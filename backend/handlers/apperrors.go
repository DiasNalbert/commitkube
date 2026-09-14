package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"gorm.io/gorm/clause"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The gap this file fills: a pod can be Running, Ready, unthrottled and on a
// healthy node while the application inside it answers 500 to every request,
// because something it depends on is down. Nothing in the Kubernetes API
// reports that, so PodProblem never sees it. Here the symptom is measured from
// two sources that need no instrumentation in the application:
//
//   - the ingress controller's access log, which already records the status
//     code of every request it proxied, and names the backing Service;
//   - the container's own stdout, for error-level lines and stack traces, which
//     catches failures on paths that never touch the ingress at all: consumers,
//     cron jobs, background workers.
//
// Neither source says whose fault the errors are. That is deliberate: blame is
// assigned in reconcileServiceProblems, by correlating these windows with the
// DependencyFailure rows the eBPF layer writes. Until that DaemonSet exists
// every problem opens with CauseKind "unknown", which is the honest answer.

// errorBucket is the aggregation unit: five minutes is short enough to catch a
// brief outage and long enough that a low-traffic service still accumulates a
// denominator worth dividing by.
const errorBucket = 5 * time.Minute

// logLookback re-reads slightly more than two buckets every pass. Each pass
// rebuilds whole buckets from the log and overwrites them rather than adding to
// them, so overlapping reads -- and a restart mid-bucket -- cannot double count.
const logLookback = 11 * time.Minute

func bucketOf(t time.Time) time.Time { return t.UTC().Truncate(errorBucket) }

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			return f
		}
	}
	return def
}

// workloadRef identifies the application a window belongs to.
type workloadRef struct {
	Namespace string
	Kind      string
	Name      string
}

func (w workloadRef) empty() bool { return w.Name == "" }

// windowAcc accumulates one bucket for one workload and one source.
type windowAcc struct {
	Ref       workloadRef
	Source    string
	Bucket    time.Time
	Requests  int64
	Status4xx int64
	Status5xx int64
	ErrorLogs int64
	statuses  map[int]int64
	paths     map[string]int64
	sample    string
}

func (a *windowAcc) addStatus(code int, path string) {
	a.Requests++
	switch {
	case code >= 500:
		a.Status5xx++
	case code >= 400:
		a.Status4xx++
	default:
		return
	}
	if a.statuses == nil {
		a.statuses = map[int]int64{}
		a.paths = map[string]int64{}
	}
	a.statuses[code]++
	if path != "" {
		a.paths[path]++
	}
}

func (a *windowAcc) addErrorLine(line string) {
	a.ErrorLogs++
	if a.sample == "" {
		a.sample = truncateLine(line, 500)
	}
}

func truncateLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// topStatus renders the error status codes most seen in the bucket, so the
// problem detail can say "502 x31" instead of just "errors".
func (a *windowAcc) topStatus() string {
	type kv struct {
		k int
		n int64
	}
	list := make([]kv, 0, len(a.statuses))
	for k, n := range a.statuses {
		list = append(list, kv{k, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].k < list[j].k
	})
	parts := []string{}
	for i, e := range list {
		if i == 3 {
			break
		}
		parts = append(parts, fmt.Sprintf("%d x%d", e.k, e.n))
	}
	return strings.Join(parts, ", ")
}

func (a *windowAcc) topPath() string {
	best, bestN := "", int64(0)
	for p, n := range a.paths {
		if n > bestN || (n == bestN && p < best) {
			best, bestN = p, n
		}
	}
	return best
}

func accKey(ref workloadRef, source string, bucket time.Time) string {
	return ref.Namespace + "/" + ref.Kind + "/" + ref.Name + "|" + source + "|" + bucket.Format(time.RFC3339)
}

// upstreamIndex resolves the backend name an ingress controller logs back to a
// workload. Rather than splitting "<namespace>-<service>-<port>" on dashes --
// which is ambiguous the moment a namespace or service name contains one -- it
// matches the longest known "<namespace>-<service>-" prefix. The service to
// workload mapping is the one the topology layer already discovered.
type upstreamIndex struct {
	prefixes map[string]workloadRef // "ns-svc-" -> workload
	byPod    map[string]workloadRef // "ns/podname" -> workload
}

func buildUpstreamIndex() *upstreamIndex {
	ix := &upstreamIndex{prefixes: map[string]workloadRef{}, byPod: map[string]workloadRef{}}

	var nodes []models.ServiceNode
	db.DB.Where("external = ?", false).Find(&nodes)
	for _, n := range nodes {
		if n.Kind == "Service" || n.Kind == "Ingress" || n.Kind == "External" {
			continue
		}
		ref := workloadRef{Namespace: n.Namespace, Kind: n.Kind, Name: n.Name}
		for _, svc := range splitCSV(n.Services) {
			if svc == "" {
				continue
			}
			ix.prefixes[n.Namespace+"-"+svc+"-"] = ref
		}
	}
	return ix
}

// resolve finds the workload behind a logged upstream name. The port suffix is
// not checked: two ports of the same Service are the same application.
func (ix *upstreamIndex) resolve(upstream string) workloadRef {
	upstream = strings.TrimSpace(strings.ToLower(upstream))
	if upstream == "" {
		return workloadRef{}
	}
	// Traefik qualifies its service names, e.g. "default-app-80@kubernetes".
	if i := strings.Index(upstream, "@"); i > 0 {
		upstream = upstream[:i]
	}
	best, bestLen := workloadRef{}, 0
	for prefix, ref := range ix.prefixes {
		if len(prefix) > bestLen && strings.HasPrefix(upstream, prefix) {
			best, bestLen = ref, len(prefix)
		}
	}
	return best
}

// parseNginxAccess reads ingress-nginx's default log format. The fields it
// needs are the status code after the quoted request, and $proxy_upstream_name,
// the first bracketed group after the user-agent quote.
//
//	1.2.3.4 - - [11/Sep/2026:12:00:00 +0000] "GET /checkout HTTP/1.1" 502 150
//	"-" "curl/8.5" 123 0.004 [shop-checkout-80] [] 10.1.2.3:8080 0 0.004 502 abc
func parseNginxAccess(line string) (upstream string, status int, path string, ok bool) {
	q1 := strings.Index(line, `"`)
	if q1 < 0 {
		return "", 0, "", false
	}
	rel := strings.Index(line[q1+1:], `"`)
	if rel < 0 {
		return "", 0, "", false
	}
	request := line[q1+1 : q1+1+rel]
	rest := line[q1+rel+2:]

	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", 0, "", false
	}
	status, err := strconv.Atoi(fields[0])
	if err != nil || status < 100 || status > 599 {
		return "", 0, "", false
	}

	// The request is "METHOD path HTTP/1.1"; the query string is dropped so
	// that paths aggregate instead of splitting into one bucket per caller.
	if parts := strings.Fields(request); len(parts) >= 2 {
		path = parts[1]
		if i := strings.Index(path, "?"); i >= 0 {
			path = path[:i]
		}
	}

	// $proxy_upstream_name is the first bracketed group after the quoted
	// user agent, so search from the last quote on the line.
	if lq := strings.LastIndex(rest, `"`); lq >= 0 {
		tail := rest[lq+1:]
		if ob := strings.Index(tail, "["); ob >= 0 {
			if cb := strings.Index(tail[ob:], "]"); cb > 0 {
				upstream = tail[ob+1 : ob+cb]
			}
		}
	}
	return upstream, status, path, true
}

// parseTraefikAccess reads Traefik's JSON access log. Traefik's CLF format does
// not name the Kubernetes Service in a position that can be read reliably, so
// only the JSON format is supported -- accesslog.format=json.
func parseTraefikAccess(line string) (upstream string, status int, path string, ok bool) {
	if !strings.HasPrefix(strings.TrimSpace(line), "{") {
		return "", 0, "", false
	}
	var rec struct {
		ServiceName      string `json:"ServiceName"`
		DownstreamStatus int    `json:"DownstreamStatus"`
		RequestPath      string `json:"RequestPath"`
	}
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return "", 0, "", false
	}
	if rec.DownstreamStatus < 100 || rec.DownstreamStatus > 599 {
		return "", 0, "", false
	}
	path = rec.RequestPath
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	return rec.ServiceName, rec.DownstreamStatus, path, true
}

// parseAccessLine tries each supported controller format. The formats are
// distinct enough that trying both is cheaper than configuring which is in use.
func parseAccessLine(line string) (upstream string, status int, path string, ok bool) {
	if u, s, p, ok := parseTraefikAccess(line); ok {
		return u, s, p, true
	}
	return parseNginxAccess(line)
}

// errorLogTokens are the markers that mean a log line reports a failure rather
// than describes work. This is a blunt instrument by design: it has to work
// across every language in the cluster without the application cooperating, so
// it looks for level tokens and the first line of the common stack traces. It
// is why an error_logs problem never opens above "warning" -- a noisy logger
// should not be able to page anyone.
var errorLogTokens = []string{
	"ERROR", "FATAL", "CRITICAL", "SEVERE",
	"panic:", "Traceback (most recent call last)",
	"Unhandled exception", "UnhandledPromiseRejection",
	"\"level\":\"error\"", "\"level\":\"fatal\"",
	"level=error", "level=fatal",

	// Portuguese. An automation written in-house logs in the language its
	// author writes in, and an English-only token list silently sees nothing at
	// all for those workloads -- no count, no group, no problem, no alert. The
	// failure mode is an empty page that looks like a healthy cluster.
	// "ERRO" cannot swallow "ERROR": the boundary check rejects a match
	// followed by another word character.
	"ERRO", "FALHA", "FALHOU", "CRÍTICO", "CRITICO",
	"EXCEÇÃO", "EXCECAO", "não foi possível", "nao foi possivel",
}

// isErrorLogLine avoids the obvious false positive of a line that merely
// mentions the word: the token must stand on its own, not sit inside another
// word such as "ERRORS_TOTAL" or a URL path like /error-codes.
func isErrorLogLine(line string) bool {
	for _, tok := range errorLogTokens {
		idx := 0
		for {
			i := strings.Index(line[idx:], tok)
			if i < 0 {
				break
			}
			at := idx + i
			if !isWordChar(byteAt(line, at-1)) && !isWordChar(byteAt(line, at+len(tok))) {
				return true
			}
			idx = at + len(tok)
			if idx >= len(line) {
				break
			}
		}
	}
	return false
}

func byteAt(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return ' '
	}
	return s[i]
}

func isWordChar(b byte) bool {
	return b == '_' || b == '-' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// readPodLog streams one container's log since a point in time, with
// timestamps so every line can be placed in the right bucket without parsing
// the application's own date format. limitBytes caps what a chatty pod can cost
// a single poll; when it truncates, the pass undercounts rather than stalls.
func readPodLog(
	ctx context.Context,
	typed kubernetes.Interface,
	namespace, pod, container string,
	previous bool,
	since time.Time,
	limitBytes int64,
	onLine func(ts time.Time, line string),
) error {
	opts := &corev1.PodLogOptions{
		Container:  container,
		Timestamps: true,
		Previous:   previous,
		LimitBytes: &limitBytes,
	}
	// SinceTime and Previous are mutually exclusive in effect: a terminated
	// instance's log is bounded already, and asking for a slice of it by wall
	// clock usually returns nothing.
	if !previous {
		sinceTime := metav1.NewTime(since)
		opts.SinceTime = &sinceTime
	}
	stream, err := typed.CoreV1().Pods(namespace).GetLogs(pod, opts).Stream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		sp := strings.IndexByte(line, ' ')
		if sp <= 0 {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, line[:sp])
		if err != nil {
			continue
		}
		onLine(ts, line[sp+1:])
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return err
	}
	return nil
}

// isIngressController recognises the controllers whose access log this can
// read. INGRESS_CONTROLLER_LABELS overrides the detection for a controller
// installed under a different name, as "key=value,key=value".
func isIngressController(pod *corev1.Pod) bool {
	if override := os.Getenv("INGRESS_CONTROLLER_LABELS"); override != "" {
		for _, pair := range strings.Split(override, ",") {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) != 2 {
				continue
			}
			if pod.Labels[strings.TrimSpace(kv[0])] != strings.TrimSpace(kv[1]) {
				return false
			}
		}
		return true
	}
	name := pod.Labels["app.kubernetes.io/name"]
	switch name {
	case "ingress-nginx", "traefik":
		return true
	}
	// Helm charts predating the recommended labels.
	switch pod.Labels["app"] {
	case "ingress-nginx", "nginx-ingress", "traefik":
		return true
	}
	return false
}

// windowSet collects buckets from several pods read in parallel.
type windowSet struct {
	mu   sync.Mutex
	accs map[string]*windowAcc
}

func newWindowSet() *windowSet { return &windowSet{accs: map[string]*windowAcc{}} }

func (w *windowSet) get(ref workloadRef, source string, ts time.Time) *windowAcc {
	bucket := bucketOf(ts)
	key := accKey(ref, source, bucket)
	w.mu.Lock()
	defer w.mu.Unlock()
	acc, ok := w.accs[key]
	if !ok {
		acc = &windowAcc{Ref: ref, Source: source, Bucket: bucket}
		w.accs[key] = acc
	}
	return acc
}

// eachPod runs fn over pods with a bounded number of concurrent log streams.
// The Kubernetes API server proxies every one of these to a kubelet, so an
// unbounded fan-out over a large cluster is a way to take the API server down.
func eachPod(pods []corev1.Pod, workers int, fn func(pod *corev1.Pod)) {
	if workers < 1 {
		workers = 1
	}
	ch := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range ch {
				fn(&pods[idx])
			}
		}()
	}
	for i := range pods {
		ch <- i
	}
	close(ch)
	wg.Wait()
}

// collectIngressWindows counts the status code of every request the ingress
// controllers proxied, attributed to the workload behind the Service.
func collectIngressWindows(
	ctx context.Context,
	typed kubernetes.Interface,
	ctrlPods []corev1.Pod,
	ix *upstreamIndex,
	since time.Time,
	limitBytes int64,
	out *windowSet,
) int {
	unresolved := 0
	var mu sync.Mutex

	eachPod(ctrlPods, 4, func(pod *corev1.Pod) {
		err := readPodLog(ctx, typed, pod.Namespace, pod.Name, "", false, since, limitBytes,
			func(ts time.Time, line string) {
				upstream, status, path, ok := parseAccessLine(line)
				if !ok {
					return
				}
				ref := ix.resolve(upstream)
				if ref.empty() {
					mu.Lock()
					unresolved++
					mu.Unlock()
					return
				}
				out.get(ref, "ingress", ts).addStatus(status, path)
			})
		if err != nil {
			fmt.Printf("App errors: ingress log %s/%s: %v\n", pod.Namespace, pod.Name, err)
		}
	})
	return unresolved
}

// groupAcc is one error class seen in one bucket for one workload.
type groupAcc struct {
	Ref         workloadRef
	Bucket      time.Time
	Fingerprint string
	Template    string
	Class       string
	Target      string
	Count       int64
	Sample      string
	LastPod     string
}

// groupSet collects the error catalogue across pods read in parallel.
type groupSet struct {
	mu     sync.Mutex
	groups map[string]*groupAcc
}

func newGroupSet() *groupSet { return &groupSet{groups: map[string]*groupAcc{}} }

func (g *groupSet) add(ref workloadRef, ts time.Time, podName, line string) {
	template := logTemplate(line)
	fp := fingerprint(template)
	bucket := bucketOf(ts)
	key := ref.Namespace + "/" + ref.Name + "|" + fp + "|" + bucket.Format(time.RFC3339)

	g.mu.Lock()
	defer g.mu.Unlock()
	acc, ok := g.groups[key]
	if !ok {
		acc = &groupAcc{
			Ref: ref, Bucket: bucket, Fingerprint: fp, Template: template,
			Class:  classifyLogError(line),
			Sample: truncateLine(line, 800),
		}
		// Only a failure that blames something outside the application gets a
		// target. A broken selector names no host and must not borrow one.
		if isDependencyClass(acc.Class) {
			acc.Target = extractTarget(line)
		}
		g.groups[key] = acc
	}
	acc.Count++
	acc.LastPod = podName
}

// jobOwnerIndex resolves a Job back to the CronJob that created it. Without
// this every scheduled run is its own workload, because a CronJob names each
// Job after the minute it fired -- rpa-nfe-29284560, then rpa-nfe-29284620 --
// so counts never accumulate and a recurring failure never crosses a threshold.
func buildJobOwnerIndex(ctx context.Context, typed kubernetes.Interface) map[string]workloadRef {
	index := map[string]workloadRef{}
	jobs, err := typed.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("App errors: list jobs: %v\n", err)
		return index
	}
	for _, job := range jobs.Items {
		ref := workloadRef{Namespace: job.Namespace, Kind: "Job", Name: job.Name}
		for _, owner := range job.OwnerReferences {
			if owner.Kind == "CronJob" {
				ref = workloadRef{Namespace: job.Namespace, Kind: "CronJob", Name: owner.Name}
				break
			}
		}
		index[job.Namespace+"/"+job.Name] = ref
	}
	return index
}

// workloadForPod names the application a pod belongs to, rolling a Job up to
// its CronJob so every run of a scheduled task reports as the same workload.
func workloadForPod(pod *corev1.Pod, jobs map[string]workloadRef) workloadRef {
	name, kind := podWorkload(pod)
	if name == "" {
		return workloadRef{}
	}
	if kind == "Job" {
		if ref, ok := jobs[pod.Namespace+"/"+name]; ok {
			return ref
		}
	}
	return workloadRef{Namespace: pod.Namespace, Kind: kind, Name: name}
}

// collectLogWindows counts error-level lines in application containers and
// catalogues them by class. This is the half of the signal that sees failures
// which never reach the ingress -- queue consumers, schedulers, RPA runs --
// and for those workloads it is the only half that sees anything at all.
func collectLogWindows(
	ctx context.Context,
	typed kubernetes.Interface,
	pods []corev1.Pod,
	jobs map[string]workloadRef,
	since time.Time,
	limitBytes int64,
	out *windowSet,
	groups *groupSet,
) {
	eachPod(pods, 8, func(pod *corev1.Pod) {
		ref := workloadForPod(pod, jobs)
		if ref.empty() {
			return
		}
		restarts := map[string]int32{}
		for _, cs := range pod.Status.ContainerStatuses {
			restarts[cs.Name] = cs.RestartCount
		}

		for _, c := range pod.Spec.Containers {
			scan := func(previous bool) {
				err := readPodLog(ctx, typed, pod.Namespace, pod.Name, c.Name, previous, since, limitBytes,
					func(ts time.Time, line string) {
						if !isErrorLogLine(line) {
							return
						}
						out.get(ref, "logs", ts).addErrorLine(line)
						groups.add(ref, ts, pod.Name, line)
					})
				if err != nil {
					// A container that has not started yet, was just replaced,
					// or has no previous instance has no readable log. That is
					// normal, not worth a line.
					return
				}
			}
			scan(false)
			// A crash-looping container's fatal line is in the dead instance's
			// log, not the running one -- which is exactly where the reason a
			// job keeps dying tends to be.
			if restarts[c.Name] > 0 {
				scan(true)
			}
		}
	})
}

// persistLogErrorGroups overwrites the catalogue buckets this pass rebuilt, on
// the same idempotency rule as the windows: a re-read cannot inflate a count.
func persistLogErrorGroups(groups map[string]*groupAcc, now time.Time, retentionDays int) error {
	rows := make([]models.LogErrorGroup, 0, len(groups))
	for _, g := range groups {
		rows = append(rows, models.LogErrorGroup{
			BucketAt:     g.Bucket,
			Namespace:    g.Ref.Namespace,
			WorkloadKind: g.Ref.Kind,
			Workload:     g.Ref.Name,
			Fingerprint:  g.Fingerprint,
			Template:     g.Template,
			Class:        g.Class,
			Target:       g.Target,
			Count:        g.Count,
			Sample:       g.Sample,
			LastPod:      g.LastPod,
		})
	}
	if len(rows) > 0 {
		upsert := clause.OnConflict{
			Columns: []clause.Column{
				{Name: "bucket_at"}, {Name: "namespace"},
				{Name: "workload_kind"}, {Name: "workload"}, {Name: "fingerprint"},
			},
			DoUpdates: clause.AssignmentColumns([]string{
				"template", "class", "target", "count", "sample", "last_pod",
			}),
		}
		if err := db.DB.Clauses(upsert).CreateInBatches(rows, 200).Error; err != nil {
			return err
		}
	}

	db.DB.Where("bucket_at < ?", now.AddDate(0, 0, -retentionDays)).Delete(&models.LogErrorGroup{})
	return nil
}

// persistErrorWindows overwrites the buckets this pass rebuilt. Assignment
// rather than accumulation is what makes the poll idempotent: the same log
// range can be read twice, by an overlapping pass or after a restart, without
// inflating any count.
func persistErrorWindows(accs map[string]*windowAcc, now time.Time, retentionDays int) error {
	rows := make([]models.ErrorWindow, 0, len(accs))
	for _, a := range accs {
		rows = append(rows, models.ErrorWindow{
			BucketAt:     a.Bucket,
			Namespace:    a.Ref.Namespace,
			WorkloadKind: a.Ref.Kind,
			Workload:     a.Ref.Name,
			Source:       a.Source,
			Requests:     a.Requests,
			Status4xx:    a.Status4xx,
			Status5xx:    a.Status5xx,
			ErrorLogs:    a.ErrorLogs,
			TopStatus:    a.topStatus(),
			TopPath:      a.topPath(),
			Sample:       a.sample,
		})
	}
	if len(rows) > 0 {
		upsert := clause.OnConflict{
			Columns: []clause.Column{
				{Name: "bucket_at"}, {Name: "namespace"},
				{Name: "workload_kind"}, {Name: "workload"}, {Name: "source"},
			},
			DoUpdates: clause.AssignmentColumns([]string{
				"requests", "status4xx", "status5xx", "error_logs",
				"top_status", "top_path", "sample",
			}),
		}
		if err := db.DB.Clauses(upsert).CreateInBatches(rows, 200).Error; err != nil {
			return err
		}
	}

	cutoff := now.AddDate(0, 0, -retentionDays)
	db.DB.Where("bucket_at < ?", cutoff).Delete(&models.ErrorWindow{})
	db.DB.Where("bucket_at < ?", cutoff).Delete(&models.DependencyFailure{})
	return nil
}

// causeAttribution is the answer to "is it me or is it them".
type causeAttribution struct {
	Kind      string // dependency | self | unknown
	Source    string // ebpf | logs | none
	Namespace string
	NodeKind  string
	Name      string
	Host      string
	Detail    string
}

// attributeCause decides who is at fault, preferring measurement over
// inference but never discarding inference when measurement is absent.
//
// The order is deliberate:
//
//  1. L4 failures observed by the eBPF layer. Strongest evidence, names the
//     dependency outright.
//  2. The application's own error text. Weaker -- a message can be stale or
//     already retried away -- but a batch job or an RPA usually has nothing
//     else, and "net::ERR_CONNECTION_TIMED_OUT at portal.vendor.com" is not an
//     ambiguous statement. It also covers what L4 cannot see: a third party
//     that accepts the connection and answers 502 is failing at L7, and every
//     one of its TCP calls completed normally.
//  3. Only with traffic observed and nothing failing anywhere does this report
//     "self". Absence of both sources reports "unknown", never "self" --
//     blaming an application on data nobody collected sends the wrong team to
//     investigate.
func attributeCause(ref workloadRef, from, to time.Time) causeAttribution {
	var rows []models.DependencyFailure
	db.DB.Where("src_namespace = ? AND src_name = ? AND bucket_at >= ? AND bucket_at <= ?",
		ref.Namespace, ref.Name, from, to).Find(&rows)

	type agg struct {
		models.DependencyFailure
		failures int64
		attempts int64
	}
	byDst := map[string]*agg{}
	for _, r := range rows {
		key := r.DstNamespace + "/" + r.DstKind + "/" + r.DstName + "/" + r.Port
		a, ok := byDst[key]
		if !ok {
			a = &agg{DependencyFailure: r}
			byDst[key] = a
		}
		a.failures += r.Failures()
		a.attempts += r.Attempts
	}

	var worst *agg
	for _, a := range byDst {
		if a.failures == 0 {
			continue
		}
		if worst == nil || a.failures > worst.failures {
			worst = a
		}
	}

	if worst != nil {
		target := worst.DstName
		if worst.DstHost != "" {
			target = worst.DstHost
		}
		reasons := []string{}
		for label, n := range map[string]int64{
			"connection refused": worst.ConnRefused,
			"timeout":            worst.ConnTimeout,
			"connection reset":   worst.ConnReset,
			"DNS failure":        worst.DNSFailed,
			"TLS failure":        worst.TLSFailed,
		} {
			if n > 0 {
				reasons = append(reasons, fmt.Sprintf("%s x%d", label, n))
			}
		}
		sort.Strings(reasons)

		pct := float64(0)
		if worst.attempts > 0 {
			pct = float64(worst.failures) / float64(worst.attempts) * 100
		}
		return causeAttribution{
			Kind: "dependency", Source: "ebpf",
			Namespace: worst.DstNamespace, NodeKind: worst.DstKind,
			Name: worst.DstName, Host: worst.DstHost,
			Detail: fmt.Sprintf("%d of %d calls to %s failed (%.1f%%): %s.",
				worst.failures, worst.attempts, target, pct, strings.Join(reasons, ", ")),
		}
	}

	if inferred, ok := causeFromLogs(ref, from, to); ok {
		return inferred
	}

	if len(rows) > 0 {
		return causeAttribution{
			Kind: "self", Source: "ebpf",
			Detail: "Every call this workload made to its dependencies completed, and nothing in its logs blames an external service. The errors originate inside the application.",
		}
	}

	return causeAttribution{
		Kind: "unknown", Source: "none",
		Detail: "Nothing observed this workload's outbound calls and its logs did not name a failing dependency, so the cause cannot be established.",
	}
}

// causeFromLogs reads the error catalogue for a verdict. It only speaks when a
// dependency-class group actually named a host: a timeout with no host in the
// message says something failed but not what, and guessing at that is how an
// incident gets routed to a team that owns none of it.
func causeFromLogs(ref workloadRef, from, to time.Time) (causeAttribution, bool) {
	var groups []models.LogErrorGroup
	db.DB.Where("namespace = ? AND workload = ? AND bucket_at >= ? AND bucket_at <= ? AND target != ''",
		ref.Namespace, ref.Name, from, to).Find(&groups)

	type tally struct {
		count int64
		class string
		tmpl  string
	}
	byTarget := map[string]*tally{}
	for _, g := range groups {
		if !isDependencyClass(g.Class) {
			continue
		}
		t, ok := byTarget[g.Target]
		if !ok {
			t = &tally{class: g.Class, tmpl: g.Template}
			byTarget[g.Target] = t
		}
		t.count += g.Count
	}

	bestHost, best := "", (*tally)(nil)
	for host, t := range byTarget {
		if best == nil || t.count > best.count || (t.count == best.count && host < bestHost) {
			bestHost, best = host, t
		}
	}
	if best == nil {
		return causeAttribution{}, false
	}

	// The host is matched against the service map so an already-known third
	// party keeps its identity there instead of becoming a second, parallel
	// record of the same dependency.
	nodeKind, nodeNS, nodeName := "External", "", bestHost
	var nodes []models.ServiceNode
	db.DB.Where("external = ? AND (name = ? OR hosts LIKE ?)",
		true, bestHost, "%"+bestHost+"%").Limit(1).Find(&nodes)
	if len(nodes) == 1 {
		nodeKind, nodeNS, nodeName = nodes[0].Kind, nodes[0].Namespace, nodes[0].Name
	}

	return causeAttribution{
		Kind: "dependency", Source: "logs",
		Namespace: nodeNS, NodeKind: nodeKind, Name: nodeName, Host: bestHost,
		Detail: fmt.Sprintf("The application logged %d %s errors naming %s (%s). "+
			"Inferred from the log text, not from observed traffic.",
			best.count, strings.ReplaceAll(strings.TrimPrefix(best.class, "dependency_"), "_", " "),
			bestHost, strings.TrimSpace(best.tmpl)),
	}, true
}

// detected is one problem the evaluation decided to report this pass.
type detected struct {
	Ref      workloadRef
	Kind     string
	Severity string
	Title    string
	Detail   string
	Value    float64
	Requests int64
	Errors   int64
	Cause    causeAttribution
}

// evaluateWindows turns the recent buckets into problems. Thresholds are read
// from the environment because what counts as "too many errors" is a property
// of the service, not of the platform.
func evaluateWindows(now time.Time) []detected {
	windows := envInt("APP_ERROR_WINDOWS", 3)
	if windows < 1 {
		windows = 1
	}
	minRequests := int64(envInt("APP_ERROR_MIN_REQUESTS", 20))
	ratePct := envFloat("APP_ERROR_RATE_PCT", 5)
	criticalPct := envFloat("APP_ERROR_CRITICAL_PCT", 20)
	logsPerMin := envFloat("APP_ERROR_LOGS_PER_MIN", 6)
	batchErrors := envInt("APP_BATCH_MIN_ERRORS", 1)
	depFailures := int64(envInt("APP_DEPENDENCY_MIN_FAILURES", 5))

	to := bucketOf(now)
	from := to.Add(-time.Duration(windows-1) * errorBucket)
	minutes := float64(windows) * errorBucket.Minutes()

	var rows []models.ErrorWindow
	db.DB.Where("bucket_at >= ? AND bucket_at <= ?", from, to).Find(&rows)

	type totals struct {
		ref       workloadRef
		requests  int64
		errors    int64
		errorLogs int64
		topStatus string
		topPath   string
		sample    string
	}
	byWorkload := map[string]*totals{}
	keyOf := func(ref workloadRef) string {
		return ref.Namespace + "/" + ref.Kind + "/" + ref.Name
	}
	for _, r := range rows {
		ref := workloadRef{Namespace: r.Namespace, Kind: r.WorkloadKind, Name: r.Workload}
		t, ok := byWorkload[keyOf(ref)]
		if !ok {
			t = &totals{ref: ref}
			byWorkload[keyOf(ref)] = t
		}
		t.requests += r.Requests
		t.errors += r.Status5xx
		t.errorLogs += r.ErrorLogs
		if r.Status5xx > 0 && r.TopStatus != "" {
			t.topStatus = r.TopStatus
			t.topPath = r.TopPath
		}
		if t.sample == "" {
			t.sample = r.Sample
		}
	}

	// A workload can have failing dependencies without yet returning errors of
	// its own -- a retry loop that has not exhausted, a queue backing up. That
	// is worth reporting before the user-visible failure arrives, so the
	// dependency side is evaluated for every workload the traffic layer saw,
	// not only for those that already appear in an error window.
	var depRows []models.DependencyFailure
	db.DB.Where("bucket_at >= ? AND bucket_at <= ?", from, to).Find(&depRows)
	depSources := map[string]workloadRef{}
	for _, r := range depRows {
		ref := workloadRef{Namespace: r.SrcNamespace, Kind: r.SrcKind, Name: r.SrcName}
		depSources[keyOf(ref)] = ref
	}

	out := []detected{}

	for _, t := range byWorkload {
		if t.requests >= minRequests && t.errors > 0 {
			rate := float64(t.errors) / float64(t.requests) * 100
			if rate >= ratePct {
				cause := attributeCause(t.ref, from, to)
				severity := "warning"
				if rate >= criticalPct {
					severity = "critical"
				}
				detail := fmt.Sprintf("%d of %d requests failed (%.1f%%) over the last %.0f minutes",
					t.errors, t.requests, rate, minutes)
				if t.topStatus != "" {
					detail += ": " + t.topStatus
				}
				if t.topPath != "" {
					detail += fmt.Sprintf(", mostly on %s", t.topPath)
				}
				out = append(out, detected{
					Ref: t.ref, Kind: "http_5xx", Severity: severity,
					Title:    fmt.Sprintf("%s is returning server errors", t.ref.Name),
					Detail:   detail + ".",
					Value:    rate,
					Requests: t.requests, Errors: t.errors, Cause: cause,
				})
			}
		}

		// A rate per minute is the right shape for something serving traffic
		// continuously and the wrong shape for a scheduled task. An RPA that
		// runs hourly and fails logs a handful of lines and then exits; divided
		// over a fifteen-minute window that is a rate of nearly zero, and the
		// run that failed goes unreported. For batch workloads the question is
		// not how fast errors arrive, it is whether the run failed at all.
		batch := t.ref.Kind == "CronJob" || t.ref.Kind == "Job"
		rate := float64(t.errorLogs) / minutes
		trips := rate >= logsPerMin
		if batch {
			trips = t.errorLogs >= int64(batchErrors)
		}

		if trips {
			cause := attributeCause(t.ref, from, to)
			title := fmt.Sprintf("%s is logging errors", t.ref.Name)
			detail := fmt.Sprintf("%d error-level log lines in %.0f minutes (%.1f/min)",
				t.errorLogs, minutes, rate)
			if batch {
				title = fmt.Sprintf("%s failed its run", t.ref.Name)
				detail = fmt.Sprintf("%d error-level log lines in the last run", t.errorLogs)
			}
			// When the logs name what could not be reached, that belongs in the
			// title. "rpa-nfe is logging errors" starts an investigation;
			// "rpa-nfe failed: portal.vendor.com unreachable" ends one.
			if cause.Kind == "dependency" {
				target := cause.Host
				if target == "" {
					target = cause.Name
				}
				title = fmt.Sprintf("%s is failing on %s", t.ref.Name, target)
				detail += ".\n" + cause.Detail
			} else if t.sample != "" {
				detail += ".\nFirst line: " + t.sample
			}
			out = append(out, detected{
				Ref: t.ref, Kind: "error_logs", Severity: "warning",
				Title:  title,
				Detail: detail,
				Value:  rate, Errors: t.errorLogs, Cause: cause,
			})
		}
	}

	for key, ref := range depSources {
		_ = key
		cause := attributeCause(ref, from, to)
		if cause.Kind != "dependency" {
			continue
		}
		var failures int64
		for _, r := range depRows {
			if r.SrcNamespace == ref.Namespace && r.SrcName == ref.Name && r.DstName == cause.Name {
				failures += r.Failures()
			}
		}
		if failures < depFailures {
			continue
		}
		target := cause.Name
		if cause.Host != "" {
			target = cause.Host
		}
		out = append(out, detected{
			Ref: ref, Kind: "dependency_failure", Severity: "warning",
			Title:  fmt.Sprintf("%s cannot reach %s", ref.Name, target),
			Detail: cause.Detail,
			Value:  float64(failures), Errors: failures, Cause: cause,
		})
	}

	return out
}

// reconcileServiceProblems opens, accumulates and closes problems, following
// the same lifecycle as PodProblem so both surfaces behave identically: a
// problem opens once, its occurrence count grows while it reproduces, and it
// closes when it stops.
func reconcileServiceProblems(found []detected, now time.Time) {
	var open []models.ServiceProblem
	db.DB.Where("closed_at IS NULL").Find(&open)
	openByKey := map[string]models.ServiceProblem{}
	for _, p := range open {
		openByKey[p.Namespace+"/"+p.Workload+"/"+p.Kind] = p
	}

	seen := map[string]bool{}
	for _, d := range found {
		key := d.Ref.Namespace + "/" + d.Ref.Name + "/" + d.Kind
		seen[key] = true

		if existing, ok := openByKey[key]; ok {
			db.DB.Model(&models.ServiceProblem{}).Where("id = ?", existing.ID).Updates(map[string]interface{}{
				"last_seen_at":    now,
				"occurrences":     existing.Occurrences + 1,
				"severity":        d.Severity,
				"detail":          d.Detail,
				"value":           d.Value,
				"requests":        d.Requests,
				"errors":          d.Errors,
				"cause_kind":      d.Cause.Kind,
				"cause_source":    d.Cause.Source,
				"cause_namespace": d.Cause.Namespace,
				"cause_node_kind": d.Cause.NodeKind,
				"cause_name":      d.Cause.Name,
				"cause_host":      d.Cause.Host,
				"cause_detail":    d.Cause.Detail,
			})
			continue
		}

		db.DB.Create(&models.ServiceProblem{
			OpenedAt:     now,
			LastSeenAt:   now,
			Namespace:    d.Ref.Namespace,
			WorkloadKind: d.Ref.Kind,
			Workload:     d.Ref.Name,
			Kind:         d.Kind,
			Severity:     d.Severity,
			Title:        d.Title,
			Detail:       d.Detail,
			Value:        d.Value,
			Requests:     d.Requests,
			Errors:       d.Errors,

			CauseKind:      d.Cause.Kind,
			CauseSource:    d.Cause.Source,
			CauseNamespace: d.Cause.Namespace,
			CauseNodeKind:  d.Cause.NodeKind,
			CauseName:      d.Cause.Name,
			CauseHost:      d.Cause.Host,
			CauseDetail:    d.Cause.Detail,
			Occurrences:    1,
		})

		message := d.Detail
		if d.Cause.Kind == "dependency" {
			message += "\nLikely cause: " + d.Cause.Detail
		}
		go SendNotifications("service."+d.Kind, d.Title,
			fmt.Sprintf("Workload %s in namespace %s: %s", d.Ref.Name, d.Ref.Namespace, message),
			d.Ref.Name, "system")
	}

	for key, p := range openByKey {
		if seen[key] {
			continue
		}
		closedAt := now
		db.DB.Model(&models.ServiceProblem{}).Where("id = ?", p.ID).
			Update("closed_at", &closedAt)
	}
}

// PollAppErrors measures application-level failure and reconciles it into
// problems. It is deliberately separate from PollPodMetrics: the two answer
// different questions, and a cluster where pods are healthy is exactly the
// cluster where only this one has anything to say.
func PollAppErrors() {
	retentionDays := envInt("APP_ERROR_RETENTION_DAYS", 3)
	limitBytes := int64(envInt("APP_LOG_LIMIT_BYTES", 8*1024*1024))
	maxPods := envInt("APP_LOG_SCAN_MAX_PODS", 120)

	typed, err := buildK8sClient()
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	podList, err := typed.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("App errors: list pods: %v\n", err)
		return
	}

	var controllers, apps []corev1.Pod
	for _, pod := range podList.Items {
		// Succeeded and Failed pods are kept, not skipped. A scheduled task or
		// an RPA run lives for seconds and is already terminated by the time
		// this poll comes round; dropping it here is dropping the only record
		// that the run failed at all. Pending pods have no log to read.
		switch pod.Status.Phase {
		case corev1.PodRunning, corev1.PodSucceeded, corev1.PodFailed:
		default:
			continue
		}
		if isIngressController(&pod) {
			if pod.Status.Phase == corev1.PodRunning {
				controllers = append(controllers, pod)
			}
			continue
		}
		apps = append(apps, pod)
	}

	// Newest first, so that when the cap bites it drops the pods least likely
	// to hold anything recent rather than an arbitrary slice of the list.
	sort.Slice(apps, func(i, j int) bool {
		return apps[i].CreationTimestamp.Time.After(apps[j].CreationTimestamp.Time)
	})
	if len(apps) > maxPods {
		fmt.Printf("App errors: %d pods to scan, capped at %d; raise APP_LOG_SCAN_MAX_PODS to cover them all.\n",
			len(apps), maxPods)
		apps = apps[:maxPods]
	}

	now := time.Now()
	since := now.Add(-logLookback)
	set := newWindowSet()

	if len(controllers) == 0 {
		fmt.Println("App errors: no ingress controller pod found; HTTP status is not being measured. " +
			"Set INGRESS_CONTROLLER_LABELS if the controller uses non-standard labels.")
	} else {
		unresolved := collectIngressWindows(ctx, typed, controllers, buildUpstreamIndex(), since, limitBytes, set)
		if unresolved > 0 {
			fmt.Printf("App errors: %d access log lines did not map to a known Service; "+
				"the topology poll may not have run yet.\n", unresolved)
		}
	}

	groups := newGroupSet()
	collectLogWindows(ctx, typed, apps, buildJobOwnerIndex(ctx, typed), since, limitBytes, set, groups)

	if err := persistErrorWindows(set.accs, now, retentionDays); err != nil {
		fmt.Printf("App errors: store windows: %v\n", err)
		return
	}
	if err := persistLogErrorGroups(groups.groups, now, retentionDays); err != nil {
		fmt.Printf("App errors: store log groups: %v\n", err)
		return
	}

	reconcileServiceProblems(evaluateWindows(now), now)
}

// GetServiceProblems lists application-level problems, open ones by default.
// cause=dependency narrows the list to the incidents that are somebody else's
// fault, which is the view to open when a service is being blamed for errors
// it is only passing along.
func GetServiceProblems(c *fiber.Ctx) error {
	q := db.DB.Model(&models.ServiceProblem{})
	if c.Query("status", "open") == "open" {
		q = q.Where("closed_at IS NULL")
	}
	if ns := c.Query("namespace"); ns != "" {
		q = q.Where("namespace = ?", ns)
	}
	if w := c.Query("workload"); w != "" {
		q = q.Where("workload = ?", w)
	}
	if sev := c.Query("severity"); sev != "" {
		q = q.Where("severity = ?", sev)
	}
	if cause := c.Query("cause"); cause != "" {
		q = q.Where("cause_kind = ?", cause)
	}

	var problems []models.ServiceProblem
	q.Order("opened_at desc").Limit(500).Find(&problems)
	if problems == nil {
		problems = []models.ServiceProblem{}
	}
	return c.JSON(fiber.Map{"problems": problems})
}

// GetServiceErrorSeries returns the raw buckets behind a problem, so the page
// can show when the errors started rather than only that they are happening.
func GetServiceErrorSeries(c *fiber.Ctx) error {
	hours := envInt("APP_ERROR_DEFAULT_HOURS", 6)
	if h, err := strconv.Atoi(c.Query("hours")); err == nil && h > 0 && h <= 168 {
		hours = h
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	q := db.DB.Model(&models.ErrorWindow{}).Where("bucket_at >= ?", since)
	if ns := c.Query("namespace"); ns != "" {
		q = q.Where("namespace = ?", ns)
	}
	if w := c.Query("workload"); w != "" {
		q = q.Where("workload = ?", w)
	}

	var windows []models.ErrorWindow
	q.Order("bucket_at asc").Limit(5000).Find(&windows)
	if windows == nil {
		windows = []models.ErrorWindow{}
	}

	var deps []models.DependencyFailure
	dq := db.DB.Model(&models.DependencyFailure{}).Where("bucket_at >= ?", since)
	if ns := c.Query("namespace"); ns != "" {
		dq = dq.Where("src_namespace = ?", ns)
	}
	if w := c.Query("workload"); w != "" {
		dq = dq.Where("src_name = ?", w)
	}
	dq.Order("bucket_at asc").Limit(5000).Find(&deps)
	if deps == nil {
		deps = []models.DependencyFailure{}
	}

	return c.JSON(fiber.Map{"windows": windows, "dependencies": deps})
}

// LogErrorGroupView is one catalogue entry rolled up across buckets.
type LogErrorGroupView struct {
	Namespace    string    `json:"namespace"`
	WorkloadKind string    `json:"workload_kind"`
	Workload     string    `json:"workload"`
	Fingerprint  string    `json:"fingerprint"`
	Template     string    `json:"template"`
	Class        string    `json:"class"`
	Target       string    `json:"target"`
	Count        int64     `json:"count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Sample       string    `json:"sample"`
	LastPod      string    `json:"last_pod"`
	External     bool      `json:"external"` // the class blames something outside the application
}

// GetLogErrors is the catalogue: which errors a workload is actually producing,
// grouped so a thousand identical failures read as one entry with a count, and
// classified so the list separates "the site I drive was unreachable" from "my
// automation broke". Ordered by count, because the error happening most is
// almost always the one to read first.
//
// class=dependency_unreachable, dependency_timeout or dependency_http narrows
// it to the failures that are not the application's fault.
func GetLogErrors(c *fiber.Ctx) error {
	hours := envInt("APP_ERROR_DEFAULT_HOURS", 6)
	if h, err := strconv.Atoi(c.Query("hours")); err == nil && h > 0 && h <= 168 {
		hours = h
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	q := db.DB.Model(&models.LogErrorGroup{}).Where("bucket_at >= ?", since)
	if ns := c.Query("namespace"); ns != "" {
		q = q.Where("namespace = ?", ns)
	}
	if w := c.Query("workload"); w != "" {
		q = q.Where("workload = ?", w)
	}
	if class := c.Query("class"); class != "" {
		q = q.Where("class = ?", class)
	}
	if c.Query("external") == "true" {
		q = q.Where("class LIKE ?", "dependency_%")
	}
	if target := c.Query("target"); target != "" {
		q = q.Where("target = ?", target)
	}

	var rows []models.LogErrorGroup
	q.Order("bucket_at asc").Limit(20000).Find(&rows)

	byKey := map[string]*LogErrorGroupView{}
	order := []string{}
	for _, r := range rows {
		key := r.Namespace + "/" + r.Workload + "/" + r.Fingerprint
		v, ok := byKey[key]
		if !ok {
			v = &LogErrorGroupView{
				Namespace: r.Namespace, WorkloadKind: r.WorkloadKind, Workload: r.Workload,
				Fingerprint: r.Fingerprint, Template: r.Template, Class: r.Class,
				Target: r.Target, FirstSeen: r.BucketAt, Sample: r.Sample,
				External: isDependencyClass(r.Class),
			}
			byKey[key] = v
			order = append(order, key)
		}
		v.Count += r.Count
		v.LastSeen = r.BucketAt
		if r.LastPod != "" {
			v.LastPod = r.LastPod
		}
	}

	out := make([]LogErrorGroupView, 0, len(order))
	for _, key := range order {
		out = append(out, *byKey[key])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})

	// A per-class tally, so the caller can say "83% of this workload's errors
	// were the third party being unreachable" without re-aggregating.
	byClass := map[string]int64{}
	var external, total int64
	for _, v := range out {
		byClass[v.Class] += v.Count
		total += v.Count
		if v.External {
			external += v.Count
		}
	}

	return c.JSON(fiber.Map{
		"groups":         out,
		"by_class":       byClass,
		"total":          total,
		"external_total": external,
	})
}
