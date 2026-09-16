package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"gorm.io/gorm"
)

// Thresholds for pod problem detection. Warning fires first, critical escalates.
const (
	memWarnPct       = 85.0
	memCritPct       = 95.0
	cpuWarnPct       = 85.0
	cpuCritPct       = 95.0
	throttleWarn     = 25.0
	throttleCrit     = 50.0
	overProvisionPct = 10.0
)

type PodContainerInfo struct {
	Name         string  `json:"name"`
	Image        string  `json:"image"`
	Ready        bool    `json:"ready"`
	RestartCount int     `json:"restart_count"`
	State        string  `json:"state"`
	StateReason  string  `json:"state_reason"`
	LastExitCode int32   `json:"last_exit_code"`
	LastReason   string  `json:"last_reason"`
	CPUCores     float64 `json:"cpu_cores"`
	CPURequests  float64 `json:"cpu_requests"`
	CPULimits    float64 `json:"cpu_limits"`
	MemBytes     int64   `json:"mem_bytes"`
	MemRequests  int64   `json:"mem_requests"`
	MemLimits    int64   `json:"mem_limits"`
	ThrottledPct float64 `json:"throttled_pct"`
}

type PodInfo struct {
	Name         string             `json:"name"`
	Namespace    string             `json:"namespace"`
	Workload     string             `json:"workload"`
	WorkloadKind string             `json:"workload_kind"`
	NodeName     string             `json:"node_name"`
	Phase        string             `json:"phase"`
	Ready        bool               `json:"ready"`
	Age          string             `json:"age"`
	RestartCount int                `json:"restart_count"`
	Image        string             `json:"image"`
	QOSClass     string             `json:"qos_class"`
	CPUCores     float64            `json:"cpu_cores"`
	CPURequests  float64            `json:"cpu_requests"`
	CPULimits    float64            `json:"cpu_limits"`
	CPUPct       float64            `json:"cpu_pct"`
	MemBytes     int64              `json:"mem_bytes"`
	MemRequests  int64              `json:"mem_requests"`
	MemLimits    int64              `json:"mem_limits"`
	MemPct       float64            `json:"mem_pct"`
	ThrottledPct float64            `json:"throttled_pct"`
	MetricsAvail bool               `json:"metrics_available"`
	Problems     []DetectedProblem  `json:"problems"`
	Containers   []PodContainerInfo `json:"containers"`
}

// DetectedProblem is a problem found during a single evaluation pass, before
// it is reconciled against the open PodProblem rows in the database.
type DetectedProblem struct {
	Kind     string  `json:"kind"`
	Severity string  `json:"severity"`
	Title    string  `json:"title"`
	Detail   string  `json:"detail"`
	Value    float64 `json:"value"`
}

type containerUsage struct {
	CPUCores float64
	MemBytes float64
}

// cfsSample holds the previous cadvisor CFS counter reading so throttling can
// be reported as a rate over the sampling window instead of a lifetime average.
type cfsSample struct {
	Throttled float64
	Periods   float64
}

var (
	cfsMu   sync.Mutex
	cfsPrev = map[string]cfsSample{}
)

// metricsDerived marks the problem kinds that can only be observed while
// metrics-server is answering, so they are not closed on a failed scrape.
var metricsDerived = map[string]bool{
	"mem_pressure":    true,
	"cpu_throttling":  true,
	"cpu_saturation":  true,
	"overprovisioned": true,
}

// lastThrottlingByPod returns the most recent throttling percentage the poller
// recorded for each pod.
func lastThrottlingByPod(clusterID uint) map[string]float64 {
	type row struct {
		Namespace    string
		PodName      string
		ThrottledPct float64
	}
	var rows []row
	// Ordered by recorded_at, not by MAX(id). The index is on
	// (cluster_id, namespace, pod_name, recorded_at), so grouping by id meant
	// the planner could not use it and scanned the whole table -- which is how
	// this took twelve seconds on a few hundred thousand rows that should have
	// been an index seek.
	db.DB.Raw(`
		SELECT namespace, pod_name, throttled_pct FROM (
			SELECT namespace, pod_name, throttled_pct,
				ROW_NUMBER() OVER (PARTITION BY namespace, pod_name ORDER BY recorded_at DESC) AS rn
			FROM pod_snapshots
			WHERE cluster_id = ?
		) WHERE rn = 1
	`, clusterID).Scan(&rows)

	out := make(map[string]float64, len(rows))
	for _, r := range rows {
		out[r.Namespace+"/"+r.PodName] = r.ThrottledPct
	}
	return out
}

// fetchPodMetrics reads live per-container usage from the metrics.k8s.io API
// served by metrics-server -- the same source `kubectl top pod` uses.
// A namespace narrows the request to that namespace's pods. It used to ask for
// the whole cluster even when the caller had filtered, which on a large cluster
// is the most expensive part of rendering a single namespace.
func fetchPodMetrics(clientset *kubernetes.Clientset, namespace string) map[string]map[string]containerUsage {
	result := map[string]map[string]containerUsage{}

	path := "/apis/metrics.k8s.io/v1beta1/pods"
	if namespace != "" {
		path = "/apis/metrics.k8s.io/v1beta1/namespaces/" + namespace + "/pods"
	}

	raw, err := clientset.RESTClient().Get().
		AbsPath(path).
		DoRaw(context.Background())
	if err != nil {
		return result
	}

	var resp struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Containers []struct {
				Name  string `json:"name"`
				Usage struct {
					CPU    string `json:"cpu"`
					Memory string `json:"memory"`
				} `json:"usage"`
			} `json:"containers"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return result
	}

	for _, item := range resp.Items {
		key := item.Metadata.Namespace + "/" + item.Metadata.Name
		containers := map[string]containerUsage{}
		for _, c := range item.Containers {
			u := containerUsage{}
			if q, err := resource.ParseQuantity(c.Usage.CPU); err == nil {
				u.CPUCores = q.AsApproximateFloat64()
			}
			if q, err := resource.ParseQuantity(c.Usage.Memory); err == nil {
				u.MemBytes = q.AsApproximateFloat64()
			}
			containers[c.Name] = u
		}
		result[key] = containers
	}
	return result
}

// fetchThrottling scrapes each node's cadvisor endpoint for CFS quota counters.
// metrics-server does not expose throttling, and throttling is what separates
// "this pod uses a lot of CPU" from "this pod is being starved by its limit".
// Best effort: needs RBAC on nodes/proxy and returns nothing if unavailable.
func fetchThrottling(clientset *kubernetes.Clientset, nodeNames []string) map[string]float64 {
	cur := map[string]cfsSample{}

	// One node at a time made the pass as long as the sum of every kubelet's
	// response, each a cadvisor payload measured in megabytes -- and a single
	// unresponsive kubelet stalled the whole poll, along with the database
	// write that follows it. Bounded concurrency with a per-node deadline
	// keeps the pass proportional to the slowest few nodes, not to all of them.
	const maxParallelScrapes = 8
	var (
		scrapeMu sync.Mutex
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, maxParallelScrapes)

	for _, node := range nodeNames {
		wg.Add(1)
		go func(node string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			raw, err := clientset.CoreV1().RESTClient().Get().
				Resource("nodes").Name(node).SubResource("proxy").
				Suffix("metrics", "cadvisor").
				DoRaw(ctx)
			if err != nil {
				return
			}

			scrapeMu.Lock()
			defer scrapeMu.Unlock()
			parseCFSMetrics(string(raw), cur)
		}(node)
	}
	wg.Wait()

	out := map[string]float64{}
	if len(cur) == 0 {
		return out
	}

	cfsMu.Lock()
	defer cfsMu.Unlock()

	// Aggregate per-container deltas up to the pod level.
	type agg struct{ throttled, periods float64 }
	pods := map[string]*agg{}
	for key, s := range cur {
		prev, ok := cfsPrev[key]
		// Counters reset when a container restarts; skip those samples.
		if ok && s.Periods >= prev.Periods && s.Throttled >= prev.Throttled {
			podKey := key[:strings.LastIndex(key, "/")]
			if pods[podKey] == nil {
				pods[podKey] = &agg{}
			}
			pods[podKey].throttled += s.Throttled - prev.Throttled
			pods[podKey].periods += s.Periods - prev.Periods
		}
	}
	cfsPrev = cur

	for podKey, a := range pods {
		if a.periods > 0 {
			out[podKey] = a.throttled / a.periods * 100
		}
	}
	return out
}

// parseCFSMetrics pulls the two CFS counters out of the Prometheus text
// exposition format that cadvisor serves, keyed by namespace/pod/container.
func parseCFSMetrics(body string, into map[string]cfsSample) {
	for _, line := range strings.Split(body, "\n") {
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		var isThrottled bool
		switch {
		case strings.HasPrefix(line, "container_cpu_cfs_throttled_periods_total{"):
			isThrottled = true
		case strings.HasPrefix(line, "container_cpu_cfs_periods_total{"):
			isThrottled = false
		default:
			continue
		}

		open := strings.IndexByte(line, '{')
		closed := strings.LastIndexByte(line, '}')
		if open < 0 || closed < open {
			continue
		}
		labels := line[open+1 : closed]

		ns := cfsLabel(labels, "namespace")
		pod := cfsLabel(labels, "pod")
		container := cfsLabel(labels, "container")
		// The pod-level cgroup has an empty container label; skip it so
		// containers are not double counted.
		if ns == "" || pod == "" || container == "" || container == "POD" {
			continue
		}

		// The value may be followed by an optional timestamp, which cadvisor
		// does emit: "<metric>{...} 1000 1699999999999".
		fields := strings.Fields(line[closed+1:])
		if len(fields) == 0 {
			continue
		}
		val, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}

		key := ns + "/" + pod + "/" + container
		s := into[key]
		if isThrottled {
			s.Throttled = val
		} else {
			s.Periods = val
		}
		into[key] = s
	}
}

func cfsLabel(labels, name string) string {
	needle := name + `="`
	i := strings.Index(labels, needle)
	if i < 0 {
		return ""
	}
	// Guard against matching a suffix of another label (e.g. "container" in
	// "container_label_foo") by requiring a delimiter before the name.
	if i > 0 && labels[i-1] != ',' && labels[i-1] != ' ' {
		return ""
	}
	rest := labels[i+len(needle):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// podWorkload resolves the owning workload of a pod. Pods created by a
// Deployment are owned by a ReplicaSet whose name carries a pod-template
// hash suffix, which is stripped to recover the Deployment name.
func podWorkload(pod *corev1.Pod) (string, string) {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		if ref.Kind == "ReplicaSet" {
			if i := strings.LastIndex(ref.Name, "-"); i > 0 {
				return ref.Name[:i], "Deployment"
			}
			return ref.Name, "Deployment"
		}
		return ref.Name, ref.Kind
	}
	return pod.Name, "Pod"
}

func shortAge(since time.Time) string {
	dur := time.Since(since)
	days := int(dur.Hours()) / 24
	hours := int(dur.Hours()) % 24
	if days > 0 {
		return strconv.Itoa(days) + "d" + strconv.Itoa(hours) + "h"
	}
	if hours > 0 {
		return strconv.Itoa(hours) + "h"
	}
	return strconv.Itoa(int(dur.Minutes())) + "m"
}

// buildPodInfo merges the pod spec, its live status and the sampled metrics
// into a single view, and runs problem detection over the result.
func buildPodInfo(pod *corev1.Pod, usage map[string]containerUsage, throttledPct float64, hasMetrics bool) PodInfo {
	workload, kind := podWorkload(pod)

	info := PodInfo{
		Name:         pod.Name,
		Namespace:    pod.Namespace,
		Workload:     workload,
		WorkloadKind: kind,
		NodeName:     pod.Spec.NodeName,
		Phase:        string(pod.Status.Phase),
		Age:          shortAge(pod.CreationTimestamp.Time),
		QOSClass:     string(pod.Status.QOSClass),
		ThrottledPct: throttledPct,
		MetricsAvail: hasMetrics,
		Problems:     []DetectedProblem{},
		Containers:   []PodContainerInfo{},
	}

	statusByName := map[string]corev1.ContainerStatus{}
	for _, cs := range pod.Status.ContainerStatuses {
		statusByName[cs.Name] = cs
	}

	readyContainers := 0
	for _, spec := range pod.Spec.Containers {
		ci := PodContainerInfo{Name: spec.Name, Image: spec.Image}

		if q := spec.Resources.Requests.Cpu(); q != nil {
			ci.CPURequests = q.AsApproximateFloat64()
		}
		if q := spec.Resources.Limits.Cpu(); q != nil {
			ci.CPULimits = q.AsApproximateFloat64()
		}
		if q := spec.Resources.Requests.Memory(); q != nil {
			ci.MemRequests = q.Value()
		}
		if q := spec.Resources.Limits.Memory(); q != nil {
			ci.MemLimits = q.Value()
		}

		if cs, ok := statusByName[spec.Name]; ok {
			ci.Ready = cs.Ready
			ci.RestartCount = int(cs.RestartCount)
			if cs.Ready {
				readyContainers++
			}
			switch {
			case cs.State.Running != nil:
				ci.State = "running"
			case cs.State.Waiting != nil:
				ci.State = "waiting"
				ci.StateReason = cs.State.Waiting.Reason
			case cs.State.Terminated != nil:
				ci.State = "terminated"
				ci.StateReason = cs.State.Terminated.Reason
			}
			if cs.LastTerminationState.Terminated != nil {
				ci.LastReason = cs.LastTerminationState.Terminated.Reason
				ci.LastExitCode = cs.LastTerminationState.Terminated.ExitCode
			}
			if cs.Image != "" {
				ci.Image = cs.Image
			}
		}

		if u, ok := usage[spec.Name]; ok {
			ci.CPUCores = u.CPUCores
			ci.MemBytes = int64(u.MemBytes)
		}
		ci.ThrottledPct = throttledPct

		info.CPUCores += ci.CPUCores
		info.CPURequests += ci.CPURequests
		info.CPULimits += ci.CPULimits
		info.MemBytes += ci.MemBytes
		info.MemRequests += ci.MemRequests
		info.MemLimits += ci.MemLimits
		info.RestartCount += ci.RestartCount
		info.Containers = append(info.Containers, ci)
	}

	if len(pod.Spec.Containers) > 0 {
		info.Image = info.Containers[0].Image
		info.Ready = readyContainers == len(pod.Spec.Containers)
	}

	// Percentages are measured against the limit when one is set, since that
	// is the value that actually causes throttling or an OOM kill. Without a
	// limit the request is the only meaningful reference point.
	if info.CPULimits > 0 {
		info.CPUPct = info.CPUCores / info.CPULimits * 100
	} else if info.CPURequests > 0 {
		info.CPUPct = info.CPUCores / info.CPURequests * 100
	}
	if info.MemLimits > 0 {
		info.MemPct = float64(info.MemBytes) / float64(info.MemLimits) * 100
	} else if info.MemRequests > 0 {
		info.MemPct = float64(info.MemBytes) / float64(info.MemRequests) * 100
	}

	info.Problems = detectPodProblems(&info, pod, hasMetrics)
	return info
}

// detectPodProblems turns raw pod state and usage into named conditions.
func detectPodProblems(info *PodInfo, pod *corev1.Pod, hasMetrics bool) []DetectedProblem {
	problems := []DetectedProblem{}
	add := func(kind, sev, title, detail string, value float64) {
		problems = append(problems, DetectedProblem{
			Kind: kind, Severity: sev, Title: title, Detail: detail, Value: value,
		})
	}

	for _, c := range info.Containers {
		if c.LastReason == "OOMKilled" {
			add("oom_killed", "critical", "Container OOMKilled",
				fmt.Sprintf("Container %s was killed for exceeding its memory limit (%s)",
					c.Name, humanBytes(c.MemLimits)), float64(c.RestartCount))
		}
		switch c.StateReason {
		case "CrashLoopBackOff":
			add("crashloop", "critical", "CrashLoopBackOff",
				fmt.Sprintf("Container %s is restarting in a loop (%d restarts, last exit code %d)",
					c.Name, c.RestartCount, c.LastExitCode), float64(c.RestartCount))
		case "ImagePullBackOff", "ErrImagePull":
			add("image_pull_failed", "critical", "Image Pull Failed",
				fmt.Sprintf("Container %s cannot pull image %s", c.Name, c.Image), 0)
		case "CreateContainerConfigError":
			add("config_error", "critical", "Container Config Error",
				fmt.Sprintf("Container %s has a missing ConfigMap or Secret reference", c.Name), 0)
		}
	}

	if pod.Status.Phase == corev1.PodPending {
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse {
				add("unschedulable", "critical", "Pod Unschedulable",
					fmt.Sprintf("Pod cannot be scheduled: %s", cond.Message), 0)
			}
		}
	}
	if pod.Status.Reason == "Evicted" {
		add("evicted", "critical", "Pod Evicted",
			fmt.Sprintf("Pod was evicted from node %s: %s", pod.Spec.NodeName, pod.Status.Message), 0)
	}

	// Resource conditions require live metrics to be meaningful.
	if !hasMetrics || pod.Status.Phase != corev1.PodRunning {
		return problems
	}

	if info.MemLimits > 0 && info.MemPct >= memWarnPct {
		sev := "warning"
		if info.MemPct >= memCritPct {
			sev = "critical"
		}
		add("mem_pressure", sev, "Memory Pressure",
			fmt.Sprintf("Using %s of %s memory limit (%.1f%%) - at risk of OOMKill",
				humanBytes(info.MemBytes), humanBytes(info.MemLimits), info.MemPct), info.MemPct)
	}

	if info.ThrottledPct >= throttleWarn {
		sev := "warning"
		if info.ThrottledPct >= throttleCrit {
			sev = "critical"
		}
		add("cpu_throttling", sev, "CPU Throttling",
			fmt.Sprintf("%.1f%% of CPU periods throttled against a %.2f core limit - the container is being starved, raise the limit",
				info.ThrottledPct, info.CPULimits), info.ThrottledPct)
	}

	if info.CPULimits > 0 && info.CPUPct >= cpuWarnPct {
		sev := "warning"
		if info.CPUPct >= cpuCritPct {
			sev = "critical"
		}
		add("cpu_saturation", sev, "CPU Saturation",
			fmt.Sprintf("Using %.2f of %.2f core limit (%.1f%%)",
				info.CPUCores, info.CPULimits, info.CPUPct), info.CPUPct)
	}

	if info.CPULimits == 0 || info.MemLimits == 0 {
		missing := []string{}
		if info.CPULimits == 0 {
			missing = append(missing, "cpu")
		}
		if info.MemLimits == 0 {
			missing = append(missing, "memory")
		}
		add("no_limits", "info", "Missing Resource Limits",
			fmt.Sprintf("No %s limit set - this pod can starve its node and is QoS class %s",
				strings.Join(missing, "/"), info.QOSClass), 0)
	}

	// A pod reserving far more than it uses blocks the scheduler from placing
	// other work, so it is a capacity problem even though nothing is failing.
	if info.MemRequests > 0 && info.MemBytes > 0 {
		pct := float64(info.MemBytes) / float64(info.MemRequests) * 100
		if pct < overProvisionPct {
			add("overprovisioned", "info", "Over-provisioned Memory",
				fmt.Sprintf("Using only %s of %s requested (%.1f%%) - the difference is reserved but idle",
					humanBytes(info.MemBytes), humanBytes(info.MemRequests), pct), pct)
		}
	}

	return problems
}

func humanBytes(b int64) string {
	switch {
	case b <= 0:
		return "none"
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(b)/(1<<20))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// collectPods gathers every pod with its metrics in one pass. Shared by the
// HTTP handler and the background poller.
func collectPods(clientset *kubernetes.Clientset, clusterID uint, namespace string, scrapeThrottling bool) ([]PodInfo, bool, error) {
	podList, err := clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("failed to list pods: %v", err)
	}

	metricsMap := fetchPodMetrics(clientset, namespace)
	metricsAvail := len(metricsMap) > 0

	// Scraping cadvisor means one request per node with a sizeable payload, and
	// the CFS counters only yield a rate when compared against a previous
	// sample. Both make it a job for the poller, not for a page load; the HTTP
	// path reuses the last value the poller stored.
	var throttleMap map[string]float64
	if scrapeThrottling {
		nodeSet := map[string]bool{}
		for i := range podList.Items {
			if n := podList.Items[i].Spec.NodeName; n != "" {
				nodeSet[n] = true
			}
		}
		nodeNames := make([]string, 0, len(nodeSet))
		for n := range nodeSet {
			nodeNames = append(nodeNames, n)
		}
		throttleMap = fetchThrottling(clientset, nodeNames)
	} else {
		throttleMap = lastThrottlingByPod(clusterID)
	}

	pods := make([]PodInfo, 0, len(podList.Items))
	for i := range podList.Items {
		pod := &podList.Items[i]
		key := pod.Namespace + "/" + pod.Name
		pods = append(pods, buildPodInfo(pod, metricsMap[key], throttleMap[key], metricsAvail))
	}
	return pods, metricsAvail, nil
}

// podCacheTTL is how long a collected listing is reused. Collecting costs a
// full pod list plus a metrics call against the apiserver, and the pods page
// refreshes every 30 seconds in every open tab -- without this, ten people
// watching the same cluster meant ten times the load for the same answer.
const podCacheTTL = 15 * time.Second

type podCacheEntry struct {
	pods         []PodInfo
	metricsAvail bool
	at           time.Time
	ready        chan struct{} // closed once the collection behind it finishes
	err          error
}

var (
	podCacheMu sync.Mutex
	podCache   = map[string]*podCacheEntry{}
)

// cachedPods collects pods for one cluster and namespace, reusing a recent
// result and collapsing concurrent requests onto a single collection so a
// burst of tabs cannot multiply into a burst of apiserver calls.
//
// What it caches is deliberately unfiltered: namespace scoping is applied per
// request by keepScopedPods, so two accounts with different scopes never share
// a view even though they share this entry.
func cachedPods(clientset *kubernetes.Clientset, clusterID uint, namespace string) ([]PodInfo, bool, error) {
	key := fmt.Sprintf("%d/%s", clusterID, namespace)

	podCacheMu.Lock()
	if e, ok := podCache[key]; ok {
		// The channel has to be captured under the lock: the collection that
		// owns it sets the field back to nil on completion, and a receive on a
		// nil channel blocks forever.
		if ch := e.ready; ch != nil {
			podCacheMu.Unlock()
			<-ch
			return e.pods, e.metricsAvail, e.err
		}
		if time.Since(e.at) < podCacheTTL {
			podCacheMu.Unlock()
			return e.pods, e.metricsAvail, e.err
		}
	}
	entry := &podCacheEntry{at: time.Now(), ready: make(chan struct{})}
	podCache[key] = entry
	podCacheMu.Unlock()

	entry.pods, entry.metricsAvail, entry.err = collectPods(clientset, clusterID, namespace, false)

	podCacheMu.Lock()
	entry.at = time.Now()
	ready := entry.ready
	entry.ready = nil
	// A failed collection is not worth serving for the next fifteen seconds:
	// drop it so the next request retries instead of inheriting the error.
	if entry.err != nil {
		delete(podCache, key)
	}
	podCacheMu.Unlock()
	close(ready)

	return entry.pods, entry.metricsAvail, entry.err
}

// GetPodStatus returns live pod resource usage and detected problems, read
// straight from metrics.k8s.io rather than through ArgoCD.
func GetPodStatus(c *fiber.Ctx) error {
	clientset, err := requestTyped(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	clusterID, err := requestClusterID(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	pods, metricsAvail, err := cachedPods(clientset, clusterID, c.Query("namespace"))
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	pods = keepScopedPods(c, pods)

	totals := map[string]int{"total": len(pods), "critical": 0, "warning": 0, "healthy": 0}
	for _, p := range pods {
		worst := ""
		for _, pr := range p.Problems {
			if pr.Severity == "critical" {
				worst = "critical"
				break
			}
			if pr.Severity == "warning" {
				worst = "warning"
			}
		}
		switch worst {
		case "critical":
			totals["critical"]++
		case "warning":
			totals["warning"]++
		default:
			totals["healthy"]++
		}
	}

	return c.JSON(fiber.Map{
		"pods":              pods,
		"totals":            totals,
		"metrics_available": metricsAvail,
	})
}

// GetPodHistory returns the stored time series for one pod or workload.
func GetPodHistory(c *fiber.Ctx) error {
	namespace := c.Query("namespace")
	podName := c.Query("pod")
	workload := c.Query("workload")

	if podName == "" && workload == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "pod or workload is required"})
	}

	clusterID, err := requestClusterID(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if namespace != "" && !namespaceAllowed(c, namespace) {
		return forbidNamespace(c)
	}

	q := db.DB.Model(&models.PodSnapshot{}).Where("cluster_id = ?", clusterID)
	if namespace != "" {
		q = q.Where("namespace = ?", namespace)
	}
	if podName != "" {
		q = q.Where("pod_name = ?", podName)
	} else {
		q = q.Where("workload = ?", workload)
	}

	var snapshots []models.PodSnapshot
	q.Order("recorded_at desc").Limit(2000).Find(&snapshots)

	pq := db.DB.Model(&models.PodProblem{}).Where("cluster_id = ?", clusterID)
	if namespace != "" {
		pq = pq.Where("namespace = ?", namespace)
	}
	if podName != "" {
		pq = pq.Where("pod_name = ?", podName)
	} else {
		pq = pq.Where("workload = ?", workload)
	}
	var problems []models.PodProblem
	pq.Order("opened_at desc").Limit(200).Find(&problems)

	return c.JSON(fiber.Map{"snapshots": snapshots, "problems": problems})
}

// GetPodProblems lists problems across the cluster, open ones by default.
func GetPodProblems(c *fiber.Ctx) error {
	clusterID, err := requestClusterID(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	q := db.DB.Model(&models.PodProblem{}).Where("cluster_id = ?", clusterID)
	if allowed, restricted, err := requestNamespaces(c); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	} else if restricted {
		q = q.Where("namespace IN ?", allowed)
	}
	if c.Query("status", "open") == "open" {
		q = q.Where("closed_at IS NULL")
	}
	if ns := c.Query("namespace"); ns != "" {
		q = q.Where("namespace = ?", ns)
	}
	if sev := c.Query("severity"); sev != "" {
		q = q.Where("severity = ?", sev)
	}

	var problems []models.PodProblem
	q.Order("opened_at desc").Limit(500).Find(&problems)
	if problems == nil {
		problems = []models.PodProblem{}
	}
	return c.JSON(fiber.Map{"problems": problems})
}

// PollPodMetrics samples every pod and reconciles detected problems against
// the open rows in the database, so a problem opens once, accumulates while it
// persists and closes when it clears.
func PollPodMetrics() {
	retentionDays := 3
	if v := os.Getenv("POD_RETENTION_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			retentionDays = d
		}
	}
	// Retention is by age alone: it applies to every cluster's rows equally.
	db.DB.Where("recorded_at < ?", time.Now().AddDate(0, 0, -retentionDays)).Delete(&models.PodSnapshot{})

	// One pass per cluster. A cluster that is unreachable is skipped rather
	// than aborting the sweep: its problems stay open, which is the truthful
	// state, and the clusters that do answer are still sampled.
	for _, cl := range allClusters() {
		pollPodMetricsFor(&cl)
	}
}

func pollPodMetricsFor(cl *models.Cluster) {
	clientset, _, err := collectorClients(cl)
	if err != nil {
		fmt.Printf("Pod monitoring: cluster %s: %v\n", cl.Name, err)
		return
	}

	pods, metricsAvail, err := collectPods(clientset, cl.ID, "", true)
	if err != nil {
		fmt.Printf("Pod monitoring: cluster %s: %v\n", cl.Name, err)
		return
	}

	now := time.Now()
	var openProblems []models.PodProblem
	db.DB.Where("cluster_id = ? AND closed_at IS NULL", cl.ID).Find(&openProblems)
	openByKey := map[string]models.PodProblem{}
	for _, p := range openProblems {
		openByKey[p.Namespace+"/"+p.PodName+"/"+p.Kind] = p
	}

	seen := map[string]bool{}
	livePods := map[string]bool{}

	// The pass builds up everything it intends to write and commits it in one
	// transaction at the end. Writing row by row meant a cluster of a few
	// hundred pods took the write lock a few hundred times every two minutes,
	// and for that whole stretch no page could read the database -- which is
	// what a five-second `database is locked` on `SELECT * FROM clusters` was
	// really reporting.
	snapshots := make([]models.PodSnapshot, 0, len(pods))
	newProblems := []models.PodProblem{}
	type problemTouch struct {
		id     uint
		fields map[string]interface{}
	}
	touched := []problemTouch{}
	type pendingNotice struct{ kind, title, body, workload string }
	notices := []pendingNotice{}

	for _, pod := range pods {
		livePods[pod.Namespace+"/"+pod.Name] = true

		if metricsAvail {
			snapshots = append(snapshots, models.PodSnapshot{
				ClusterID:    cl.ID,
				RecordedAt:   now,
				Namespace:    pod.Namespace,
				PodName:      pod.Name,
				Workload:     pod.Workload,
				WorkloadKind: pod.WorkloadKind,
				NodeName:     pod.NodeName,
				Phase:        pod.Phase,
				Ready:        pod.Ready,
				RestartCount: pod.RestartCount,
				Image:        pod.Image,
				CPUCores:     pod.CPUCores,
				CPURequests:  pod.CPURequests,
				CPULimits:    pod.CPULimits,
				CPUPct:       pod.CPUPct,
				MemBytes:     pod.MemBytes,
				MemRequests:  pod.MemRequests,
				MemLimits:    pod.MemLimits,
				MemPct:       pod.MemPct,
				ThrottledPct: pod.ThrottledPct,
			})
		}

		for _, det := range pod.Problems {
			key := pod.Namespace + "/" + pod.Name + "/" + det.Kind
			seen[key] = true

			if existing, ok := openByKey[key]; ok {
				touched = append(touched, problemTouch{existing.ID, map[string]interface{}{
					"last_seen_at": now,
					"occurrences":  existing.Occurrences + 1,
					"severity":     det.Severity,
					"detail":       det.Detail,
					"value":        det.Value,
				}})
				continue
			}

			newProblems = append(newProblems, models.PodProblem{
				ClusterID:   cl.ID,
				OpenedAt:    now,
				LastSeenAt:  now,
				Namespace:   pod.Namespace,
				PodName:     pod.Name,
				Workload:    pod.Workload,
				NodeName:    pod.NodeName,
				Kind:        det.Kind,
				Severity:    det.Severity,
				Title:       det.Title,
				Detail:      det.Detail,
				Value:       det.Value,
				Occurrences: 1,
			})

			// Informational findings are configuration advice, not incidents.
			if det.Severity == "info" {
				continue
			}
			notices = append(notices, pendingNotice{
				kind:  "pod." + det.Kind,
				title: det.Title,
				body: fmt.Sprintf("Pod %s in namespace %s: %s",
					pod.Name, pod.Namespace, det.Detail),
				workload: pod.Workload,
			})
		}
	}

	// Close problems that no longer reproduce. A problem whose pod is gone always
	// closes; otherwise a metrics-derived problem is left open when metrics were
	// unavailable this pass, since its absence proves nothing.
	closing := []uint{}
	for key, p := range openByKey {
		if seen[key] {
			continue
		}
		podAlive := livePods[p.Namespace+"/"+p.PodName]
		if podAlive && !metricsAvail && metricsDerived[p.Kind] {
			continue
		}
		closing = append(closing, p.ID)
	}

	err = db.DB.Transaction(func(tx *gorm.DB) error {
		if len(snapshots) > 0 {
			if err := tx.CreateInBatches(&snapshots, 200).Error; err != nil {
				return err
			}
		}
		if len(newProblems) > 0 {
			if err := tx.CreateInBatches(&newProblems, 100).Error; err != nil {
				return err
			}
		}
		for _, t := range touched {
			if err := tx.Model(&models.PodProblem{}).Where("id = ?", t.id).
				Updates(t.fields).Error; err != nil {
				return err
			}
		}
		if len(closing) > 0 {
			if err := tx.Model(&models.PodProblem{}).Where("id IN ?", closing).
				Update("closed_at", &now).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Pod monitoring: cluster %s: persisting the pass failed: %v\n", cl.Name, err)
		return
	}

	// Notifications go out only once the pass is committed: a problem that was
	// rolled back was never opened, and announcing it would page someone about
	// a row nobody can look up.
	for _, n := range notices {
		go SendNotifications(n.kind, n.title, n.body, n.workload, "system")
	}
}

// keepScopedPods drops the pods of namespaces this account is not scoped to.
// The collection above used the collector's credential, which sees the whole
// cluster, so filtering here is not belt-and-braces -- it is the only fence.
func keepScopedPods(c *fiber.Ctx, pods []PodInfo) []PodInfo {
	allowed, restricted, err := requestNamespaces(c)
	if err != nil || !restricted {
		return pods
	}
	permitted := map[string]bool{}
	for _, ns := range allowed {
		permitted[ns] = true
	}
	kept := pods[:0]
	for _, p := range pods {
		if permitted[p.Namespace] {
			kept = append(kept, p)
		}
	}
	return kept
}
