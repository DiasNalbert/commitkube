package handlers

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
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
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// The service map is built from what the cluster declares about itself: a
// Service's selector says which workload answers a name, an env var pointing
// at that name says who calls it, an Ingress says what gets in from outside.
//
// That makes the whole map automatic -- nothing is registered by hand -- but it
// also makes it *intent*, not traffic. An edge means "this is wired up to call
// that". It cannot know whether the call ever happens, and it cannot see a
// dependency that exists only as a hardcoded address inside an image. Measured
// traffic needs a per-node agent, because a pod can only observe its own
// network namespace; that is a separate layer, and models.ServiceEdge.Observed
// is the seam it will fill.

// nodeRef identifies one participant in the map. An external target has an
// empty Namespace and Kind "External", so its hostname alone is the identity.
type nodeRef struct {
	Namespace string
	Kind      string
	Name      string
}

func (n nodeRef) id() string { return n.Namespace + "/" + n.Kind + "/" + n.Name }

// edgeAcc is a discovered dependency before it is written. Several
// declarations often describe the same edge (an env var and a NetworkPolicy,
// say); they collapse on the identity of src+dst+port+source.
type edgeAcc struct {
	Src        nodeRef
	Dst        nodeRef
	Port       string
	Protocol   string
	Source     string
	Evidence   string
	Confidence string
}

func (e edgeAcc) key() string {
	return e.Src.id() + "->" + e.Dst.id() + "|" + e.Port + "|" + e.Source
}

// topoWorkload is one workload with the two things discovery needs from it:
// the labels a Service selector can match, and the pod spec whose env vars and
// ConfigMap references name the things it talks to.
type topoWorkload struct {
	Ref      nodeRef
	Labels   map[string]string
	Spec     corev1.PodSpec
	Replicas int32
	Status   string
}

// topoIndex resolves a hostname to the nodes it addresses, the way in-cluster
// DNS would, and accumulates the nodes discovered along the way.
type topoIndex struct {
	// byHost holds every form that unambiguously names a Service: the
	// namespace-qualified DNS names and the cluster IP.
	byHost map[string][]nodeRef
	// byBareName is keyed name -> namespace -> targets. A bare name only
	// resolves inside the caller's own namespace, which is why the namespace
	// stays part of the key instead of being flattened away.
	byBareName map[string]map[string][]nodeRef

	nodes map[string]*models.ServiceNode
}

func newTopoIndex() *topoIndex {
	return &topoIndex{
		byHost:     map[string][]nodeRef{},
		byBareName: map[string]map[string][]nodeRef{},
		nodes:      map[string]*models.ServiceNode{},
	}
}

// node returns the stored node for a ref, creating a bare one if this is the
// first time the ref is seen. Targets are frequently discovered as the far end
// of an edge before they are discovered as a workload of their own.
func (ix *topoIndex) node(ref nodeRef) *models.ServiceNode {
	if n, ok := ix.nodes[ref.id()]; ok {
		return n
	}
	n := &models.ServiceNode{
		Namespace: ref.Namespace,
		Kind:      ref.Kind,
		Name:      ref.Name,
		Status:    "unknown",
		External:  ref.Kind == "External",
	}
	if n.External {
		n.Hosts = ref.Name
	}
	ix.nodes[ref.id()] = n
	return n
}

func (ix *topoIndex) registerHost(host string, refs []nodeRef) {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" || len(refs) == 0 {
		return
	}
	ix.byHost[h] = refs
}

func (ix *topoIndex) registerBare(name, namespace string, refs []nodeRef) {
	n := strings.ToLower(name)
	if ix.byBareName[n] == nil {
		ix.byBareName[n] = map[string][]nodeRef{}
	}
	ix.byBareName[n][namespace] = refs
}

// resolveHost maps a hostname to the nodes it addresses. callerNS is the
// namespace doing the addressing, which is what makes a bare Service name
// resolvable: `redis` only means anything from inside the namespace that holds
// the `redis` Service, exactly as the pod's DNS search path would have it.
//
// qualified says the value was unmistakably an address -- it carried a scheme
// or a port. It only matters for hosts outside the cluster, where it is the
// difference between `http://api.vendor.io` and the string `log.level`.
func (ix *topoIndex) resolveHost(host, callerNS string, qualified bool) ([]nodeRef, string) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" || isLoopback(h) {
		return nil, ""
	}

	if refs, ok := ix.byHost[h]; ok {
		return refs, "high"
	}

	if !strings.Contains(h, ".") {
		if byNS, ok := ix.byBareName[h]; ok {
			if refs, ok := byNS[callerNS]; ok {
				return refs, "high"
			}
		}
		// A bare name that is not a Service in the caller's own namespace
		// would not resolve from that pod either. Inventing an edge to a
		// same-named Service elsewhere would be a guess, so it is dropped.
		return nil, ""
	}

	// An in-cluster name that did not resolve is a dangling reference -- a
	// Service that was renamed or never created. Worth surfacing one day as a
	// broken dependency; it is not an external target, so it is not turned
	// into one here.
	if strings.HasSuffix(h, ".svc") || strings.Contains(h, ".svc.") || strings.HasSuffix(h, ".cluster.local") {
		return nil, ""
	}

	if !isPlausibleExternalHost(h) {
		return nil, ""
	}
	// Outside the cluster there is nothing to check a name against, so an
	// unqualified value has to look like a real domain to be believed. Without
	// this, `LOG_FORMAT=log.level` becomes a service.
	if !qualified && !commonTLDs[h[strings.LastIndex(h, ".")+1:]] && net.ParseIP(h) == nil {
		return nil, ""
	}
	return []nodeRef{{Kind: "External", Name: h}}, "medium"
}

// commonTLDs is the believability test for an external hostname that arrived
// without a scheme or a port. It does not need to be exhaustive: a host that
// misses the list is simply left out of the map, and one named in a URL is
// accepted regardless.
var commonTLDs = map[string]bool{
	"com": true, "net": true, "org": true, "io": true, "dev": true, "app": true,
	"cloud": true, "ai": true, "co": true, "me": true, "info": true, "biz": true,
	"xyz": true, "sh": true, "gov": true, "edu": true, "int": true, "tech": true,
	"online": true, "site": true, "store": true, "run": true, "systems": true,
	"tools": true, "link": true, "zone": true, "digital": true, "email": true,
	"tv": true, "gg": true, "to": true, "id": true, "so": true, "fm": true,
	"br": true, "us": true, "uk": true, "de": true, "fr": true, "eu": true,
	"ca": true, "au": true, "jp": true, "cn": true, "in": true, "es": true,
	"it": true, "nl": true, "se": true, "no": true, "fi": true, "dk": true,
	"pl": true, "pt": true, "ru": true, "mx": true, "ar": true, "cl": true,
	"za": true, "ie": true, "ch": true, "at": true, "be": true, "nz": true,
}

func isLoopback(h string) bool {
	switch h {
	case "localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal":
		return true
	}
	return strings.HasPrefix(h, "127.")
}

// isPlausibleExternalHost keeps configuration noise out of the map. Env values
// are arbitrary strings; without this, any dotted word ("v1.2.3", "log.level")
// would become a node.
func isPlausibleExternalHost(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return !ip.IsLoopback() && !ip.IsUnspecified()
	}
	labelsOf := strings.Split(h, ".")
	if len(labelsOf) < 2 {
		return false
	}
	tld := labelsOf[len(labelsOf)-1]
	if len(tld) < 2 || !isAllAlpha(tld) {
		return false
	}
	for _, l := range labelsOf {
		if l == "" {
			return false
		}
	}
	return true
}

func isAllAlpha(s string) bool {
	for _, r := range s {
		if r < 'a' || r > 'z' {
			if r < 'A' || r > 'Z' {
				return false
			}
		}
	}
	return true
}

// portProtocol names the protocol behind a well-known port, so an edge to a
// database reads as "postgres" rather than "tcp".
var portProtocol = map[string]string{
	"80": "http", "443": "https", "8080": "http", "8443": "https", "3000": "http",
	"5432": "postgres", "3306": "mysql", "6379": "redis", "11211": "memcached",
	"5672": "amqp", "15672": "amqp", "9092": "kafka", "27017": "mongodb",
	"9200": "elasticsearch", "9300": "elasticsearch", "50051": "grpc",
	"1433": "mssql", "1521": "oracle", "8500": "consul", "2379": "etcd",
}

func protocolFor(scheme, port string) string {
	if scheme != "" {
		switch scheme {
		case "http", "https", "grpc", "grpcs", "amqp", "amqps", "redis", "rediss",
			"mongodb", "mongodb+srv", "kafka", "ws", "wss":
			return strings.TrimSuffix(scheme, "s")
		case "postgres", "postgresql":
			return "postgres"
		case "mysql":
			return "mysql"
		}
	}
	if p, ok := portProtocol[port]; ok {
		return p
	}
	return "tcp"
}

// hostCand is one address found inside a configuration value.
type hostCand struct {
	Host   string
	Port   string
	Scheme string
}

var hostPortRe = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9._-]*):(\d{1,5})$`)

// hostNameRe matches a hostname with no scheme and no port, which is how most
// env vars name a dependency: `REDIS_HOST=redis.data.svc.cluster.local`.
var hostNameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$`)

// clusterFQDNRe matches a name that can only be in-cluster DNS. Such a name is
// safe to read out of any text, including a whole config file, because nothing
// else is shaped like it.
var clusterFQDNRe = regexp.MustCompile(`(?i)^[a-z0-9][a-z0-9.-]*\.svc(\.cluster\.local)?$`)

// hostishKeyRe decides whether a single-word value may be read as a Service
// name. `PAYMENTS_HOST=payments` is an address; `NODE_ENV=production` is not,
// and without this test any value that happened to match a Service name would
// become an edge.
var hostishKeyRe = regexp.MustCompile(`(?i)(HOST|URL|URI|ADDR|ADDRESS|ENDPOINT|UPSTREAM|TARGET|BACKEND|SERVER|SERVICE|BROKER|DSN|DATABASE|_DB$|^DB_)`)

// secretishKeyRe marks values that must never be copied into evidence, even
// truncated: the value itself is the credential.
var secretishKeyRe = regexp.MustCompile(`(?i)(PASS|SECRET|TOKEN|CREDENTIAL|PRIVATE|APIKEY|API_KEY|_KEY$|^KEY$)`)

// valueSplit breaks a configuration value into tokens that could each be an
// address, without assuming the value is only an address: a JDBC string, a
// comma-separated broker list and a YAML line all give up their hosts here.
func valueSplit(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '"', '\'', '`', ',', ';', '(', ')', '[', ']', '{', '}', '<', '>', '|', '=':
		return true
	}
	return false
}

// extractCandidates pulls addresses out of a configuration value. allowBare
// permits a lone Service name, which is only safe when the key it came from
// looks like an address (see hostishKeyRe) -- never for a whole config file.
func extractCandidates(text string, allowBare bool) []hostCand {
	if len(text) > 64*1024 {
		return nil
	}
	out := []hostCand{}
	seen := map[string]bool{}
	add := func(c hostCand) {
		k := c.Scheme + "|" + c.Host + "|" + c.Port
		if c.Host == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, c)
	}

	for _, tok := range strings.FieldsFunc(text, valueSplit) {
		switch {
		case strings.Contains(tok, "://"):
			// url.Parse handles credentials, paths and brackets for us, which
			// a regex over the raw token would get wrong.
			u, err := url.Parse(tok)
			if err != nil || u.Hostname() == "" {
				continue
			}
			add(hostCand{Host: u.Hostname(), Port: u.Port(), Scheme: strings.ToLower(u.Scheme)})
		case hostPortRe.MatchString(tok):
			m := hostPortRe.FindStringSubmatch(tok)
			if p, err := strconv.Atoi(m[2]); err == nil && p > 0 && p <= 65535 {
				add(hostCand{Host: m[1], Port: m[2]})
			}
		case clusterFQDNRe.MatchString(tok):
			add(hostCand{Host: tok})
		case allowBare && hostNameRe.MatchString(tok):
			add(hostCand{Host: tok})
		}
	}
	return out
}

// redact strips credentials and trims a declaration down to something safe to
// store as evidence. A DSN in an env var carries a password; the map needs the
// host, never the secret.
var userinfoRe = regexp.MustCompile(`://[^/@\s]*@`)

func redact(s string) string {
	s = userinfoRe.ReplaceAllString(s, "://***@")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// maxPeers caps how many workloads one NetworkPolicy rule may expand to. A
// policy that selects everything in a namespace is a blanket allow, not a
// statement about dependencies, and fanning it out would bury the real edges.
const maxPeers = 25

// listTopoWorkloads reads every workload that can be a participant in the map.
// Bare pods and one-off Jobs are left out on purpose: they are instances, not
// services. A CronJob is included because it is a recurring caller, and its
// env vars are often the only record that it talks to anything.
func listTopoWorkloads(ctx context.Context, typed kubernetes.Interface) ([]topoWorkload, error) {
	opts := metav1.ListOptions{}
	out := []topoWorkload{}

	deps, err := typed.AppsV1().Deployments("").List(ctx, opts)
	if err != nil {
		return nil, err
	}
	for i := range deps.Items {
		d := &deps.Items[i]
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		out = append(out, topoWorkload{
			Ref:      nodeRef{d.Namespace, "Deployment", d.Name},
			Labels:   d.Spec.Template.Labels,
			Spec:     d.Spec.Template.Spec,
			Replicas: desired,
			Status:   deriveStatus(desired, d.Status.ReadyReplicas),
		})
	}

	sts, err := typed.AppsV1().StatefulSets("").List(ctx, opts)
	if err != nil {
		return nil, err
	}
	for i := range sts.Items {
		s := &sts.Items[i]
		desired := int32(1)
		if s.Spec.Replicas != nil {
			desired = *s.Spec.Replicas
		}
		out = append(out, topoWorkload{
			Ref:      nodeRef{s.Namespace, "StatefulSet", s.Name},
			Labels:   s.Spec.Template.Labels,
			Spec:     s.Spec.Template.Spec,
			Replicas: desired,
			Status:   deriveStatus(desired, s.Status.ReadyReplicas),
		})
	}

	ds, err := typed.AppsV1().DaemonSets("").List(ctx, opts)
	if err != nil {
		return nil, err
	}
	for i := range ds.Items {
		d := &ds.Items[i]
		out = append(out, topoWorkload{
			Ref:      nodeRef{d.Namespace, "DaemonSet", d.Name},
			Labels:   d.Spec.Template.Labels,
			Spec:     d.Spec.Template.Spec,
			Replicas: d.Status.DesiredNumberScheduled,
			Status:   deriveStatus(d.Status.DesiredNumberScheduled, d.Status.NumberReady),
		})
	}

	// CronJobs are best-effort: an older cluster serves them under batch/v1beta1
	// and the list simply fails, which costs the map nothing else.
	if cjs, err := typed.BatchV1().CronJobs("").List(ctx, opts); err == nil {
		for i := range cjs.Items {
			cj := &cjs.Items[i]
			status := "healthy"
			if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
				status = "scaled_zero"
			}
			out = append(out, topoWorkload{
				Ref:      nodeRef{cj.Namespace, "CronJob", cj.Name},
				Labels:   cj.Spec.JobTemplate.Spec.Template.Labels,
				Spec:     cj.Spec.JobTemplate.Spec.Template.Spec,
				Replicas: 0,
				Status:   status,
			})
		}
	}

	return out, nil
}

// matchWorkloads resolves a plain selector map (a Service's) to workloads in
// one namespace, by matching it against each workload's pod template labels.
func matchWorkloads(selector map[string]string, ns string, workloads []topoWorkload) []nodeRef {
	if len(selector) == 0 {
		return nil
	}
	sel := labels.Set(selector).AsSelector()
	out := []nodeRef{}
	for i := range workloads {
		w := &workloads[i]
		if w.Ref.Namespace != ns || len(w.Labels) == 0 {
			continue
		}
		if sel.Matches(labels.Set(w.Labels)) {
			out = append(out, w.Ref)
		}
	}
	return out
}

// matchLabelSelector is the same resolution for the richer selector type used
// by NetworkPolicy, which also supports matchExpressions.
func matchLabelSelector(ls *metav1.LabelSelector, namespaces []string, workloads []topoWorkload) []nodeRef {
	sel := labels.Everything()
	if ls != nil {
		s, err := metav1.LabelSelectorAsSelector(ls)
		if err != nil {
			return nil
		}
		sel = s
	}
	nsSet := map[string]bool{}
	for _, ns := range namespaces {
		nsSet[ns] = true
	}
	out := []nodeRef{}
	for i := range workloads {
		w := &workloads[i]
		if !nsSet[w.Ref.Namespace] {
			continue
		}
		if sel.Matches(labels.Set(w.Labels)) {
			out = append(out, w.Ref)
		}
	}
	return out
}

// indexServices makes every Service addressable by each name it answers to,
// and records which workload is actually behind it. A Service whose selector
// matches nothing we listed becomes a node in its own right, so the edge is
// still drawn -- it just stops at the Service.
func indexServices(ix *topoIndex, svcs []corev1.Service, workloads []topoWorkload) {
	for i := range svcs {
		svc := &svcs[i]

		var refs []nodeRef
		switch {
		case svc.Spec.Type == corev1.ServiceTypeExternalName && svc.Spec.ExternalName != "":
			// The Service is a pointer out of the cluster: the dependency is
			// the host it forwards to, not the Service object.
			refs = []nodeRef{{Kind: "External", Name: strings.ToLower(svc.Spec.ExternalName)}}
		default:
			refs = matchWorkloads(svc.Spec.Selector, svc.Namespace, workloads)
			if len(refs) == 0 {
				refs = []nodeRef{{svc.Namespace, "Service", svc.Name}}
			}
		}

		for _, r := range refs {
			n := ix.node(r)
			if r.Kind != "External" && r.Kind != "Service" {
				n.Services = appendCSV(n.Services, svc.Name)
			}
		}

		ix.registerBare(svc.Name, svc.Namespace, refs)
		for _, form := range []string{
			svc.Name + "." + svc.Namespace,
			svc.Name + "." + svc.Namespace + ".svc",
			svc.Name + "." + svc.Namespace + ".svc.cluster.local",
		} {
			ix.registerHost(form, refs)
		}
		if ip := svc.Spec.ClusterIP; ip != "" && ip != corev1.ClusterIPNone {
			ix.registerHost(ip, refs)
		}
	}
}

func appendCSV(csv, v string) string {
	if csv == "" {
		return v
	}
	for _, p := range strings.Split(csv, ",") {
		if p == v {
			return csv
		}
	}
	return csv + "," + v
}

// scanValue reads one configuration value and emits an edge for every address
// in it that resolves to something in the map.
func scanValue(ix *topoIndex, src nodeRef, key, value, source string, out *[]edgeAcc) {
	if strings.TrimSpace(value) == "" {
		return
	}
	allowBare := key != "" && hostishKeyRe.MatchString(key)

	for _, c := range extractCandidates(value, allowBare) {
		refs, conf := ix.resolveHost(c.Host, src.Namespace, c.Scheme != "" || c.Port != "")
		if len(refs) == 0 {
			continue
		}
		hostport := c.Host
		if c.Port != "" {
			hostport += ":" + c.Port
		}
		evidence := key + "=" + value
		if key == "" {
			evidence = value
		}
		// A long value is a whole config file and a secret-looking key holds a
		// credential; in both cases report the match, not the value.
		if secretishKeyRe.MatchString(key) || len(value) > 200 {
			evidence = strings.TrimSpace(key + " → " + hostport)
		}

		for _, dst := range refs {
			if dst.id() == src.id() {
				continue // a workload addressing its own Service is not a dependency
			}
			ix.node(dst)
			*out = append(*out, edgeAcc{
				Src:        src,
				Dst:        dst,
				Port:       c.Port,
				Protocol:   protocolFor(c.Scheme, c.Port),
				Source:     source,
				Evidence:   redact(evidence),
				Confidence: conf,
			})
		}
	}
}

// edgesFromConfig is where most real edges come from: the env vars, ConfigMap
// values and arguments that tell a container where its dependencies live.
//
// Secrets are deliberately never read here. A DSN in a Secret would yield an
// edge, but it would mean this poller pulling every Secret in the cluster into
// memory every few minutes, and the Secrets page gates that access behind a
// password re-check for a reason.
func edgesFromConfig(ix *topoIndex, workloads []topoWorkload, cms map[string]map[string]string) []edgeAcc {
	out := []edgeAcc{}

	for i := range workloads {
		w := &workloads[i]
		src := w.Ref
		cmData := func(name string) map[string]string {
			return cms[w.Ref.Namespace+"/"+name]
		}

		containers := append([]corev1.Container{}, w.Spec.InitContainers...)
		containers = append(containers, w.Spec.Containers...)

		for ci := range containers {
			c := &containers[ci]

			for _, e := range c.Env {
				if e.Value != "" {
					scanValue(ix, src, e.Name, e.Value, "env", &out)
					continue
				}
				if e.ValueFrom != nil && e.ValueFrom.ConfigMapKeyRef != nil {
					ref := e.ValueFrom.ConfigMapKeyRef
					if d := cmData(ref.Name); d != nil {
						scanValue(ix, src, e.Name, d[ref.Key], "configmap", &out)
					}
				}
			}

			for _, ef := range c.EnvFrom {
				if ef.ConfigMapRef == nil {
					continue
				}
				for k, v := range cmData(ef.ConfigMapRef.Name) {
					scanValue(ix, src, k, v, "configmap", &out)
				}
			}

			// Command and args carry addresses too (`--upstream=http://api:80`),
			// but they are free text: only fully qualified forms are read, never
			// a bare word.
			for _, a := range append(append([]string{}, c.Command...), c.Args...) {
				scanValue(ix, src, "", a, "env", &out)
			}
		}

		// A mounted ConfigMap is a config file. Its keys are filenames, not
		// hostish names, so nothing bare is accepted from here either.
		for _, vol := range w.Spec.Volumes {
			names := []string{}
			if vol.ConfigMap != nil {
				names = append(names, vol.ConfigMap.Name)
			}
			if vol.Projected != nil {
				for _, s := range vol.Projected.Sources {
					if s.ConfigMap != nil {
						names = append(names, s.ConfigMap.Name)
					}
				}
			}
			for _, name := range names {
				for k, v := range cmData(name) {
					scanValue(ix, src, name+"/"+k, v, "mount", &out)
				}
			}
		}
	}

	return out
}

// edgesFromIngress adds the cluster's entry points. An Ingress is modelled as
// a node rather than an attribute of its backend, because "what is reachable
// from outside" is one of the things a service map is read for.
func edgesFromIngress(ix *topoIndex, ings []networkingv1.Ingress) []edgeAcc {
	out := []edgeAcc{}

	for i := range ings {
		ing := &ings[i]
		src := nodeRef{ing.Namespace, "Ingress", ing.Name}

		hosts := []string{}
		for _, r := range ing.Spec.Rules {
			if r.Host != "" {
				hosts = append(hosts, r.Host)
			}
		}
		n := ix.node(src)
		n.Hosts = strings.Join(hosts, ",")
		n.Status = "healthy"

		link := func(b *networkingv1.IngressBackend, path string) {
			if b == nil || b.Service == nil {
				return
			}
			refs := ix.byBareName[strings.ToLower(b.Service.Name)][ing.Namespace]
			if len(refs) == 0 {
				return
			}
			port := ""
			if b.Service.Port.Number > 0 {
				port = strconv.Itoa(int(b.Service.Port.Number))
			} else if b.Service.Port.Name != "" {
				port = b.Service.Port.Name
			}
			evidence := "Ingress " + ing.Name
			if path != "" {
				evidence += " " + path
			}
			evidence += " → " + b.Service.Name
			for _, dst := range refs {
				ix.node(dst)
				out = append(out, edgeAcc{
					Src: src, Dst: dst, Port: port,
					Protocol: protocolFor("http", port),
					Source:   "ingress", Evidence: evidence, Confidence: "high",
				})
			}
		}

		link(ing.Spec.DefaultBackend, "")
		for _, r := range ing.Spec.Rules {
			if r.HTTP == nil {
				continue
			}
			for _, p := range r.HTTP.Paths {
				label := r.Host + p.Path
				link(&p.Backend, label)
			}
		}
	}

	return out
}

// edgesFromNetworkPolicies reads the cluster's allow rules. These are the
// weakest evidence in the map -- permission to talk is not a dependency -- but
// in a namespace with tight policies they are also the most complete picture
// of who is *meant* to talk to whom, which is why they are kept at low
// confidence rather than dropped.
func edgesFromNetworkPolicies(
	ix *topoIndex,
	policies []networkingv1.NetworkPolicy,
	workloads []topoWorkload,
	nsLabels map[string]map[string]string,
) []edgeAcc {
	out := []edgeAcc{}

	namespacesMatching := func(sel *metav1.LabelSelector, own string) []string {
		if sel == nil {
			return []string{own}
		}
		s, err := metav1.LabelSelectorAsSelector(sel)
		if err != nil {
			return nil
		}
		res := []string{}
		for ns, l := range nsLabels {
			if s.Matches(labels.Set(l)) {
				res = append(res, ns)
			}
		}
		return res
	}

	for i := range policies {
		np := &policies[i]
		owners := matchLabelSelector(&np.Spec.PodSelector, []string{np.Namespace}, workloads)
		if len(owners) == 0 || len(owners) > maxPeers {
			continue
		}

		peersOf := func(peers []networkingv1.NetworkPolicyPeer) []nodeRef {
			res := []nodeRef{}
			for pi := range peers {
				p := &peers[pi]
				if p.IPBlock != nil || (p.PodSelector == nil && p.NamespaceSelector == nil) {
					continue // a CIDR or an allow-all says nothing about services
				}
				ns := namespacesMatching(p.NamespaceSelector, np.Namespace)
				if len(ns) == 0 {
					continue
				}
				res = append(res, matchLabelSelector(p.PodSelector, ns, workloads)...)
			}
			return res
		}

		portsOf := func(ports []networkingv1.NetworkPolicyPort) []string {
			res := []string{}
			for _, p := range ports {
				if p.Port != nil {
					res = append(res, p.Port.String())
				}
			}
			if len(res) == 0 {
				res = []string{""}
			}
			return res
		}

		emit := func(src, dst nodeRef, port, direction string) {
			if src.id() == dst.id() {
				return
			}
			ix.node(src)
			ix.node(dst)
			out = append(out, edgeAcc{
				Src: src, Dst: dst, Port: port,
				Protocol:   protocolFor("", port),
				Source:     "networkpolicy",
				Evidence:   "NetworkPolicy " + np.Name + " (" + direction + ")",
				Confidence: "low",
			})
		}

		for _, rule := range np.Spec.Egress {
			peers := peersOf(rule.To)
			if len(peers) == 0 || len(peers) > maxPeers {
				continue
			}
			for _, port := range portsOf(rule.Ports) {
				for _, o := range owners {
					for _, p := range peers {
						emit(o, p, port, "egress")
					}
				}
			}
		}

		for _, rule := range np.Spec.Ingress {
			peers := peersOf(rule.From)
			if len(peers) == 0 || len(peers) > maxPeers {
				continue
			}
			for _, port := range portsOf(rule.Ports) {
				for _, o := range owners {
					for _, p := range peers {
						emit(p, o, port, "ingress")
					}
				}
			}
		}
	}

	return out
}

var istioVirtualServices = schema.GroupVersionResource{
	Group: "networking.istio.io", Version: "v1beta1", Resource: "virtualservices",
}

// edgesFromIstio adds mesh entry points, and is a no-op on a cluster without
// Istio: the list simply fails and the map is built from everything else.
//
// Only a VirtualService bound to a gateway becomes an edge. One without
// gateways is a routing rule applied to whoever already calls the host -- it
// names a destination but no caller, so it would add a node with no meaning.
func edgesFromIstio(ctx context.Context, dyn dynamic.Interface, ix *topoIndex) []edgeAcc {
	list, err := dyn.Resource(istioVirtualServices).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	out := []edgeAcc{}
	for i := range list.Items {
		item := &list.Items[i]
		gateways, _, _ := unstructured.NestedStringSlice(item.Object, "spec", "gateways")
		if len(gateways) == 0 {
			continue
		}
		src := nodeRef{item.GetNamespace(), "Ingress", item.GetName()}
		hosts, _, _ := unstructured.NestedStringSlice(item.Object, "spec", "hosts")
		n := ix.node(src)
		n.Hosts = strings.Join(hosts, ",")
		n.Status = "healthy"

		for _, section := range []string{"http", "tcp", "tls"} {
			rules, _, _ := unstructured.NestedSlice(item.Object, "spec", section)
			for _, r := range rules {
				rm, ok := r.(map[string]interface{})
				if !ok {
					continue
				}
				routes, _, _ := unstructured.NestedSlice(rm, "route")
				for _, rt := range routes {
					rtm, ok := rt.(map[string]interface{})
					if !ok {
						continue
					}
					host, _, _ := unstructured.NestedString(rtm, "destination", "host")
					if host == "" {
						continue
					}
					port := ""
					if pn, found, _ := unstructured.NestedInt64(rtm, "destination", "port", "number"); found {
						port = strconv.FormatInt(pn, 10)
					}
					// A route destination is an address by definition.
					refs, conf := ix.resolveHost(host, item.GetNamespace(), true)
					for _, dst := range refs {
						if dst.id() == src.id() {
							continue
						}
						ix.node(dst)
						out = append(out, edgeAcc{
							Src: src, Dst: dst, Port: port,
							Protocol:   protocolFor(section, port),
							Source:     "istio",
							Evidence:   "VirtualService " + item.GetName() + " → " + host,
							Confidence: conf,
						})
					}
				}
			}
		}
	}
	return out
}

// loadReferencedConfigMaps fetches the ConfigMaps the workloads actually name.
// One cluster-wide list is a single API call, against one Get per reference;
// everything unreferenced is dropped immediately rather than kept in memory.
func loadReferencedConfigMaps(ctx context.Context, typed kubernetes.Interface, workloads []topoWorkload) map[string]map[string]string {
	wanted := map[string]bool{}
	for i := range workloads {
		w := &workloads[i]
		want := func(name string) {
			if name != "" {
				wanted[w.Ref.Namespace+"/"+name] = true
			}
		}
		containers := append([]corev1.Container{}, w.Spec.InitContainers...)
		containers = append(containers, w.Spec.Containers...)
		for ci := range containers {
			c := &containers[ci]
			for _, e := range c.Env {
				if e.ValueFrom != nil && e.ValueFrom.ConfigMapKeyRef != nil {
					want(e.ValueFrom.ConfigMapKeyRef.Name)
				}
			}
			for _, ef := range c.EnvFrom {
				if ef.ConfigMapRef != nil {
					want(ef.ConfigMapRef.Name)
				}
			}
		}
		for _, vol := range w.Spec.Volumes {
			if vol.ConfigMap != nil {
				want(vol.ConfigMap.Name)
			}
			if vol.Projected != nil {
				for _, s := range vol.Projected.Sources {
					if s.ConfigMap != nil {
						want(s.ConfigMap.Name)
					}
				}
			}
		}
	}

	out := map[string]map[string]string{}
	if len(wanted) == 0 {
		return out
	}
	list, err := typed.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return out
	}
	for i := range list.Items {
		cm := &list.Items[i]
		key := cm.Namespace + "/" + cm.Name
		if wanted[key] {
			out[key] = cm.Data
		}
	}
	return out
}

// confidenceRank orders the three levels so that when two declarations describe
// the same edge, the stronger evidence is the one that is kept.
var confidenceRank = map[string]int{"low": 1, "medium": 2, "high": 3}

func dedupeEdges(edges []edgeAcc) []edgeAcc {
	best := map[string]edgeAcc{}
	order := []string{}
	for _, e := range edges {
		k := e.key()
		prev, ok := best[k]
		if !ok {
			best[k] = e
			order = append(order, k)
			continue
		}
		if confidenceRank[e.Confidence] > confidenceRank[prev.Confidence] {
			best[k] = e
		}
	}
	out := make([]edgeAcc, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}

// discoverTopology reads the cluster once and returns the whole map. Each
// source beyond the core (Ingress, NetworkPolicy, Istio) is best-effort: a
// missing permission or a missing CRD costs that source's edges, not the map.
func discoverTopology(ctx context.Context, cl *models.Cluster) (*topoIndex, []edgeAcc, error) {
	typed, dyn, err := collectorClients(cl)
	if err != nil {
		return nil, nil, err
	}

	workloads, err := listTopoWorkloads(ctx, typed)
	if err != nil {
		return nil, nil, err
	}
	svcs, err := typed.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	ix := newTopoIndex()
	for i := range workloads {
		w := &workloads[i]
		n := ix.node(w.Ref)
		n.Replicas = w.Replicas
		n.Status = w.Status
	}
	indexServices(ix, svcs.Items, workloads)

	edges := edgesFromConfig(ix, workloads, loadReferencedConfigMaps(ctx, typed, workloads))

	if ings, err := typed.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{}); err == nil {
		edges = append(edges, edgesFromIngress(ix, ings.Items)...)
	}

	if nps, err := typed.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{}); err == nil && len(nps.Items) > 0 {
		nsLabels := map[string]map[string]string{}
		if nss, err := typed.CoreV1().Namespaces().List(ctx, metav1.ListOptions{}); err == nil {
			for i := range nss.Items {
				nsLabels[nss.Items[i].Name] = nss.Items[i].Labels
			}
		}
		edges = append(edges, edgesFromNetworkPolicies(ix, nps.Items, workloads, nsLabels)...)
	}

	edges = append(edges, edgesFromIstio(ctx, dyn, ix)...)

	return ix, dedupeEdges(edges), nil
}

// PollTopology rebuilds the map and upserts it. Nodes and edges keep a
// LastSeen instead of being deleted and reinserted, so a dependency that was
// removed yesterday is still visible today and disappears on retention -- the
// map has a memory, which is what makes "this used to call that" answerable.
func PollTopology() {
	retentionDays := 7
	if v := os.Getenv("TOPOLOGY_RETENTION_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			retentionDays = d
		}
	}

	// One discovery per cluster. A cluster that fails is reported and skipped:
	// aborting would drop the map for every other cluster too.
	failed := 0
	for _, cl := range allClusters() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		ix, edges, err := discoverTopology(ctx, &cl)
		cancel()
		if err != nil {
			fmt.Printf("Topology discovery: cluster %s: %v\n", cl.Name, err)
			topologyState.fail("discovery " + cl.Name + ": " + err.Error())
			failed++
			continue
		}
		if err := persistTopology(cl.ID, ix, edges, time.Now(), retentionDays); err != nil {
			fmt.Printf("Topology store: cluster %s: %v\n", cl.Name, err)
			topologyState.fail("store " + cl.Name + ": " + err.Error())
			failed++
		}
	}
	if failed == 0 {
		topologyState.ok()
	}
}

// persistTopology writes one discovery pass. It is separated from the polling
// so the upsert can be tested against a real database: a silent write failure
// here is indistinguishable from an empty cluster on the page, which is
// exactly the kind of bug that needs a test rather than a log line.
func persistTopology(clusterID uint, ix *topoIndex, edges []edgeAcc, now time.Time, retentionDays int) error {
	nodeUpsert := clause.OnConflict{
		Columns: []clause.Column{{Name: "cluster_id"}, {Name: "namespace"}, {Name: "kind"}, {Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"updated_at", "last_seen", "services", "hosts", "replicas", "status", "external",
		}),
	}
	nodes := make([]models.ServiceNode, 0, len(ix.nodes))
	for _, n := range ix.nodes {
		n.ClusterID = clusterID
		n.FirstSeen = now
		n.LastSeen = now
		n.UpdatedAt = now
		nodes = append(nodes, *n)
	}
	if len(nodes) > 0 {
		if err := db.DB.Clauses(nodeUpsert).CreateInBatches(nodes, 200).Error; err != nil {
			return fmt.Errorf("nodes: %w", err)
		}
	}

	// Observed is left out of the update list on purpose: the traffic layer
	// owns that column, and a discovery poll must not clear what it set.
	edgeUpsert := clause.OnConflict{
		Columns: []clause.Column{
			{Name: "cluster_id"},
			{Name: "src_namespace"}, {Name: "src_kind"}, {Name: "src_name"},
			{Name: "dst_namespace"}, {Name: "dst_kind"}, {Name: "dst_name"},
			{Name: "port"}, {Name: "source"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"updated_at", "last_seen", "protocol", "evidence", "confidence",
		}),
	}
	rows := make([]models.ServiceEdge, 0, len(edges))
	for _, e := range edges {
		rows = append(rows, models.ServiceEdge{
			ClusterID: clusterID,
			UpdatedAt: now, FirstSeen: now, LastSeen: now,
			SrcNamespace: e.Src.Namespace, SrcKind: e.Src.Kind, SrcName: e.Src.Name,
			DstNamespace: e.Dst.Namespace, DstKind: e.Dst.Kind, DstName: e.Dst.Name,
			Port: e.Port, Source: e.Source, Protocol: e.Protocol,
			Evidence: e.Evidence, Confidence: e.Confidence,
		})
	}
	if len(rows) > 0 {
		if err := db.DB.Clauses(edgeUpsert).CreateInBatches(rows, 200).Error; err != nil {
			return fmt.Errorf("edges: %w", err)
		}
	}

	cutoff := now.AddDate(0, 0, -retentionDays)
	db.DB.Where("cluster_id = ? AND last_seen < ?", clusterID, cutoff).Delete(&models.ServiceEdge{})
	db.DB.Where("cluster_id = ? AND last_seen < ?", clusterID, cutoff).Delete(&models.ServiceNode{})
	return nil
}

// topologyRun records how the last pass went. Without it a failed poll is
// indistinguishable on the page from a cluster with nothing in it -- the error
// only reaches the pod's stdout, which is the wrong place to have to look for
// the reason a page is empty.
type topologyRun struct {
	mu        sync.Mutex
	lastRun   time.Time
	lastError string
}

var topologyState topologyRun

func (s *topologyRun) fail(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRun = time.Now()
	s.lastError = msg
}

func (s *topologyRun) ok() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRun = time.Now()
	s.lastError = ""
}

// snapshot reports when the last pass ran and why it failed, if it did. A zero
// time means no pass has finished yet in this process.
func (s *topologyRun) snapshot() (time.Time, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRun, s.lastError
}

// topologyNode is the shape the graph page draws. Depth and the degrees are
// computed here rather than in the browser so the frontend needs no graph
// library: it lays nodes out in columns by depth.
type topologyNode struct {
	ID         string    `json:"id"`
	Namespace  string    `json:"namespace"`
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	Services   []string  `json:"services"`
	Hosts      []string  `json:"hosts"`
	Replicas   int32     `json:"replicas"`
	Status     string    `json:"status"`
	External   bool      `json:"external"`
	EntryPoint bool      `json:"entry_point"`
	Depth      int       `json:"depth"`
	InDegree   int       `json:"in_degree"`
	OutDegree  int       `json:"out_degree"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

type topologyEdge struct {
	From       string    `json:"from"`
	To         string    `json:"to"`
	Port       string    `json:"port"`
	Protocol   string    `json:"protocol"`
	Source     string    `json:"source"`
	Evidence   string    `json:"evidence"`
	Confidence string    `json:"confidence"`
	Observed   bool      `json:"observed"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// GetTopology serves the map. Filters narrow what is returned, never what is
// stored: the poller always discovers everything, so switching a filter off
// does not mean waiting for the next poll.
func GetTopology(c *fiber.Ctx) error {
	sinceHours := 48
	if v := c.Query("since_hours"); v != "" {
		if h, err := strconv.Atoi(v); err == nil && h > 0 {
			sinceHours = h
		}
	}
	cutoff := time.Now().Add(-time.Duration(sinceHours) * time.Hour)

	nsFilter := c.Query("namespace")
	includeExternal := c.Query("include_external") != "false"
	includeIsolated := c.Query("include_isolated") == "true"

	clusterID, err := requestClusterID(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	edgeQuery := db.DB.Where("cluster_id = ? AND last_seen >= ?", clusterID, cutoff)
	if s := c.Query("source"); s != "" {
		edgeQuery = edgeQuery.Where("source IN ?", splitCSV(s))
	}
	if mc := c.Query("min_confidence"); confidenceRank[mc] > 0 {
		allowed := []string{}
		for level, rank := range confidenceRank {
			if rank >= confidenceRank[mc] {
				allowed = append(allowed, level)
			}
		}
		edgeQuery = edgeQuery.Where("confidence IN ?", allowed)
	}

	var stored []models.ServiceEdge
	edgeQuery.Order("src_namespace, src_name, dst_namespace, dst_name").Find(&stored)

	var storedNodes []models.ServiceNode
	db.DB.Where("cluster_id = ? AND last_seen >= ?", clusterID, cutoff).Find(&storedNodes)

	byID := map[string]*models.ServiceNode{}
	for i := range storedNodes {
		n := &storedNodes[i]
		byID[nodeRef{n.Namespace, n.Kind, n.Name}.id()] = n
	}

	edges := []topologyEdge{}
	inDeg := map[string]int{}
	outDeg := map[string]int{}
	used := map[string]bool{}
	bySource := map[string]int{}
	byConfidence := map[string]int{}
	observed := 0

	for i := range stored {
		e := &stored[i]
		src := nodeRef{e.SrcNamespace, e.SrcKind, e.SrcName}
		dst := nodeRef{e.DstNamespace, e.DstKind, e.DstName}

		if !includeExternal && (src.Kind == "External" || dst.Kind == "External") {
			continue
		}
		// A namespace filter keeps the edges that touch it, so the neighbours
		// outside the namespace stay visible -- a map of one namespace with its
		// callers cut off would not be a map.
		if nsFilter != "" && e.SrcNamespace != nsFilter && e.DstNamespace != nsFilter {
			continue
		}

		edges = append(edges, topologyEdge{
			From: src.id(), To: dst.id(),
			Port: e.Port, Protocol: e.Protocol, Source: e.Source,
			Evidence: e.Evidence, Confidence: e.Confidence, Observed: e.Observed,
			FirstSeen: e.FirstSeen, LastSeen: e.LastSeen,
		})
		outDeg[src.id()]++
		inDeg[dst.id()]++
		used[src.id()] = true
		used[dst.id()] = true
		bySource[e.Source]++
		byConfidence[e.Confidence]++
		if e.Observed {
			observed++
		}

		// An edge can name a node that fell outside the node query (a target
		// discovered only as the far end of an edge). Synthesising it keeps the
		// graph closed instead of dropping the edge.
		for _, ref := range []nodeRef{src, dst} {
			if _, ok := byID[ref.id()]; !ok {
				byID[ref.id()] = &models.ServiceNode{
					Namespace: ref.Namespace, Kind: ref.Kind, Name: ref.Name,
					Status: "unknown", External: ref.Kind == "External",
					FirstSeen: e.FirstSeen, LastSeen: e.LastSeen,
				}
			}
		}
	}

	// Depth by longest path from an entry point, relaxed edge by edge. The
	// iteration cap is what makes a dependency cycle terminate instead of
	// counting forever.
	depth := map[string]int{}
	for i := 0; i < 20; i++ {
		changed := false
		for _, e := range edges {
			if depth[e.To] < depth[e.From]+1 {
				depth[e.To] = depth[e.From] + 1
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	isolated := 0
	nodes := []topologyNode{}
	namespaces := map[string]bool{}
	for id, n := range byID {
		connected := used[id]
		if !connected {
			isolated++
			if !includeIsolated {
				continue
			}
		}
		if !includeExternal && n.External {
			continue
		}
		if nsFilter != "" && !connected && n.Namespace != nsFilter {
			continue
		}
		if n.Namespace != "" {
			namespaces[n.Namespace] = true
		}
		nodes = append(nodes, topologyNode{
			ID:        id,
			Namespace: n.Namespace, Kind: n.Kind, Name: n.Name,
			Services: splitCSV(n.Services), Hosts: splitCSV(n.Hosts),
			Replicas: n.Replicas, Status: n.Status, External: n.External,
			EntryPoint: inDeg[id] == 0 && outDeg[id] > 0,
			Depth:      depth[id],
			InDegree:   inDeg[id], OutDegree: outDeg[id],
			FirstSeen: n.FirstSeen, LastSeen: n.LastSeen,
		})
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Depth != nodes[j].Depth {
			return nodes[i].Depth < nodes[j].Depth
		}
		if nodes[i].Namespace != nodes[j].Namespace {
			return nodes[i].Namespace < nodes[j].Namespace
		}
		return nodes[i].Name < nodes[j].Name
	})

	nsList := make([]string, 0, len(namespaces))
	for ns := range namespaces {
		nsList = append(nsList, ns)
	}
	sort.Strings(nsList)

	var lastPoll *time.Time
	for i := range storedNodes {
		if lastPoll == nil || storedNodes[i].LastSeen.After(*lastPoll) {
			lastPoll = &storedNodes[i].LastSeen
		}
	}

	lastRun, lastError := topologyState.snapshot()
	var lastRunOut *time.Time
	if !lastRun.IsZero() {
		lastRunOut = &lastRun
	}

	return c.JSON(fiber.Map{
		"nodes":      nodes,
		"edges":      edges,
		"namespaces": nsList,
		// last_run and last_error describe the discovery pass itself, so an
		// empty map can say whether it found nothing or never got to look.
		"last_run":   lastRunOut,
		"last_error": lastError,
		"stats": fiber.Map{
			"nodes":         len(nodes),
			"edges":         len(edges),
			"isolated":      isolated,
			"observed":      observed,
			"by_source":     bySource,
			"by_confidence": byConfidence,
		},
		"last_poll": lastPoll,
		// The map is inferred from what the cluster declares. Nothing here was
		// measured, and the page says so rather than implying it was.
		"declared_only": observed == 0,
	})
}

// RefreshTopology rebuilds the map now instead of waiting for the next poll,
// for when someone has just deployed and wants to see the new dependency.
func RefreshTopology(c *fiber.Ctx) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	PollTopology()

	// The refresh rebuilds every cluster, but the counts reported back are the
	// ones for the cluster the caller is looking at -- a total across clusters
	// would not match the map they are about to see.
	clusterID, err := requestClusterID(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	var nodes, edges int64
	db.DB.Model(&models.ServiceNode{}).Where("cluster_id = ?", clusterID).Count(&nodes)
	db.DB.Model(&models.ServiceEdge{}).Where("cluster_id = ?", clusterID).Count(&edges)

	lastRun, lastError := topologyState.snapshot()
	if lastError != "" {
		// A discovery that could not read the cluster is a failed request, not
		// an empty result: returning 200 here is what made the page say
		// "nothing discovered yet" when the real answer was a missing
		// permission.
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "Service map discovery failed: " + lastError,
		})
	}
	return c.JSON(fiber.Map{
		"nodes": nodes, "edges": edges, "refreshed_at": lastRun,
	})
}
