package handlers

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The cluster overview answers, on one screen, the three questions every other
// page only answers in part: how much of the cluster is actually used, what is
// broken right now, and where the consumption is concentrated. Everything is
// derived live from the API server -- nothing here reads the snapshot tables,
// so the page never shows a stale number from a poller that stopped.

// ClusterAxis is one resource dimension measured at the four levels that
// matter. Capacity is what the machines have, allocatable is what the kubelet
// will hand out, requests is what the scheduler has already committed, and
// usage is what is genuinely being consumed. The gap between requests and
// usage is the cluster's waste; the gap between allocatable and requests is
// what can still be scheduled.
type ClusterAxis struct {
	Capacity    float64 `json:"capacity"`
	Allocatable float64 `json:"allocatable"`
	Requests    float64 `json:"requests"`
	Limits      float64 `json:"limits"`
	Usage       float64 `json:"usage"`
}

type CountedValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type NodeSummary struct {
	Name          string  `json:"name"`
	Status        string  `json:"status"` // healthy | warning | critical | unknown
	StatusText    string  `json:"status_text"`
	Roles         string  `json:"roles"`
	Version       string  `json:"version"`
	Age           string  `json:"age"`
	CPUUsageCores float64 `json:"cpu_usage_cores"`
	CPUCapCores   float64 `json:"cpu_cap_cores"`
	CPUPct        float64 `json:"cpu_pct"`
	MemUsageBytes float64 `json:"mem_usage_bytes"`
	MemCapBytes   float64 `json:"mem_cap_bytes"`
	MemPct        float64 `json:"mem_pct"`
	Pods          int     `json:"pods"`
	PodCapacity   int     `json:"pod_capacity"`
	Schedulable   bool    `json:"schedulable"`
}

type NamespaceUsage struct {
	Name        string  `json:"name"`
	CPUCores    float64 `json:"cpu_cores"`
	CPURequests float64 `json:"cpu_requests"`
	MemBytes    float64 `json:"mem_bytes"`
	MemRequests float64 `json:"mem_requests"`
	Pods        int     `json:"pods"`
}

type PodUsage struct {
	Name      string  `json:"name"`
	Namespace string  `json:"namespace"`
	CPUCores  float64 `json:"cpu_cores"`
	MemBytes  float64 `json:"mem_bytes"`
	Node      string  `json:"node"`
}

type ProblemSummary struct {
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type ProblemPod struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Severity  string `json:"severity"`
}

type WorkloadHealth struct {
	Kind     string `json:"kind"`
	Total    int    `json:"total"`
	Degraded int    `json:"degraded"`
}

type ClusterOverview struct {
	KubernetesVersion string         `json:"kubernetes_version"`
	Versions          []CountedValue `json:"versions"`
	OSImages          []CountedValue `json:"os_images"`
	OldestNodeAge     string         `json:"oldest_node_age"`

	NodesTotal     int `json:"nodes_total"`
	NodesReady     int `json:"nodes_ready"`
	NodesNotReady  int `json:"nodes_not_ready"`
	NodesCordoned  int `json:"nodes_cordoned"`
	NodesUnderLoad int `json:"nodes_under_pressure"`

	CPU         ClusterAxis `json:"cpu"`
	Memory      ClusterAxis `json:"memory"`
	PodsRunning int         `json:"pods_running"`
	PodCapacity int         `json:"pod_capacity"`

	PodsByPhase    map[string]int `json:"pods_by_phase"`
	PodsTotal      int            `json:"pods_total"`
	PodsReady      int            `json:"pods_ready"`
	PodsRestarts   int            `json:"pods_restarts"`
	Containers     int            `json:"containers"`
	NamespaceCount int            `json:"namespace_count"`

	Workloads []WorkloadHealth `json:"workloads"`
	Inventory map[string]int   `json:"inventory"`

	Problems      []ProblemSummary `json:"problems"`
	ProblemPods   []ProblemPod     `json:"problem_pods"`
	CriticalCount int              `json:"critical_count"`
	WarningCount  int              `json:"warning_count"`

	TopNamespaces []NamespaceUsage `json:"top_namespaces"`
	TopPodsCPU    []PodUsage       `json:"top_pods_cpu"`
	TopPodsMem    []PodUsage       `json:"top_pods_mem"`
	Nodes         []NodeSummary    `json:"nodes"`

	MetricsAvailable bool     `json:"metrics_available"`
	Degraded         []string `json:"degraded,omitempty"` // best-effort lookups that failed
}

// topCounts turns a tally into the ordered list a "spread" card renders,
// biggest first, so one odd kubelet version among forty stands out.
func topCounts(tally map[string]int, limit int) []CountedValue {
	out := make([]CountedValue, 0, len(tally))
	for v, n := range tally {
		out = append(out, CountedValue{Value: v, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// GetClusterOverview aggregates the whole cluster into a single response.
func GetClusterOverview(c *fiber.Ctx) error {
	cs, err := requestTyped(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "cannot connect to cluster: " + err.Error()})
	}

	ctx := context.Background()
	opts := metav1.ListOptions{}
	o := &ClusterOverview{
		PodsByPhase: map[string]int{},
		Inventory:   map[string]int{},
		Workloads:   []WorkloadHealth{},
		Problems:    []ProblemSummary{},
		ProblemPods: []ProblemPod{},
	}

	// Nodes first: they set the denominator for everything that follows.
	nodeList, err := cs.CoreV1().Nodes().List(ctx, opts)
	if err != nil {
		return k8sError(c, err)
	}
	nodeMetrics := fetchNodeMetrics(cs)
	o.MetricsAvailable = len(nodeMetrics) > 0

	versions := map[string]int{}
	osImages := map[string]int{}
	podsPerNode := map[string]int{}
	var oldest *corev1.Node

	o.NodesTotal = len(nodeList.Items)
	for i := range nodeList.Items {
		n := &nodeList.Items[i]
		versions[n.Status.NodeInfo.KubeletVersion]++
		osImages[n.Status.NodeInfo.OSImage]++

		if oldest == nil || n.CreationTimestamp.Time.Before(oldest.CreationTimestamp.Time) {
			oldest = n
		}

		ready, pressure := false, false
		for _, cond := range n.Status.Conditions {
			switch cond.Type {
			case corev1.NodeReady:
				ready = cond.Status == corev1.ConditionTrue
			case corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure:
				// Any pressure condition means the kubelet is already evicting
				// or about to, which a "Ready" node otherwise hides.
				if cond.Status == corev1.ConditionTrue {
					pressure = true
				}
			}
		}
		if ready {
			o.NodesReady++
		} else {
			o.NodesNotReady++
		}
		if pressure {
			o.NodesUnderLoad++
		}
		// A cordoned node is Ready and takes no new work: invisible in a plain
		// ready count, and the usual reason capacity "disappears".
		if n.Spec.Unschedulable {
			o.NodesCordoned++
		}

		o.CPU.Capacity += n.Status.Capacity.Cpu().AsApproximateFloat64()
		o.CPU.Allocatable += n.Status.Allocatable.Cpu().AsApproximateFloat64()
		o.Memory.Capacity += n.Status.Capacity.Memory().AsApproximateFloat64()
		o.Memory.Allocatable += n.Status.Allocatable.Memory().AsApproximateFloat64()
		o.PodCapacity += int(n.Status.Capacity.Pods().Value())

		status, statusText := "healthy", "Ready"
		switch {
		case !ready:
			status, statusText = "critical", "NotReady"
		case pressure:
			status, statusText = "warning", "Under pressure"
		case n.Spec.Unschedulable:
			status, statusText = "warning", "Cordoned"
		}

		roles := []string{}
		for label := range n.Labels {
			if strings.HasPrefix(label, "node-role.kubernetes.io/") {
				if r := strings.TrimPrefix(label, "node-role.kubernetes.io/"); r != "" {
					roles = append(roles, r)
				}
			}
		}
		sort.Strings(roles)

		ns := NodeSummary{
			Name: n.Name, Status: status, StatusText: statusText,
			Roles: strings.Join(roles, ","), Version: n.Status.NodeInfo.KubeletVersion,
			Age:         shortAge(n.CreationTimestamp.Time),
			CPUCapCores: n.Status.Capacity.Cpu().AsApproximateFloat64(),
			MemCapBytes: n.Status.Capacity.Memory().AsApproximateFloat64(),
			PodCapacity: int(n.Status.Capacity.Pods().Value()),
			Schedulable: !n.Spec.Unschedulable,
		}
		if m, ok := nodeMetrics[n.Name]; ok {
			ns.CPUUsageCores = m.CPUUsageCores
			ns.MemUsageBytes = m.MemUsageBytes
			if ns.CPUCapCores > 0 {
				ns.CPUPct = m.CPUUsageCores / ns.CPUCapCores * 100
			}
			if ns.MemCapBytes > 0 {
				ns.MemPct = m.MemUsageBytes / ns.MemCapBytes * 100
			}
			o.CPU.Usage += m.CPUUsageCores
			o.Memory.Usage += m.MemUsageBytes
		}
		o.Nodes = append(o.Nodes, ns)
	}

	if oldest != nil {
		o.OldestNodeAge = shortAge(oldest.CreationTimestamp.Time)
	}
	o.Versions = topCounts(versions, 5)
	o.OSImages = topCounts(osImages, 5)
	if len(o.Versions) > 0 {
		o.KubernetesVersion = o.Versions[0].Value
	}

	// Worst node first: the whole point of the list is the exception.
	rank := map[string]int{"critical": 0, "warning": 1, "unknown": 2, "healthy": 3}
	sort.SliceStable(o.Nodes, func(i, j int) bool {
		if rank[o.Nodes[i].Status] != rank[o.Nodes[j].Status] {
			return rank[o.Nodes[i].Status] < rank[o.Nodes[j].Status]
		}
		return o.Nodes[i].CPUPct > o.Nodes[j].CPUPct
	})

	// Pods: the single listing that feeds phases, commitment, per-namespace
	// consumption and the problem tally, so the page costs one pod list.
	podList, err := cs.CoreV1().Pods("").List(ctx, opts)
	if err != nil {
		return k8sError(c, err)
	}
	podMetrics := fetchPodMetrics(cs, "")
	if len(podMetrics) > 0 {
		o.MetricsAvailable = true
	}

	nsUsage := map[string]*NamespaceUsage{}
	problemTally := map[string]*ProblemSummary{}

	o.PodsTotal = len(podList.Items)
	for i := range podList.Items {
		pod := &podList.Items[i]
		o.PodsByPhase[string(pod.Status.Phase)]++
		if pod.Spec.NodeName != "" {
			podsPerNode[pod.Spec.NodeName]++
		}

		key := pod.Namespace + "/" + pod.Name
		usage := containerUsage{}
		for _, u := range podMetrics[key] {
			usage.CPUCores += u.CPUCores
			usage.MemBytes += u.MemBytes
		}

		// Only pods that hold a slot count toward commitment: a Succeeded or
		// Failed pod keeps its spec but the scheduler has already released it.
		scheduled := pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodPending
		if pod.Status.Phase == corev1.PodRunning {
			o.PodsRunning++
		}

		allReady := len(pod.Status.ContainerStatuses) > 0
		for j := range pod.Status.ContainerStatuses {
			st := &pod.Status.ContainerStatuses[j]
			o.PodsRestarts += int(st.RestartCount)
			if !st.Ready {
				allReady = false
			}
		}
		if allReady && pod.Status.Phase == corev1.PodRunning {
			o.PodsReady++
		}

		u := nsUsage[pod.Namespace]
		if u == nil {
			u = &NamespaceUsage{Name: pod.Namespace}
			nsUsage[pod.Namespace] = u
		}
		u.Pods++
		u.CPUCores += usage.CPUCores
		u.MemBytes += usage.MemBytes

		for _, ctr := range pod.Spec.Containers {
			o.Containers++
			if !scheduled {
				continue
			}
			if q, ok := ctr.Resources.Requests[corev1.ResourceCPU]; ok {
				v := q.AsApproximateFloat64()
				o.CPU.Requests += v
				u.CPURequests += v
			}
			if q, ok := ctr.Resources.Limits[corev1.ResourceCPU]; ok {
				o.CPU.Limits += q.AsApproximateFloat64()
			}
			if q, ok := ctr.Resources.Requests[corev1.ResourceMemory]; ok {
				v := q.AsApproximateFloat64()
				o.Memory.Requests += v
				u.MemRequests += v
			}
			if q, ok := ctr.Resources.Limits[corev1.ResourceMemory]; ok {
				o.Memory.Limits += q.AsApproximateFloat64()
			}
		}

		// Problem detection is the same pass the Pods and Triage pages use, so
		// a number here always agrees with the list it links to. Throttling is
		// passed as zero: measuring it means scraping cadvisor per node, which
		// is the poller's job, not a page load's.
		info := buildPodInfo(pod, podMetrics[key], 0, o.MetricsAvailable)
		for _, p := range info.Problems {
			if t, ok := problemTally[p.Kind]; ok {
				t.Count++
			} else {
				problemTally[p.Kind] = &ProblemSummary{
					Kind: p.Kind, Title: p.Title, Severity: p.Severity, Count: 1,
				}
			}
			switch p.Severity {
			case "critical":
				o.CriticalCount++
			case "warning":
				o.WarningCount++
			}
			if p.Severity == "critical" {
				o.ProblemPods = append(o.ProblemPods, ProblemPod{
					Name: pod.Name, Namespace: pod.Namespace,
					Title: p.Title, Detail: p.Detail, Severity: p.Severity,
				})
			}
		}

		if usage.CPUCores > 0 || usage.MemBytes > 0 {
			o.TopPodsCPU = append(o.TopPodsCPU, PodUsage{
				Name: pod.Name, Namespace: pod.Namespace, Node: pod.Spec.NodeName,
				CPUCores: usage.CPUCores, MemBytes: usage.MemBytes,
			})
		}
	}

	for i := range o.Nodes {
		o.Nodes[i].Pods = podsPerNode[o.Nodes[i].Name]
	}

	o.TopPodsMem = append([]PodUsage{}, o.TopPodsCPU...)
	sort.Slice(o.TopPodsCPU, func(i, j int) bool { return o.TopPodsCPU[i].CPUCores > o.TopPodsCPU[j].CPUCores })
	sort.Slice(o.TopPodsMem, func(i, j int) bool { return o.TopPodsMem[i].MemBytes > o.TopPodsMem[j].MemBytes })
	if len(o.TopPodsCPU) > 8 {
		o.TopPodsCPU = o.TopPodsCPU[:8]
	}
	if len(o.TopPodsMem) > 8 {
		o.TopPodsMem = o.TopPodsMem[:8]
	}

	for _, t := range problemTally {
		o.Problems = append(o.Problems, *t)
	}
	sort.Slice(o.Problems, func(i, j int) bool {
		si := map[string]int{"critical": 0, "warning": 1}[o.Problems[i].Severity]
		sj := map[string]int{"critical": 0, "warning": 1}[o.Problems[j].Severity]
		if si != sj {
			return si < sj
		}
		return o.Problems[i].Count > o.Problems[j].Count
	})
	if len(o.ProblemPods) > 10 {
		o.ProblemPods = o.ProblemPods[:10]
	}

	for _, u := range nsUsage {
		o.TopNamespaces = append(o.TopNamespaces, *u)
	}
	// Ordered by what is actually burning CPU, falling back to requests when
	// metrics-server is down, so the card is never empty.
	sort.Slice(o.TopNamespaces, func(i, j int) bool {
		if o.MetricsAvailable {
			return o.TopNamespaces[i].CPUCores > o.TopNamespaces[j].CPUCores
		}
		return o.TopNamespaces[i].CPURequests > o.TopNamespaces[j].CPURequests
	})
	if len(o.TopNamespaces) > 8 {
		o.TopNamespaces = o.TopNamespaces[:8]
	}

	// Inventory and workload health. Each listing is best effort: one missing
	// RBAC rule or absent CRD costs a number, never the page, and what failed
	// is reported so the zero is not mistaken for an empty cluster.
	fail := func(what string, err error) {
		o.Degraded = append(o.Degraded, fmt.Sprintf("%s: %v", what, err))
	}

	if l, err := cs.CoreV1().Namespaces().List(ctx, opts); err == nil {
		o.NamespaceCount = len(l.Items)
		o.Inventory["namespaces"] = len(l.Items)
	} else {
		fail("namespaces", err)
	}
	o.Inventory["pods"] = o.PodsTotal
	o.Inventory["nodes"] = o.NodesTotal

	if l, err := cs.AppsV1().Deployments("").List(ctx, opts); err == nil {
		h := WorkloadHealth{Kind: "Deployment", Total: len(l.Items)}
		for i := range l.Items {
			d := &l.Items[i]
			desired := int32(1)
			if d.Spec.Replicas != nil {
				desired = *d.Spec.Replicas
			}
			if d.Status.ReadyReplicas < desired {
				h.Degraded++
			}
		}
		o.Workloads = append(o.Workloads, h)
		o.Inventory["deployments"] = h.Total
	} else {
		fail("deployments", err)
	}

	if l, err := cs.AppsV1().StatefulSets("").List(ctx, opts); err == nil {
		h := WorkloadHealth{Kind: "StatefulSet", Total: len(l.Items)}
		for i := range l.Items {
			s := &l.Items[i]
			desired := int32(1)
			if s.Spec.Replicas != nil {
				desired = *s.Spec.Replicas
			}
			if s.Status.ReadyReplicas < desired {
				h.Degraded++
			}
		}
		o.Workloads = append(o.Workloads, h)
		o.Inventory["statefulsets"] = h.Total
	} else {
		fail("statefulsets", err)
	}

	if l, err := cs.AppsV1().DaemonSets("").List(ctx, opts); err == nil {
		h := WorkloadHealth{Kind: "DaemonSet", Total: len(l.Items)}
		for i := range l.Items {
			d := &l.Items[i]
			if d.Status.NumberReady < d.Status.DesiredNumberScheduled {
				h.Degraded++
			}
		}
		o.Workloads = append(o.Workloads, h)
		o.Inventory["daemonsets"] = h.Total
	} else {
		fail("daemonsets", err)
	}

	if l, err := cs.AppsV1().ReplicaSets("").List(ctx, opts); err == nil {
		o.Inventory["replicasets"] = len(l.Items)
	}
	if l, err := cs.CoreV1().Services("").List(ctx, opts); err == nil {
		o.Inventory["services"] = len(l.Items)
	} else {
		fail("services", err)
	}
	if l, err := cs.NetworkingV1().Ingresses("").List(ctx, opts); err == nil {
		o.Inventory["ingresses"] = len(l.Items)
	}
	if l, err := cs.CoreV1().PersistentVolumeClaims("").List(ctx, opts); err == nil {
		o.Inventory["persistentvolumeclaims"] = len(l.Items)
	}
	if l, err := cs.BatchV1().CronJobs("").List(ctx, opts); err == nil {
		o.Inventory["cronjobs"] = len(l.Items)
	}
	if l, err := cs.BatchV1().Jobs("").List(ctx, opts); err == nil {
		o.Inventory["jobs"] = len(l.Items)
	}

	return c.JSON(o)
}
