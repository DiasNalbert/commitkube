package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// The detail endpoint answers the question a list cannot: what *is* this one
// object, and what else in the cluster is attached to it. It is deliberately
// separate from the manifest endpoint -- a manifest shows what was declared,
// this shows what the declaration actually resolved to (which pods a selector
// matched, what a namespace is really consuming).

// KeyValue keeps labels and annotations ordered, so the panel renders the same
// way on every reload instead of following Go's map iteration.
type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type ServicePortDetail struct {
	Name        string `json:"name"`
	Port        int32  `json:"port"`
	Protocol    string `json:"protocol"`
	TargetPort  string `json:"target_port"`
	NodePort    int32  `json:"node_port"`
	AppProtocol string `json:"app_protocol"`
}

type RelatedPod struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // healthy | warning | critical | unknown
	Phase    string `json:"phase"`  // human readable state
	Ready    string `json:"ready"`  // "2/2"
	Restarts int32  `json:"restarts"`
	Node     string `json:"node"`
	IP       string `json:"ip"`
	Endpoint bool   `json:"endpoint"` // backing a ready endpoint address right now
}

type RelatedWorkload struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Pods int    `json:"pods"`
}

type RelatedIngress struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
	Paths []string `json:"paths"`
}

type ServiceDetail struct {
	Name                  string              `json:"name"`
	Namespace             string              `json:"namespace"`
	Type                  string              `json:"type"`
	Created               string              `json:"created"`
	Age                   string              `json:"age"`
	UID                   string              `json:"uid"`
	ClusterIPs            []string            `json:"cluster_ips"`
	ExternalIPs           []string            `json:"external_ips"`
	ExternalName          string              `json:"external_name"`
	SessionAffinity       string              `json:"session_affinity"`
	InternalTrafficPolicy string              `json:"internal_traffic_policy"`
	ExternalTrafficPolicy string              `json:"external_traffic_policy"`
	IPFamilies            []string            `json:"ip_families"`
	IPFamilyPolicy        string              `json:"ip_family_policy"`
	Ports                 []ServicePortDetail `json:"ports"`
	Labels                []KeyValue          `json:"labels"`
	Annotations           []KeyValue          `json:"annotations"`
	Selector              []KeyValue          `json:"selector"`
	EndpointsReady        int                 `json:"endpoints_ready"`
	EndpointsNotReady     int                 `json:"endpoints_not_ready"`
	EndpointsError        string              `json:"endpoints_error,omitempty"`
	Pods                  []RelatedPod        `json:"pods"`
	Workloads             []RelatedWorkload   `json:"workloads"`
	Ingresses             []RelatedIngress    `json:"ingresses"`
	Status                string              `json:"status"`
	StatusText            string              `json:"status_text"`
}

type ResourceAxis struct {
	Usage    float64 `json:"usage"`
	Requests float64 `json:"requests"`
	Limits   float64 `json:"limits"`
}

type QuotaEntry struct {
	Resource string `json:"resource"`
	Used     string `json:"used"`
	Hard     string `json:"hard"`
}

type QuotaDetail struct {
	Name    string       `json:"name"`
	Entries []QuotaEntry `json:"entries"`
}

type LimitRangeEntry struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Resource string `json:"resource"`
	Min      string `json:"min"`
	Max      string `json:"max"`
	Default  string `json:"default"`
	Request  string `json:"default_request"`
}

type TopPod struct {
	Name     string  `json:"name"`
	CPUCores float64 `json:"cpu_cores"`
	MemBytes float64 `json:"mem_bytes"`
}

type NamespaceDetail struct {
	Name        string     `json:"name"`
	Phase       string     `json:"phase"`
	Created     string     `json:"created"`
	Age         string     `json:"age"`
	UID         string     `json:"uid"`
	Labels      []KeyValue `json:"labels"`
	Annotations []KeyValue `json:"annotations"`

	// Counts is the inventory of the namespace: what kinds of object live in
	// it and how many. Keyed by the slug the Kubernetes pages already use, so
	// the panel can link straight to the matching list.
	Counts map[string]int `json:"counts"`

	PodsRunning   int `json:"pods_running"`
	PodsPending   int `json:"pods_pending"`
	PodsFailed    int `json:"pods_failed"`
	PodsSucceeded int `json:"pods_succeeded"`
	PodsTotal     int `json:"pods_total"`
	Containers    int `json:"containers"`

	CPU              ResourceAxis `json:"cpu"`
	Memory           ResourceAxis `json:"memory"`
	MetricsAvailable bool         `json:"metrics_available"`

	Quotas      []QuotaDetail     `json:"quotas"`
	LimitRanges []LimitRangeEntry `json:"limit_ranges"`
	TopPods     []TopPod          `json:"top_pods"`
}

// kindsWithDetail gates the endpoint: a kind without a hand-written detail view
// gets a clear error instead of an empty panel.
var kindsWithDetail = map[string]bool{
	"services":   true,
	"namespaces": true,
}

// GetK8sResourceDetail returns the enriched, kind-specific view of one object.
func GetK8sResourceDetail(c *fiber.Ctx) error {
	kind := strings.ToLower(c.Params("kind"))
	name := c.Params("name")
	namespace := c.Query("namespace")

	if !kindsWithDetail[kind] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("no detail view for kind %q", kind),
		})
	}
	if name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name is required"})
	}

	// A namespaced detail names one object; a namespace detail names itself.
	target := namespace
	if kind == "namespaces" {
		target = name
	}
	if target != "" && !namespaceAllowed(c, target) {
		return forbidNamespace(c)
	}

	clientset, err := requestTyped(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "cannot connect to cluster: " + err.Error()})
	}
	ctx := context.Background()

	switch kind {
	case "services":
		if namespace == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "namespace is required for services"})
		}
		detail, err := buildServiceDetail(ctx, clientset, namespace, name)
		if err != nil {
			return k8sError(c, err)
		}
		return c.JSON(fiber.Map{"kind": kind, "service": detail})

	case "namespaces":
		detail, err := buildNamespaceDetail(ctx, clientset, name)
		if err != nil {
			return k8sError(c, err)
		}
		return c.JSON(fiber.Map{"kind": kind, "namespace": detail})
	}

	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported kind"})
}

func toKeyValues(m map[string]string) []KeyValue {
	out := make([]KeyValue, 0, len(m))
	for k, v := range m {
		out = append(out, KeyValue{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// podHealth condenses a pod's containers into the same four-state vocabulary
// the resource lists use, so a Service's pod table reads like the Pods page.
func podHealth(pod *corev1.Pod) (status, phase, ready string, restarts int32) {
	total := len(pod.Spec.Containers)
	readyCount := 0
	waitingReason := ""
	for i := range pod.Status.ContainerStatuses {
		cs := &pod.Status.ContainerStatuses[i]
		if cs.Ready {
			readyCount++
		}
		restarts += cs.RestartCount
		if cs.State.Waiting != nil && waitingReason == "" {
			waitingReason = cs.State.Waiting.Reason
		}
	}
	ready = fmt.Sprintf("%d/%d", readyCount, total)

	phase = string(pod.Status.Phase)
	if waitingReason != "" {
		phase = waitingReason
	}

	switch {
	case pod.DeletionTimestamp != nil:
		return "warning", "Terminating", ready, restarts
	case pod.Status.Phase == corev1.PodFailed:
		return "critical", phase, ready, restarts
	case pod.Status.Phase == corev1.PodSucceeded:
		return "unknown", phase, ready, restarts
	case waitingReason != "":
		return "critical", phase, ready, restarts
	case total > 0 && readyCount == total:
		return "healthy", phase, ready, restarts
	case readyCount == 0:
		return "critical", phase, ready, restarts
	default:
		return "warning", phase, ready, restarts
	}
}

func buildServiceDetail(ctx context.Context, cs kubernetes.Interface, namespace, name string) (*ServiceDetail, error) {
	svc, err := cs.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	d := &ServiceDetail{
		Name:                  svc.Name,
		Namespace:             svc.Namespace,
		Type:                  string(svc.Spec.Type),
		Created:               svc.CreationTimestamp.UTC().Format("2006-01-02 15:04:05 UTC"),
		Age:                   shortAge(svc.CreationTimestamp.Time),
		UID:                   string(svc.UID),
		ClusterIPs:            svc.Spec.ClusterIPs,
		ExternalName:          svc.Spec.ExternalName,
		SessionAffinity:       string(svc.Spec.SessionAffinity),
		ExternalTrafficPolicy: string(svc.Spec.ExternalTrafficPolicy),
		Labels:                toKeyValues(svc.Labels),
		Annotations:           toKeyValues(svc.Annotations),
		Selector:              toKeyValues(svc.Spec.Selector),
		Ports:                 []ServicePortDetail{},
		Pods:                  []RelatedPod{},
		Workloads:             []RelatedWorkload{},
		Ingresses:             []RelatedIngress{},
	}
	if len(d.ClusterIPs) == 0 && svc.Spec.ClusterIP != "" {
		d.ClusterIPs = []string{svc.Spec.ClusterIP}
	}
	if svc.Spec.InternalTrafficPolicy != nil {
		d.InternalTrafficPolicy = string(*svc.Spec.InternalTrafficPolicy)
	}
	if svc.Spec.IPFamilyPolicy != nil {
		d.IPFamilyPolicy = string(*svc.Spec.IPFamilyPolicy)
	}
	for _, f := range svc.Spec.IPFamilies {
		d.IPFamilies = append(d.IPFamilies, string(f))
	}

	d.ExternalIPs = append(d.ExternalIPs, svc.Spec.ExternalIPs...)
	for _, lb := range svc.Status.LoadBalancer.Ingress {
		if lb.IP != "" {
			d.ExternalIPs = append(d.ExternalIPs, lb.IP)
		} else if lb.Hostname != "" {
			d.ExternalIPs = append(d.ExternalIPs, lb.Hostname)
		}
	}

	for _, p := range svc.Spec.Ports {
		d.Ports = append(d.Ports, ServicePortDetail{
			Name:       p.Name,
			Port:       p.Port,
			Protocol:   string(p.Protocol),
			TargetPort: p.TargetPort.String(),
			NodePort:   p.NodePort,
			AppProtocol: func() string {
				if p.AppProtocol != nil {
					return *p.AppProtocol
				}
				return ""
			}(),
		})
	}

	// Endpoints are the ground truth: a Service with a selector that matches
	// nothing looks perfectly healthy in its own spec.
	endpointIPs := map[string]bool{}
	if eps, err := cs.CoreV1().Endpoints(namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		for _, sub := range eps.Subsets {
			d.EndpointsReady += len(sub.Addresses)
			d.EndpointsNotReady += len(sub.NotReadyAddresses)
			for _, a := range sub.Addresses {
				endpointIPs[a.IP] = true
			}
		}
	} else if !strings.Contains(err.Error(), "not found") {
		d.EndpointsError = err.Error()
	}

	// Pods behind the Service, resolved through the selector rather than
	// through the endpoint list, so pods that exist but are not ready still
	// show up -- those are exactly the ones worth looking at.
	if len(svc.Spec.Selector) > 0 {
		sel := labels.SelectorFromSet(svc.Spec.Selector).String()
		pods, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: sel})
		if err == nil {
			// One ReplicaSet listing rolls pods up to the Deployment that owns
			// them, instead of showing the generated ReplicaSet names.
			rsOwner := map[string]RelatedWorkload{}
			if rsList, err := cs.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{}); err == nil {
				for i := range rsList.Items {
					rs := &rsList.Items[i]
					w := RelatedWorkload{Kind: "ReplicaSet", Name: rs.Name}
					if len(rs.OwnerReferences) > 0 {
						w = RelatedWorkload{Kind: rs.OwnerReferences[0].Kind, Name: rs.OwnerReferences[0].Name}
					}
					rsOwner[rs.Name] = w
				}
			}

			counts := map[string]*RelatedWorkload{}
			for i := range pods.Items {
				pod := &pods.Items[i]
				status, phase, ready, restarts := podHealth(pod)
				d.Pods = append(d.Pods, RelatedPod{
					Name: pod.Name, Status: status, Phase: phase, Ready: ready,
					Restarts: restarts, Node: pod.Spec.NodeName, IP: pod.Status.PodIP,
					Endpoint: endpointIPs[pod.Status.PodIP],
				})

				w := RelatedWorkload{Kind: "Pod", Name: pod.Name}
				if len(pod.OwnerReferences) > 0 {
					owner := pod.OwnerReferences[0]
					if owner.Kind == "ReplicaSet" {
						if resolved, ok := rsOwner[owner.Name]; ok {
							w = resolved
						} else {
							w = RelatedWorkload{Kind: owner.Kind, Name: owner.Name}
						}
					} else {
						w = RelatedWorkload{Kind: owner.Kind, Name: owner.Name}
					}
				}
				key := w.Kind + "/" + w.Name
				if existing, ok := counts[key]; ok {
					existing.Pods++
				} else {
					w.Pods = 1
					counts[key] = &w
				}
			}
			for _, w := range counts {
				d.Workloads = append(d.Workloads, *w)
			}
			sort.Slice(d.Workloads, func(i, j int) bool { return d.Workloads[i].Name < d.Workloads[j].Name })
			sort.Slice(d.Pods, func(i, j int) bool { return d.Pods[i].Name < d.Pods[j].Name })
		}
	}

	// Which Ingresses route to this Service -- the reverse of the lookup the
	// Ingresses page already does, answered from the Service's side.
	if ingList, err := cs.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{}); err == nil {
		for i := range ingList.Items {
			ing := &ingList.Items[i]
			hosts := map[string]bool{}
			paths := []string{}
			for _, rule := range ing.Spec.Rules {
				if rule.HTTP == nil {
					continue
				}
				for _, p := range rule.HTTP.Paths {
					if p.Backend.Service == nil || p.Backend.Service.Name != svc.Name {
						continue
					}
					if rule.Host != "" {
						hosts[rule.Host] = true
					}
					paths = append(paths, p.Path)
				}
			}
			if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil &&
				ing.Spec.DefaultBackend.Service.Name == svc.Name {
				paths = append(paths, "/ (default backend)")
			}
			if len(paths) == 0 {
				continue
			}
			hostList := make([]string, 0, len(hosts))
			for h := range hosts {
				hostList = append(hostList, h)
			}
			sort.Strings(hostList)
			d.Ingresses = append(d.Ingresses, RelatedIngress{Name: ing.Name, Hosts: hostList, Paths: paths})
		}
		sort.Slice(d.Ingresses, func(i, j int) bool { return d.Ingresses[i].Name < d.Ingresses[j].Name })
	}

	// The headline status: a selector matching no ready pod is the failure a
	// Service list cannot show, because the Service object itself is fine.
	switch {
	case svc.Spec.Type == corev1.ServiceTypeExternalName:
		d.Status, d.StatusText = "healthy", "ExternalName → "+svc.Spec.ExternalName
	case svc.Spec.Type == corev1.ServiceTypeLoadBalancer && len(d.ExternalIPs) == 0:
		d.Status, d.StatusText = "warning", "LoadBalancer pending"
	case len(svc.Spec.Selector) == 0:
		d.Status, d.StatusText = "unknown", "No selector (endpoints managed manually)"
	case d.EndpointsReady == 0:
		d.Status, d.StatusText = "critical", "No ready endpoints"
	case d.EndpointsNotReady > 0:
		d.Status, d.StatusText = "warning", fmt.Sprintf("%d ready, %d not ready", d.EndpointsReady, d.EndpointsNotReady)
	default:
		d.Status, d.StatusText = "healthy", fmt.Sprintf("%d ready endpoint%s", d.EndpointsReady, plural(d.EndpointsReady))
	}

	return d, nil
}

// countMetaOnly lists a resource asking the API server for metadata only. It
// exists for ConfigMaps and Secrets: a plain List would pull every value in the
// namespace across the wire just to produce a number on a card.
func countMetaOnly(ctx context.Context, cs *kubernetes.Clientset, namespace, resource string) (int, bool) {
	raw, err := cs.CoreV1().RESTClient().Get().
		Namespace(namespace).Resource(resource).
		SetHeader("Accept", "application/json;as=PartialObjectMetadataList;v=v1;g=meta.k8s.io").
		DoRaw(ctx)
	if err != nil {
		return 0, false
	}
	var resp struct {
		Items []struct{} `json:"items"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return 0, false
	}
	return len(resp.Items), true
}

func buildNamespaceDetail(ctx context.Context, cs *kubernetes.Clientset, name string) (*NamespaceDetail, error) {
	ns, err := cs.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	d := &NamespaceDetail{
		Name:        ns.Name,
		Phase:       string(ns.Status.Phase),
		Created:     ns.CreationTimestamp.UTC().Format("2006-01-02 15:04:05 UTC"),
		Age:         shortAge(ns.CreationTimestamp.Time),
		UID:         string(ns.UID),
		Labels:      toKeyValues(ns.Labels),
		Annotations: toKeyValues(ns.Annotations),
		Counts:      map[string]int{},
		Quotas:      []QuotaDetail{},
		LimitRanges: []LimitRangeEntry{},
		TopPods:     []TopPod{},
	}

	opts := metav1.ListOptions{}

	// Usage comes from metrics-server, requests and limits from the pod specs:
	// three different numbers that the Utilization view puts side by side,
	// because "using 300m" only means something against what was asked for.
	usageByPod := map[string]containerUsage{}
	if metrics := fetchPodMetrics(cs); len(metrics) > 0 {
		d.MetricsAvailable = true
		for key, containers := range metrics {
			podNS, podName, found := strings.Cut(key, "/")
			if !found || podNS != name {
				continue
			}
			agg := containerUsage{}
			for _, u := range containers {
				agg.CPUCores += u.CPUCores
				agg.MemBytes += u.MemBytes
			}
			usageByPod[podName] = agg
			d.CPU.Usage += agg.CPUCores
			d.Memory.Usage += agg.MemBytes
		}
	}

	if pods, err := cs.CoreV1().Pods(name).List(ctx, opts); err == nil {
		d.PodsTotal = len(pods.Items)
		for i := range pods.Items {
			pod := &pods.Items[i]
			switch pod.Status.Phase {
			case corev1.PodRunning:
				d.PodsRunning++
			case corev1.PodPending:
				d.PodsPending++
			case corev1.PodFailed:
				d.PodsFailed++
			case corev1.PodSucceeded:
				d.PodsSucceeded++
			}

			// Terminated pods still hold a spec but consume nothing, so they
			// would inflate the requests total against a usage of zero.
			counted := pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodPending
			for _, ctr := range pod.Spec.Containers {
				d.Containers++
				if !counted {
					continue
				}
				if q, ok := ctr.Resources.Requests[corev1.ResourceCPU]; ok {
					d.CPU.Requests += q.AsApproximateFloat64()
				}
				if q, ok := ctr.Resources.Limits[corev1.ResourceCPU]; ok {
					d.CPU.Limits += q.AsApproximateFloat64()
				}
				if q, ok := ctr.Resources.Requests[corev1.ResourceMemory]; ok {
					d.Memory.Requests += q.AsApproximateFloat64()
				}
				if q, ok := ctr.Resources.Limits[corev1.ResourceMemory]; ok {
					d.Memory.Limits += q.AsApproximateFloat64()
				}
			}

			if u, ok := usageByPod[pod.Name]; ok {
				d.TopPods = append(d.TopPods, TopPod{Name: pod.Name, CPUCores: u.CPUCores, MemBytes: u.MemBytes})
			}
		}
		d.Counts["pods"] = len(pods.Items)
	}

	// The heaviest few pods are what a namespace's total is actually made of.
	sort.Slice(d.TopPods, func(i, j int) bool { return d.TopPods[i].CPUCores > d.TopPods[j].CPUCores })
	if len(d.TopPods) > 5 {
		d.TopPods = d.TopPods[:5]
	}

	// Inventory. Each listing is best effort: a cluster without a CRD, or a
	// ServiceAccount without one rule, should lose a single number rather
	// than the whole panel.
	if l, err := cs.CoreV1().Services(name).List(ctx, opts); err == nil {
		d.Counts["services"] = len(l.Items)
	}
	if l, err := cs.AppsV1().Deployments(name).List(ctx, opts); err == nil {
		d.Counts["deployments"] = len(l.Items)
	}
	if l, err := cs.AppsV1().StatefulSets(name).List(ctx, opts); err == nil {
		d.Counts["statefulsets"] = len(l.Items)
	}
	if l, err := cs.AppsV1().DaemonSets(name).List(ctx, opts); err == nil {
		d.Counts["daemonsets"] = len(l.Items)
	}
	if l, err := cs.AppsV1().ReplicaSets(name).List(ctx, opts); err == nil {
		d.Counts["replicasets"] = len(l.Items)
	}
	if l, err := cs.NetworkingV1().Ingresses(name).List(ctx, opts); err == nil {
		d.Counts["ingresses"] = len(l.Items)
	}
	if l, err := cs.CoreV1().PersistentVolumeClaims(name).List(ctx, opts); err == nil {
		d.Counts["persistentvolumeclaims"] = len(l.Items)
	}
	if n, ok := countMetaOnly(ctx, cs, name, "configmaps"); ok {
		d.Counts["configmaps"] = n
	}
	if n, ok := countMetaOnly(ctx, cs, name, "secrets"); ok {
		d.Counts["secrets"] = n
	}
	if l, err := cs.BatchV1().CronJobs(name).List(ctx, opts); err == nil {
		d.Counts["cronjobs"] = len(l.Items)
	}
	if l, err := cs.BatchV1().Jobs(name).List(ctx, opts); err == nil {
		d.Counts["jobs"] = len(l.Items)
	}

	// A quota is the hard ceiling the namespace is measured against; without
	// it the utilization numbers have no upper bound to compare to.
	if quotas, err := cs.CoreV1().ResourceQuotas(name).List(ctx, opts); err == nil {
		for i := range quotas.Items {
			q := &quotas.Items[i]
			entry := QuotaDetail{Name: q.Name, Entries: []QuotaEntry{}}
			names := make([]string, 0, len(q.Status.Hard))
			for res := range q.Status.Hard {
				names = append(names, string(res))
			}
			sort.Strings(names)
			for _, res := range names {
				hard := q.Status.Hard[corev1.ResourceName(res)]
				used := "0"
				if u, ok := q.Status.Used[corev1.ResourceName(res)]; ok {
					used = u.String()
				}
				entry.Entries = append(entry.Entries, QuotaEntry{Resource: res, Used: used, Hard: hard.String()})
			}
			d.Quotas = append(d.Quotas, entry)
		}
	}

	if lrs, err := cs.CoreV1().LimitRanges(name).List(ctx, opts); err == nil {
		for i := range lrs.Items {
			lr := &lrs.Items[i]
			for _, item := range lr.Spec.Limits {
				resources := map[string]bool{}
				for _, set := range []corev1.ResourceList{item.Min, item.Max, item.Default, item.DefaultRequest} {
					for res := range set {
						resources[string(res)] = true
					}
				}
				names := make([]string, 0, len(resources))
				for res := range resources {
					names = append(names, res)
				}
				sort.Strings(names)
				for _, res := range names {
					key := corev1.ResourceName(res)
					val := func(list corev1.ResourceList) string {
						if q, ok := list[key]; ok {
							return q.String()
						}
						return ""
					}
					d.LimitRanges = append(d.LimitRanges, LimitRangeEntry{
						Name: lr.Name, Type: string(item.Type), Resource: res,
						Min: val(item.Min), Max: val(item.Max),
						Default: val(item.Default), Request: val(item.DefaultRequest),
					})
				}
			}
		}
	}

	return d, nil
}
