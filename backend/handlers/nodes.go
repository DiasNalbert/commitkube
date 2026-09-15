package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type NodeInfo struct {
	Name          string          `json:"name"`
	Status        string          `json:"status"`
	Roles         []string        `json:"roles"`
	Age           string          `json:"age"`
	Version       string          `json:"version"`
	OS            string          `json:"os"`
	Arch          string          `json:"arch"`
	CPUCapCores   float64         `json:"cpu_cap_cores"`
	CPUUsageCores float64         `json:"cpu_usage_cores"`
	CPUPct        float64         `json:"cpu_pct"`
	MemCapGB      float64         `json:"mem_cap_gb"`
	MemUsageGB    float64         `json:"mem_usage_gb"`
	MemPct        float64         `json:"mem_pct"`
	DiskCapGB     float64         `json:"disk_cap_gb"`
	MetricsAvail  bool            `json:"metrics_available"`
	Conditions    []NodeCondition `json:"conditions"`
}

type NodeCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type nodeUsage struct {
	CPUUsageCores float64
	MemUsageBytes float64
}

var (
	nodeAlertMu    sync.Mutex
	nodeAlertState = map[string]string{}
)

// buildK8sClient is the typed-only variant of buildK8sClients, with the same
// caveat: it resolves the default cluster, so it belongs to pollers and to
// code that genuinely has no request in hand.
func buildK8sClient() (*kubernetes.Clientset, error) {
	cl, err := defaultCluster()
	if err != nil {
		return nil, err
	}
	typed, _, err := clientsFor(cl)
	return typed, err
}

func fetchNodeMetrics(clientset *kubernetes.Clientset) map[string]nodeUsage {
	result := map[string]nodeUsage{}

	raw, err := clientset.RESTClient().Get().
		AbsPath("/apis/metrics.k8s.io/v1beta1/nodes").
		DoRaw(context.Background())
	if err != nil {
		return result
	}

	var resp struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Usage struct {
				CPU    string `json:"cpu"`
				Memory string `json:"memory"`
			} `json:"usage"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return result
	}

	for _, item := range resp.Items {
		u := nodeUsage{}
		if q, err := resource.ParseQuantity(item.Usage.CPU); err == nil {
			u.CPUUsageCores = q.AsApproximateFloat64()
		}
		if q, err := resource.ParseQuantity(item.Usage.Memory); err == nil {
			u.MemUsageBytes = q.AsApproximateFloat64()
		}
		result[item.Metadata.Name] = u
	}
	return result
}

func GetNodeStatus(c *fiber.Ctx) error {
	clientset, err := requestTyped(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	nodeList, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": fmt.Sprintf("failed to list nodes: %v", err),
		})
	}

	metricsMap := fetchNodeMetrics(clientset)
	metricsAvail := len(metricsMap) > 0

	nodes := make([]NodeInfo, 0, len(nodeList.Items))
	for _, item := range nodeList.Items {
		var roles []string
		for label := range item.Labels {
			if strings.HasPrefix(label, "node-role.kubernetes.io/") {
				roles = append(roles, strings.TrimPrefix(label, "node-role.kubernetes.io/"))
			}
		}
		if r, ok := item.Labels["kubernetes.io/role"]; ok && r != "" {
			roles = append(roles, r)
		}
		if len(roles) == 0 {
			roles = []string{"<none>"}
		}

		dur := time.Since(item.CreationTimestamp.Time)
		days := int(dur.Hours()) / 24
		hours := int(dur.Hours()) % 24
		age := strconv.Itoa(days) + "d" + strconv.Itoa(hours) + "h"
		if days == 0 {
			age = strconv.Itoa(hours) + "h"
		}

		nodeStatus := "NotReady"
		var conditions []NodeCondition
		for _, cond := range item.Status.Conditions {
			// Only show relevant conditions
			if string(cond.Type) == "Ready" || cond.Status == "True" {
				conditions = append(conditions, NodeCondition{
					Type:    string(cond.Type),
					Status:  string(cond.Status),
					Message: cond.Message,
				})
			}
			if cond.Type == "Ready" && cond.Status == "True" {
				nodeStatus = "Ready"
			}
		}

		capCPU := item.Status.Capacity.Cpu().AsApproximateFloat64()
		capMemBytes := item.Status.Capacity.Memory().AsApproximateFloat64()
		capMemGB := capMemBytes / 1e9

		diskCapGB := 0.0
		if q, ok := item.Status.Capacity["ephemeral-storage"]; ok {
			diskCapGB = q.AsApproximateFloat64() / 1e9
		}

		info := NodeInfo{
			Name:         item.Name,
			Status:       nodeStatus,
			Roles:        roles,
			Age:          age,
			Version:      item.Status.NodeInfo.KubeletVersion,
			OS:           item.Status.NodeInfo.OperatingSystem,
			Arch:         item.Status.NodeInfo.Architecture,
			CPUCapCores:  capCPU,
			MemCapGB:     capMemGB,
			DiskCapGB:    diskCapGB,
			MetricsAvail: metricsAvail,
			Conditions:   conditions,
		}

		if m, ok := metricsMap[item.Name]; ok {
			info.CPUUsageCores = m.CPUUsageCores
			info.MemUsageGB = m.MemUsageBytes / 1e9
			if capCPU > 0 {
				info.CPUPct = m.CPUUsageCores / capCPU * 100
			}
			if capMemBytes > 0 {
				info.MemPct = m.MemUsageBytes / capMemBytes * 100
			}
		}

		nodes = append(nodes, info)
	}

	return c.JSON(fiber.Map{"nodes": nodes, "metrics_available": metricsAvail})
}

// PollNodeAlerts checks node health and resource usage, sending notifications when thresholds are exceeded.
func PollNodeAlerts() {
	clientset, err := buildK8sClient()
	if err != nil {
		return
	}

	nodeList, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return
	}

	metricsMap := fetchNodeMetrics(clientset)

	nodeAlertMu.Lock()
	defer nodeAlertMu.Unlock()

	for _, node := range nodeList.Items {
		name := node.Name

		ready := false
		for _, cond := range node.Status.Conditions {
			if cond.Type == "Ready" && cond.Status == "True" {
				ready = true
			}
		}

		prevStatus := nodeAlertState[name+"_status"]
		if !ready && prevStatus != "down" {
			nodeAlertState[name+"_status"] = "down"
			go SendNotifications("node.down", "Node Down",
				fmt.Sprintf("Node %s is not ready / unreachable", name),
				name, "system")
		} else if ready {
			nodeAlertState[name+"_status"] = "ready"
		}

		m, hasMetrics := metricsMap[name]
		if !hasMetrics {
			continue
		}

		capCPU := node.Status.Capacity.Cpu().AsApproximateFloat64()
		capMem := node.Status.Capacity.Memory().AsApproximateFloat64()

		if capCPU > 0 {
			cpuPct := m.CPUUsageCores / capCPU * 100
			prev := nodeAlertState[name+"_cpu"]
			if cpuPct > 80 && prev != "high" {
				nodeAlertState[name+"_cpu"] = "high"
				go SendNotifications("node.high_cpu", "High CPU Usage",
					fmt.Sprintf("Node %s CPU at %.1f%% (%.2f / %.0f cores)", name, cpuPct, m.CPUUsageCores, capCPU),
					name, "system")
			} else if cpuPct <= 70 {
				nodeAlertState[name+"_cpu"] = "ok"
			}
		}

		if capMem > 0 {
			memPct := m.MemUsageBytes / capMem * 100
			prev := nodeAlertState[name+"_mem"]
			if memPct > 85 && prev != "high" {
				nodeAlertState[name+"_mem"] = "high"
				go SendNotifications("node.high_memory", "High Memory Usage",
					fmt.Sprintf("Node %s memory at %.1f%% (%.1f GB / %.1f GB)", name, memPct, m.MemUsageBytes/1e9, capMem/1e9),
					name, "system")
			} else if memPct <= 75 {
				nodeAlertState[name+"_mem"] = "ok"
			}
		}
	}
}

// NodePodUsage is one pod's resource consumption on a node, with its share of
// that node's capacity -- the number that answers "what is eating this node".
type NodePodUsage struct {
	Name         string  `json:"name"`
	Namespace    string  `json:"namespace"`
	Workload     string  `json:"workload"`
	Phase        string  `json:"phase"`
	RestartCount int     `json:"restart_count"`
	CPUCores     float64 `json:"cpu_cores"`
	CPULimits    float64 `json:"cpu_limits"`
	CPUNodePct   float64 `json:"cpu_node_pct"`
	MemBytes     int64   `json:"mem_bytes"`
	MemLimits    int64   `json:"mem_limits"`
	MemNodePct   float64 `json:"mem_node_pct"`
	ProblemCount int     `json:"problem_count"`
	WorstProblem string  `json:"worst_problem"`
}

// GetNodePods returns the pods scheduled on one node, ranked by CPU and by
// memory. Both rankings come back in a single response so the UI can switch
// between them without another metrics scrape.
func GetNodePods(c *fiber.Ctx) error {
	nodeName := c.Query("node")
	if nodeName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "node is required"})
	}
	limit := c.QueryInt("limit", 10)
	if limit < 1 || limit > 100 {
		limit = 10
	}

	clientset, err := requestTyped(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	node, err := clientset.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": fmt.Sprintf("failed to read node %s: %v", nodeName, err),
		})
	}
	capCPU := node.Status.Capacity.Cpu().AsApproximateFloat64()
	capMem := node.Status.Capacity.Memory().AsApproximateFloat64()

	// Throttling is not scraped here: this view ranks consumption, and the
	// cadvisor scrape belongs to the poller.
	clusterID, err := requestClusterID(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	pods, metricsAvail, err := collectPods(clientset, clusterID, "", false)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	pods = keepScopedPods(c, pods)

	usage := []NodePodUsage{}
	var sumCPU float64
	var sumMem int64

	for _, p := range pods {
		if p.NodeName != nodeName {
			continue
		}

		worst := ""
		for _, pr := range p.Problems {
			if pr.Severity == "critical" {
				worst = pr.Title
				break
			}
			if pr.Severity == "warning" && worst == "" {
				worst = pr.Title
			}
		}

		u := NodePodUsage{
			Name: p.Name, Namespace: p.Namespace, Workload: p.Workload,
			Phase: p.Phase, RestartCount: p.RestartCount,
			CPUCores: p.CPUCores, CPULimits: p.CPULimits,
			MemBytes: p.MemBytes, MemLimits: p.MemLimits,
			ProblemCount: len(p.Problems), WorstProblem: worst,
		}
		if capCPU > 0 {
			u.CPUNodePct = p.CPUCores / capCPU * 100
		}
		if capMem > 0 {
			u.MemNodePct = float64(p.MemBytes) / capMem * 100
		}

		sumCPU += p.CPUCores
		sumMem += p.MemBytes
		usage = append(usage, u)
	}

	byCPU := make([]NodePodUsage, len(usage))
	copy(byCPU, usage)
	sort.SliceStable(byCPU, func(i, j int) bool { return byCPU[i].CPUCores > byCPU[j].CPUCores })

	byMem := make([]NodePodUsage, len(usage))
	copy(byMem, usage)
	sort.SliceStable(byMem, func(i, j int) bool { return byMem[i].MemBytes > byMem[j].MemBytes })

	if len(byCPU) > limit {
		byCPU = byCPU[:limit]
	}
	if len(byMem) > limit {
		byMem = byMem[:limit]
	}

	return c.JSON(fiber.Map{
		"node":              nodeName,
		"pod_count":         len(usage),
		"metrics_available": metricsAvail,
		"top_cpu":           byCPU,
		"top_memory":        byMem,
		// The sums are what the pods actually use, which is normally below the
		// node total: kubelet, container runtime and system daemons are not pods.
		"pods_cpu_cores": sumCPU,
		"pods_mem_bytes": sumMem,
		"node_cpu_cores": capCPU,
		"node_mem_bytes": capMem,
	})
}
