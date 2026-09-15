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

// What a pod is *allowed* to do is written in its spec, and almost nobody
// reads it. A container running as root with the host's PID namespace and a
// hostPath mount of / is one YAML away from being the node, and nothing in a
// health check notices, because the pod is perfectly Ready the whole time.
//
// Everything here is read from the spec. That is a deliberate boundary: it is
// complete, it costs one list call, and it is true before anything bad
// happens. Catching a container that actually ran wget at 3am is a different
// problem needing eBPF or an audit webhook, and pretending a spec scan does
// that would be worse than not offering it.

type PodSecurityFinding struct {
	Kind      string `json:"kind"`
	Severity  string `json:"severity"` // critical | warning | info
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Container string `json:"container,omitempty"`
}

type PodSecurityRow struct {
	Namespace string               `json:"namespace"`
	Pod       string               `json:"pod"`
	Workload  string               `json:"workload"`
	Node      string               `json:"node"`
	Findings  []PodSecurityFinding `json:"findings"`
	Worst     string               `json:"worst"`
}

// dangerousCapabilities are the ones that hand over the node in one step.
// NET_RAW is deliberately absent: it is on by default almost everywhere, and a
// finding that fires on every pod trains people to ignore the whole page.
var dangerousCapabilities = map[corev1.Capability]string{
	"SYS_ADMIN":       "effectively root on the node",
	"SYS_PTRACE":      "can read the memory of other processes, including their secrets",
	"SYS_MODULE":      "can load kernel modules",
	"NET_ADMIN":       "can reconfigure the node's networking",
	"DAC_READ_SEARCH": "can bypass file permission checks",
	"SYS_BOOT":        "can reboot the node",
}

// sensitiveHostPaths are mounts that hand over the node or the cluster.
var sensitiveHostPaths = map[string]string{
	"/":                    "the entire node filesystem",
	"/etc":                 "the node's configuration, including kubelet credentials",
	"/var/run/docker.sock": "the container runtime — equivalent to root on the node",
	"/var/run/containerd":  "the container runtime — equivalent to root on the node",
	"/var/run/crio":        "the container runtime — equivalent to root on the node",
	"/var/lib/kubelet":     "kubelet state, including other pods' service account tokens",
	"/proc":                "every process on the node",
	"/root":                "the node's root home directory",
	"/var/run/secrets":     "mounted secrets of other workloads",
}

// downloadTools are the binaries whose presence in a command line means the
// container fetches something at start-up. That is not an attack by itself,
// and saying so matters: it is an image that is not self-contained, which is a
// supply-chain surface and a reason a pod behaves differently on each restart.
var downloadTools = []string{"wget", "curl", "nc ", "netcat", "apt-get install", "apk add", "pip install", "npm install"}

func worstOf(findings []PodSecurityFinding) string {
	worst := "info"
	for _, f := range findings {
		if f.Severity == "critical" {
			return "critical"
		}
		if f.Severity == "warning" {
			worst = "warning"
		}
	}
	if len(findings) == 0 {
		return "healthy"
	}
	return worst
}

// inspectPodSecurity reads one pod's spec. Pure, so it can be tested against
// fixtures rather than against a cluster.
func inspectPodSecurity(pod *corev1.Pod) []PodSecurityFinding {
	out := []PodSecurityFinding{}
	add := func(kind, sev, title, detail, container string) {
		out = append(out, PodSecurityFinding{
			Kind: kind, Severity: sev, Title: title, Detail: detail, Container: container,
		})
	}

	spec := &pod.Spec

	// ---- pod level ---------------------------------------------------------

	if spec.HostNetwork {
		add("host_network", "critical", "Uses the host network",
			"The pod shares the node's network namespace, so it can reach anything the node can and bind to its ports, bypassing NetworkPolicy entirely.", "")
	}
	if spec.HostPID {
		add("host_pid", "critical", "Uses the host PID namespace",
			"The pod sees and can signal every process on the node, including other workloads' containers.", "")
	}
	if spec.HostIPC {
		add("host_ipc", "critical", "Uses the host IPC namespace",
			"The pod shares shared-memory segments with the node and with every other workload using them.", "")
	}

	for _, vol := range spec.Volumes {
		if vol.HostPath == nil {
			continue
		}
		path := vol.HostPath.Path
		if why, sensitive := sensitiveHostPaths[path]; sensitive {
			add("host_path", "critical", "Mounts a sensitive host path",
				fmt.Sprintf("Volume %q mounts %s from the node — %s.", vol.Name, path, why), "")
		} else {
			add("host_path", "warning", "Mounts a host path",
				fmt.Sprintf("Volume %q mounts %s from the node. Anything written there outlives the pod and is visible to the node.", vol.Name, path), "")
		}
	}

	// A token is mounted by default whether or not anything uses it, and a
	// container that never calls the API server is one compromise away from
	// having credentials it never needed.
	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		add("token_mounted", "info", "Service account token is mounted",
			"The API token is mounted even if nothing in the pod talks to Kubernetes. Set automountServiceAccountToken: false when it is not used.", "")
	}

	// ---- container level ---------------------------------------------------

	containers := append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...)
	for i := range containers {
		ctr := &containers[i]
		sc := ctr.SecurityContext

		runAsRoot := true
		if sc != nil && sc.RunAsUser != nil && *sc.RunAsUser != 0 {
			runAsRoot = false
		} else if sc != nil && sc.RunAsNonRoot != nil && *sc.RunAsNonRoot {
			runAsRoot = false
		} else if spec.SecurityContext != nil {
			if spec.SecurityContext.RunAsUser != nil && *spec.SecurityContext.RunAsUser != 0 {
				runAsRoot = false
			} else if spec.SecurityContext.RunAsNonRoot != nil && *spec.SecurityContext.RunAsNonRoot {
				runAsRoot = false
			}
		}

		if sc != nil && sc.Privileged != nil && *sc.Privileged {
			add("privileged", "critical", "Runs privileged",
				"A privileged container has every capability and can access every device. It is root on the node with extra steps.", ctr.Name)
		} else if runAsRoot {
			// Not critical on its own: plenty of images still run as root and
			// are contained by everything else. It is the multiplier that
			// makes every other finding on this pod worse.
			add("run_as_root", "warning", "Runs as root",
				"No runAsUser or runAsNonRoot is set, so the container runs as uid 0. On its own this is contained; combined with a host mount or an added capability it is not.", ctr.Name)
		}

		if sc != nil && sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
			add("privilege_escalation", "warning", "Allows privilege escalation",
				"A process in this container can gain more privileges than its parent, which defeats dropping to a non-root user.", ctr.Name)
		}

		if sc != nil && sc.Capabilities != nil {
			for _, capability := range sc.Capabilities.Add {
				if why, dangerous := dangerousCapabilities[capability]; dangerous {
					add("capability", "critical", "Adds a dangerous capability",
						fmt.Sprintf("%s is added — %s.", capability, why), ctr.Name)
				}
			}
		}

		if sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
			add("writable_root", "info", "Root filesystem is writable",
				"Anything that gets execution can write to the image's filesystem and persist for the life of the container.", ctr.Name)
		}

		// A moving tag means the image running now is not the image that was
		// reviewed, and nobody can say which one it is after the fact.
		if strings.HasSuffix(ctr.Image, ":latest") || !strings.Contains(ctr.Image, ":") {
			add("mutable_tag", "warning", "Image has no fixed tag",
				fmt.Sprintf("%s resolves to whatever that tag points at today, so the image that was scanned and the image that is running can differ.", ctr.Image), ctr.Name)
		}

		joined := strings.ToLower(strings.Join(append(append([]string{}, ctr.Command...), ctr.Args...), " "))
		for _, tool := range downloadTools {
			if strings.Contains(joined, tool) {
				add("fetches_at_start", "warning", "Fetches something at start-up",
					fmt.Sprintf("The command line runs %q, so the container pulls content at run time rather than shipping it in the image. What runs then depends on whatever that endpoint served.", strings.TrimSpace(tool)), ctr.Name)
				break
			}
		}

		// Environment variables end up in crash dumps, in `kubectl describe`,
		// and in any log line that prints the environment.
		for _, env := range ctr.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				add("secret_in_env", "info", "Secret is passed as an environment variable",
					fmt.Sprintf("%s comes from a Secret. Environment variables appear in kubectl describe and in crash dumps, and cannot be rotated without restarting the pod.", env.Name), ctr.Name)
				break
			}
		}
	}

	return out
}

// GetPodSecurity reports what every pod in scope is permitted to do.
func GetPodSecurity(c *fiber.Ctx) error {
	typed, err := requestTyped(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "cannot connect to cluster: " + err.Error()})
	}

	allowed, restricted, err := requestNamespaces(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	permitted := map[string]bool{}
	for _, ns := range allowed {
		permitted[ns] = true
	}

	list, err := typed.CoreV1().Pods(c.Query("namespace")).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return k8sError(c, err)
	}

	rows := []PodSecurityRow{}
	totals := map[string]int{"critical": 0, "warning": 0, "info": 0, "healthy": 0}
	byKind := map[string]*PodSecurityFinding{}
	kindCount := map[string]int{}

	for i := range list.Items {
		pod := &list.Items[i]
		if restricted && !permitted[pod.Namespace] {
			continue
		}

		findings := inspectPodSecurity(pod)
		worst := worstOf(findings)
		totals[worst]++

		for j := range findings {
			f := &findings[j]
			kindCount[f.Kind]++
			if _, seen := byKind[f.Kind]; !seen {
				byKind[f.Kind] = f
			}
		}

		if len(findings) == 0 {
			continue
		}
		workload := ""
		if len(pod.OwnerReferences) > 0 {
			workload = pod.OwnerReferences[0].Name
		}
		rows = append(rows, PodSecurityRow{
			Namespace: pod.Namespace, Pod: pod.Name, Workload: workload,
			Node: pod.Spec.NodeName, Findings: findings, Worst: worst,
		})
	}

	rank := map[string]int{"critical": 0, "warning": 1, "info": 2, "healthy": 3}
	sort.SliceStable(rows, func(i, j int) bool {
		if rank[rows[i].Worst] != rank[rows[j].Worst] {
			return rank[rows[i].Worst] < rank[rows[j].Worst]
		}
		if len(rows[i].Findings) != len(rows[j].Findings) {
			return len(rows[i].Findings) > len(rows[j].Findings)
		}
		return rows[i].Namespace+rows[i].Pod < rows[j].Namespace+rows[j].Pod
	})

	// Grouped by kind as well: "forty pods run as root" is one decision to
	// make, where forty rows are forty things to read.
	summary := make([]fiber.Map, 0, len(byKind))
	for kind, f := range byKind {
		summary = append(summary, fiber.Map{
			"kind": kind, "severity": f.Severity, "title": f.Title, "pods": kindCount[kind],
		})
	}
	sort.Slice(summary, func(i, j int) bool {
		si := rank[summary[i]["severity"].(string)]
		sj := rank[summary[j]["severity"].(string)]
		if si != sj {
			return si < sj
		}
		return summary[i]["pods"].(int) > summary[j]["pods"].(int)
	})

	return c.JSON(fiber.Map{
		"pods": rows, "totals": totals, "summary": summary,
		"scanned": len(list.Items),
	})
}
