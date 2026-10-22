package handlers

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

// GetClusterChanges answers "what changed" for the overview: rollouts, pods
// that started failing, and workloads that lost or regained their replicas,
// in one time-ordered list. Each kind already has a page of its own; what
// none of them shows is the order -- that the pods began failing two minutes
// after a rollout is the whole diagnosis, and it only appears when the two
// sit on one line.
//
// Everything is read from tables the pollers keep. No cluster call: the
// overview polls this, and the cluster has better things to do.

type changeEvent struct {
	At        time.Time `json:"at"`
	Kind      string    `json:"kind"` // rollout | problem | workload
	Tone      string    `json:"tone"` // red | gold | green | muted
	Text      string    `json:"text"`
	Sub       string    `json:"sub"`
	Namespace string    `json:"namespace,omitempty"`
	// Failing asks the overview to highlight failing pods in Namespace.
	Failing bool `json:"failing,omitempty"`
	// Count is how many pods a problem line covers.
	Count int `json:"count,omitempty"`
	// Workload and image, for a rollout the reader may want to compare.
	Workload string `json:"workload,omitempty"`
	Image    string `json:"image,omitempty"`
}

// problemPhrase turns a problem kind into the sentence the list reads as.
var problemPhrase = map[string]string{
	"crashloop":         "entered CrashLoopBackOff",
	"oom_killed":        "were OOMKilled",
	"image_pull_failed": "can't pull their image",
	"config_error":      "have a container config error",
	"unschedulable":     "can't be scheduled",
	"evicted":           "were evicted",
	"mem_pressure":      "are near their memory limit",
	"cpu_throttling":    "are CPU-throttled",
	"cpu_saturation":    "are saturating their CPU",
}

// displayTag is what a reader calls a version: the tag, or a short digest
// for an image pinned by one.
func displayTag(image string) string {
	if t := imageTag(image); t != "" {
		return t
	}
	if i := strings.Index(image, "@sha256:"); i >= 0 && len(image) >= i+8+7 {
		return image[i+8 : i+8+7]
	}
	return "latest"
}

func GetClusterChanges(c *fiber.Ctx) error {
	clusterID, err := requestClusterID(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	hours := c.QueryInt("hours", 6)
	if hours < 1 || hours > 72 {
		hours = 6
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	allowed, restricted, err := requestNamespaces(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	events := buildClusterChanges(clusterID, since, allowed, restricted)
	return c.JSON(fiber.Map{"hours": hours, "events": events})
}

func buildClusterChanges(clusterID uint, since time.Time, allowed []string, restricted bool) []changeEvent {
	events := []changeEvent{}

	// Rollouts.
	var deps []models.Deployment
	dq := db.DB.Where("cluster_id = ? AND deployed_at >= ?", clusterID, since)
	if restricted {
		dq = dq.Where("namespace IN ?", allowed)
	}
	dq.Order("deployed_at desc").Limit(50).Find(&deps)
	for _, d := range deps {
		e := changeEvent{
			At: d.DeployedAt, Kind: "rollout", Tone: "gold", Namespace: d.Namespace,
			Workload: d.Workload, Image: d.Image,
			Text: fmt.Sprintf("%s %s rolled out", d.Workload, displayTag(d.Image)),
		}
		var sub []string
		sub = append(sub, d.Namespace)
		if d.Rollback {
			e.Text = fmt.Sprintf("%s rolled back to %s", d.Workload, displayTag(d.Image))
		}
		if d.CommitSHA != "" {
			sha := d.CommitSHA
			if len(sha) > 7 {
				sha = sha[:7]
			}
			sub = append(sub, "commit "+sha)
		}
		if d.PrevImage != "" {
			sub = append(sub, "was "+displayTag(d.PrevImage))
		}
		switch d.Outcome {
		case "failed":
			e.Tone = "red"
			if d.FailedReason != "" {
				sub = append(sub, "failed: "+d.FailedReason)
			}
		case "ok":
			e.Tone = "green"
			sub = append(sub, "settled healthy")
		}
		e.Sub = strings.Join(sub, " · ")
		events = append(events, e)
	}

	// Pods that started failing, grouped: forty pods in CrashLoopBackOff
	// within the same half hour are one event, not forty lines.
	var probs []models.PodProblem
	pq := db.DB.Where("cluster_id = ? AND opened_at >= ? AND severity IN ?", clusterID, since, []string{"critical", "warning"})
	if restricted {
		pq = pq.Where("namespace IN ?", allowed)
	}
	pq.Order("opened_at asc").Limit(5000).Find(&probs)
	type group struct {
		kind, title, severity string
		first                 time.Time
		pods                  map[string]bool
		byNS                  map[string]int
		open                  int
	}
	groups := map[string]*group{}
	var order []string
	for _, p := range probs {
		bucket := p.OpenedAt.Truncate(30 * time.Minute)
		key := p.Kind + "|" + bucket.Format(time.RFC3339)
		g, ok := groups[key]
		if !ok {
			g = &group{kind: p.Kind, title: p.Title, severity: p.Severity, first: p.OpenedAt, pods: map[string]bool{}, byNS: map[string]int{}}
			groups[key] = g
			order = append(order, key)
		}
		id := p.Namespace + "/" + p.PodName
		if g.pods[id] {
			continue
		}
		g.pods[id] = true
		g.byNS[p.Namespace]++
		if p.ClosedAt == nil {
			g.open++
		}
		if p.Severity == "critical" {
			g.severity = "critical"
		}
	}
	for _, key := range order {
		g := groups[key]
		n := len(g.pods)
		phrase := problemPhrase[g.kind]
		if phrase == "" {
			phrase = "report " + g.title
		}
		noun := "pods"
		if n == 1 {
			noun = "pod"
			phrase = strings.Replace(strings.Replace(phrase, "were ", "was ", 1), "are ", "is ", 1)
			phrase = strings.Replace(strings.Replace(phrase, "can't pull their", "can't pull its", 1), "have a", "has a", 1)
			phrase = strings.Replace(strings.Replace(phrase, "their memory", "its memory", 1), "their CPU", "its CPU", 1)
		}
		type nsCount struct {
			ns string
			n  int
		}
		var ns []nsCount
		for k, v := range g.byNS {
			ns = append(ns, nsCount{k, v})
		}
		sort.Slice(ns, func(i, j int) bool { return ns[i].n > ns[j].n || (ns[i].n == ns[j].n && ns[i].ns < ns[j].ns) })
		parts := []string{}
		for i, x := range ns {
			if i == 4 {
				parts = append(parts, fmt.Sprintf("+%d more", len(ns)-4))
				break
			}
			parts = append(parts, fmt.Sprintf("%s %d", x.ns, x.n))
		}
		sub := strings.Join(parts, " · ")
		switch {
		case g.open == 0:
			sub += ". All recovered since."
		case g.open < n:
			sub += fmt.Sprintf(". %d still failing.", g.open)
		}
		tone := "red"
		if g.severity != "critical" {
			tone = "gold"
		}
		if g.open == 0 {
			tone = "muted"
		}
		e := changeEvent{
			At: g.first, Kind: "problem", Tone: tone,
			Text: fmt.Sprintf("%d %s %s", n, noun, phrase), Sub: sub,
			Failing: g.open > 0, Count: n,
		}
		if len(ns) == 1 {
			e.Namespace = ns[0].ns
		}
		events = append(events, e)
	}

	// Workloads that lost all their replicas, or got them back. Progressing
	// is the normal middle of a rollout and would only repeat the rollouts.
	var wev []models.WorkloadEvent
	wq := db.DB.Where("cluster_id = ? AND recorded_at >= ? AND event_type = ?", clusterID, since, "status_change")
	if restricted {
		wq = wq.Where("namespace IN ?", allowed)
	}
	wq.Order("recorded_at desc").Limit(100).Find(&wev)
	for _, w := range wev {
		var e changeEvent
		switch {
		case w.NewValue == "degraded":
			e = changeEvent{Tone: "red", Text: fmt.Sprintf("%s has no ready replicas", w.Name)}
		case w.NewValue == "healthy" && w.OldValue == "degraded":
			e = changeEvent{Tone: "green", Text: fmt.Sprintf("%s is serving again", w.Name)}
		default:
			continue
		}
		e.At, e.Kind, e.Namespace, e.Workload = w.RecordedAt, "workload", w.Namespace, w.Name
		e.Sub = fmt.Sprintf("%s · %s", w.Namespace, strings.ToLower(w.Kind))
		events = append(events, e)
	}

	sort.SliceStable(events, func(i, j int) bool { return events[i].At.After(events[j].At) })
	if len(events) > 40 {
		events = events[:40]
	}
	return events
}
