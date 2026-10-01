package handlers

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

// The DORA module measures delivery from the cluster's side. A deployment is
// an image that started running (models.Deployment, written by PollWorkloads),
// not a pipeline that reported success.
//
// Three of the four metrics need no collection at all: deployment frequency is
// a count of those rows, change failure rate reads the problem lifecycle that
// already exists, and recovery time reads when those problems closed. Only
// lead time needs something new -- the link from a running image back to the
// commit that produced it, which is what resolveDeploymentLinks does.

// repoNameFromImage returns the repository an image was built from, which is
// taken to be the last path segment before the tag: registry:5000/org/api:v2
// is "api". Matching that against a Repository row is a guess, and a guess
// that fails leaves the deployment unlinked rather than attached to the wrong
// repository.
func repoNameFromImage(image string) string {
	ref := image
	if at := strings.Index(ref, "@"); at >= 0 { // digest form: name@sha256:...
		ref = ref[:at]
	}
	slash := strings.LastIndex(ref, "/")
	// A colon before the last slash is a registry port, not a tag.
	if colon := strings.LastIndex(ref, ":"); colon > slash {
		ref = ref[:colon]
	}
	if slash = strings.LastIndex(ref, "/"); slash >= 0 {
		ref = ref[slash+1:]
	}
	return ref
}

// imageTag returns the tag part of an image reference, empty when it carries
// none or is pinned by digest.
func imageTag(image string) string {
	ref := image
	if at := strings.Index(ref, "@"); at >= 0 {
		return ""
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon <= slash {
		return ""
	}
	return ref[colon+1:]
}

// commitSHAFromImage pulls a commit hash out of an image tag. The conventions
// in the wild are api:abc1234, api:main-abc1234, api:1.4.2-abc1234 and
// api:abc1234-20260101, so the rule is to split the tag on the usual
// separators and take the longest part that looks like a hash.
//
// "Looks like a hash" deliberately requires at least one letter a-f. A seven
// digit build number is valid hexadecimal and is not a commit, and a lead time
// computed against a commit that does not exist is worse than no lead time: it
// is a number someone will act on.
func commitSHAFromImage(image string) string {
	tag := imageTag(image)
	if tag == "" {
		return ""
	}
	best := ""
	for _, part := range strings.FieldsFunc(tag, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == '+'
	}) {
		p := strings.ToLower(part)
		// A tag like "sha-abc1234" or "g1a2b3c4" prefixes the hash; strip a
		// leading marker so the hash itself is what gets measured.
		p = strings.TrimPrefix(p, "sha")
		if len(p) < 7 || len(p) > 40 {
			continue
		}
		hex, letter := true, false
		for _, r := range p {
			switch {
			case r >= '0' && r <= '9':
			case r >= 'a' && r <= 'f':
				letter = true
			default:
				hex = false
			}
			if !hex {
				break
			}
		}
		if !hex || !letter {
			continue
		}
		if len(p) > len(best) {
			best = p
		}
	}
	return best
}

// deploymentLinkBatch caps how many commit lookups one pass performs, since
// each unresolved repository costs an SCM round trip.
const deploymentLinkBatch = 50

// linkGiveUpAfter is how long a deployment keeps being retried before its
// link is recorded as failed for good. Without it a repository whose
// credentials are wrong leaves rows pending forever, and a pending row is
// invisible in the coverage figure rather than counted against it.
const linkGiveUpAfter = 24 * time.Hour

// resolveDeploymentLinks attaches each new deployment to the commit that
// produced it, and with it the lead time.
//
// The distinction that matters here is between a determinate answer and a
// transient one. "The tag carries no hash" and "that commit is not in the
// branch history" are answers: the row is marked unlinked and never asked
// again. A network error or a rejected credential is not an answer, so the row
// stays pending and is retried, up to linkGiveUpAfter.
func resolveDeploymentLinks() {
	var pending []models.Deployment
	db.DB.Where("link_status = 'pending'").
		Order("deployed_at asc").Limit(deploymentLinkBatch).Find(&pending)
	if len(pending) == 0 {
		return
	}

	// One SCM call per repository per pass, not per deployment: a rollout that
	// touches twenty workloads is one commit history.
	type historyResult struct {
		commits []services.CommitInfo
		err     error
	}
	history := map[string]historyResult{}

	for i := range pending {
		dep := &pending[i]
		mark := func(status, detail string) {
			dep.LinkStatus, dep.LinkDetail = status, detail
			db.DB.Model(dep).Updates(map[string]any{
				"link_status": status, "link_detail": detail,
			})
		}
		giveUp := time.Since(dep.DeployedAt) > linkGiveUpAfter

		sha := commitSHAFromImage(dep.Image)
		if sha == "" {
			mark("unlinked", "the image tag carries no commit hash")
			continue
		}
		repoName := repoNameFromImage(dep.Image)
		var repo models.Repository
		if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
			mark("unlinked", fmt.Sprintf("no connected repository named %q", repoName))
			continue
		}

		res, cached := history[repo.Name]
		if !cached {
			res.commits, res.err = recentCommitsFor(repo)
			history[repo.Name] = res
		}
		if res.err != nil {
			// Transient until proven otherwise: keep it pending so a fixed
			// credential backfills the lead time on the next pass.
			if giveUp {
				mark("unlinked", "commit history unavailable: "+res.err.Error())
			}
			continue
		}

		var match *services.CommitInfo
		for j := range res.commits {
			if strings.HasPrefix(strings.ToLower(res.commits[j].Hash), sha) {
				match = &res.commits[j]
				break
			}
		}
		if match == nil {
			mark("unlinked", fmt.Sprintf("commit %s is not in the recent history of %s", sha, repo.Name))
			continue
		}
		commitAt, err := time.Parse(time.RFC3339, match.Date)
		if err != nil {
			mark("unlinked", fmt.Sprintf("commit %s has an unreadable date", match.ShortHash))
			continue
		}
		// Clock skew between the SCM and the cluster can put a commit after
		// the deployment it produced. A negative lead time is not a fact about
		// delivery, so it is floored rather than stored as measured.
		lead := int64(dep.DeployedAt.Sub(commitAt).Seconds())
		if lead < 0 {
			lead = 0
		}
		db.DB.Model(dep).Updates(map[string]any{
			"link_status": "linked", "link_detail": "",
			"repo_name": repo.Name, "commit_sha": match.Hash,
			"commit_at": commitAt, "lead_time_sec": lead,
		})
	}
}

// recentCommitsFor reads a repository's recent commits with the workspace
// credentials, the way the background scanner does -- there is no request and
// therefore no user to borrow them from.
func recentCommitsFor(repo models.Repository) ([]services.CommitInfo, error) {
	ws, err := resolveWorkspace(repo.UserID, repo.WorkspaceID)
	if err != nil {
		return nil, fmt.Errorf("no workspace configured")
	}
	pass := crypto.DecryptField(crypto.MasterKey(), ws.AppPass)
	if ws.Username == "" || pass == "" {
		return nil, fmt.Errorf("workspace credentials are not configured")
	}
	client := services.NewSCMClient(repo.Provider, ws.Username, pass, ws.WorkspaceID)
	return client.GetRecentCommits(repo.Name, "", 100)
}

// settleDeploymentOutcomes decides, once the failure window has passed,
// whether a deployment broke what it changed.
//
// The rule that makes this number honest is the treatment of cause. A problem
// attributed to a dependency is a third party's outage, and counting it as a
// change failure blames the team that deployed for something they did not do.
// Those are excluded from the rate and recorded on the row, so the exclusion
// is visible rather than silent.
func settleDeploymentOutcomes() {
	window := durationEnv("DORA_FAILURE_WINDOW", time.Hour)

	var pending []models.Deployment
	db.DB.Where("outcome = 'pending' AND deployed_at <= ?", time.Now().Add(-window)).
		Order("deployed_at asc").Limit(500).Find(&pending)
	for i := range pending {
		evaluateDeployment(&pending[i], window)
	}

	// A deployment already known to have failed may not have recovered yet.
	var unrecovered []models.Deployment
	db.DB.Where("outcome = 'failed' AND recovered_at IS NULL").Limit(500).Find(&unrecovered)
	for i := range unrecovered {
		dep := &unrecovered[i]
		if at := findRecovery(dep); at != nil {
			from := dep.DeployedAt
			if dep.FailedAt != nil {
				from = *dep.FailedAt
			}
			secs := int64(at.Sub(from).Seconds())
			if secs < 0 {
				secs = 0
			}
			db.DB.Model(dep).Updates(map[string]any{"recovered_at": at, "recovery_sec": secs})
		}
	}
}

func evaluateDeployment(dep *models.Deployment, window time.Duration) {
	end := dep.DeployedAt.Add(window)
	update := map[string]any{"outcome": "ok"}

	fail := func(reason string, at time.Time) {
		update["outcome"] = "failed"
		update["failed_reason"] = reason
		update["failed_at"] = at
	}

	// A rollback is the strongest evidence there is: someone put back what was
	// running before. It is read off the deployment history itself, since
	// every image change writes a row.
	var back models.Deployment
	if dep.PrevImage != "" {
		err := db.DB.Where(`cluster_id = ? AND namespace = ? AND workload = ? AND workload_kind = ?
			AND deployed_at > ? AND deployed_at <= ? AND image = ?`,
			dep.ClusterID, dep.Namespace, dep.Workload, dep.WorkloadKind,
			dep.DeployedAt, end, dep.PrevImage).
			Order("deployed_at asc").First(&back).Error
		if err == nil {
			db.DB.Model(&models.Deployment{}).Where("id = ?", back.ID).Update("rollback", true)
			// A rollback says the deployment was bad; it does not say when it
			// started being bad. So the failure is dated from the deployment
			// and service is restored when the old image is back, which makes
			// the recovery time the length of the bad release.
			fail("rolled back to the previous image", dep.DeployedAt)
			update["recovered_at"] = back.DeployedAt
			secs := int64(back.DeployedAt.Sub(dep.DeployedAt).Seconds())
			if secs < 0 {
				secs = 0
			}
			update["recovery_sec"] = secs
		}
	}

	// A problem the error layer opened on this workload inside the window.
	// cause_kind is what separates "this deployment broke it" from "a third
	// party went down while this deployment happened to be recent".
	if update["outcome"] == "ok" {
		var sp models.ServiceProblem
		err := db.DB.Where(`cluster_id = ? AND namespace = ? AND workload = ?
			AND opened_at >= ? AND opened_at <= ? AND cause_kind != 'dependency'`,
			dep.ClusterID, dep.Namespace, dep.Workload, dep.DeployedAt, end).
			Order("opened_at asc").First(&sp).Error
		if err == nil {
			fail(sp.Kind, sp.OpenedAt)
		}
	}

	if update["outcome"] == "ok" {
		var pp models.PodProblem
		err := db.DB.Where(`cluster_id = ? AND namespace = ? AND workload = ?
			AND opened_at >= ? AND opened_at <= ?`,
			dep.ClusterID, dep.Namespace, dep.Workload, dep.DeployedAt, end).
			Order("opened_at asc").First(&pp).Error
		if err == nil {
			fail(pp.Kind, pp.OpenedAt)
		}
	}

	// Last resort: the workload itself went to zero ready replicas. The pod
	// problems above usually say why, but a rollout that never becomes ready
	// produces this and nothing else.
	if update["outcome"] == "ok" {
		var ev models.WorkloadEvent
		err := db.DB.Where(`cluster_id = ? AND namespace = ? AND name = ?
			AND event_type = 'status_change' AND new_value = 'degraded'
			AND recorded_at > ? AND recorded_at <= ?`,
			dep.ClusterID, dep.Namespace, dep.Workload, dep.DeployedAt, end).
			Order("recorded_at asc").First(&ev).Error
		if err == nil {
			fail("degraded", ev.RecordedAt)
		}
	}

	// Whatever the verdict, record whether a dependency-caused problem was
	// seen in the window. On an "ok" row that is the exclusion made visible.
	var depIncidents int64
	db.DB.Model(&models.ServiceProblem{}).Where(`cluster_id = ? AND namespace = ? AND workload = ?
		AND opened_at >= ? AND opened_at <= ? AND cause_kind = 'dependency'`,
		dep.ClusterID, dep.Namespace, dep.Workload, dep.DeployedAt, end).Count(&depIncidents)
	update["dependency_incident"] = depIncidents > 0

	db.DB.Model(dep).Updates(update)

	if _, done := update["recovered_at"]; update["outcome"] == "failed" && !done {
		var reload models.Deployment
		if db.DB.Where("id = ?", dep.ID).First(&reload).Error == nil {
			if at := findRecovery(&reload); at != nil {
				from := reload.DeployedAt
				if reload.FailedAt != nil {
					from = *reload.FailedAt
				}
				secs := int64(at.Sub(from).Seconds())
				if secs < 0 {
					secs = 0
				}
				db.DB.Model(&reload).Updates(map[string]any{"recovered_at": at, "recovery_sec": secs})
			}
		}
	}
}

// findRecovery returns when service was restored after a failed deployment:
// the earliest of the problems closing or the workload reporting healthy
// again. Nil means it has not recovered yet, which is a real state and not a
// missing value -- an incident still open must not be averaged into a
// recovery time as if it had ended.
func findRecovery(dep *models.Deployment) *time.Time {
	from := dep.DeployedAt
	if dep.FailedAt != nil {
		from = *dep.FailedAt
	}
	var best *time.Time
	consider := func(t *time.Time) {
		if t == nil || t.Before(from) {
			return
		}
		if best == nil || t.Before(*best) {
			best = t
		}
	}

	var sp models.ServiceProblem
	if db.DB.Where(`cluster_id = ? AND namespace = ? AND workload = ?
		AND closed_at IS NOT NULL AND closed_at >= ?`,
		dep.ClusterID, dep.Namespace, dep.Workload, from).
		Order("closed_at asc").First(&sp).Error == nil {
		consider(sp.ClosedAt)
	}
	var pp models.PodProblem
	if db.DB.Where(`cluster_id = ? AND namespace = ? AND workload = ?
		AND closed_at IS NOT NULL AND closed_at >= ?`,
		dep.ClusterID, dep.Namespace, dep.Workload, from).
		Order("closed_at asc").First(&pp).Error == nil {
		consider(pp.ClosedAt)
	}
	var ev models.WorkloadEvent
	if db.DB.Where(`cluster_id = ? AND namespace = ? AND name = ?
		AND event_type = 'status_change' AND new_value = 'healthy' AND recorded_at >= ?`,
		dep.ClusterID, dep.Namespace, dep.Workload, from).
		Order("recorded_at asc").First(&ev).Error == nil {
		consider(&ev.RecordedAt)
	}
	return best
}

// PollDelivery runs the two passes that cannot live in the workload poller:
// one makes network calls, the other needs the failure window to have elapsed.
func PollDelivery() {
	resolveDeploymentLinks()
	settleDeploymentOutcomes()

	// Deployments outlive the snapshots they were derived from on purpose:
	// the DORA bands are defined over months and WORKLOAD_RETENTION_DAYS is 30.
	days := 180
	if v := os.Getenv("DORA_RETENTION_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			days = d
		}
	}
	db.DB.Where("deployed_at < ?", time.Now().AddDate(0, 0, -days)).Delete(&models.Deployment{})
}

// --- read side ---

// doraBand places a measurement in one of the four performance bands. The
// thresholds are the published ones; they are here rather than in the frontend
// so that the API and any future export agree on what "elite" means.
func doraBand(metric string, v float64) string {
	const (
		hour = 3600.0
		day  = 24 * hour
		week = 7 * day
	)
	switch metric {
	case "deploy_frequency": // deployments per day
		switch {
		case v >= 1:
			return "elite"
		case v >= 1.0/7:
			return "high"
		case v >= 1.0/30:
			return "medium"
		default:
			return "low"
		}
	case "lead_time", "recovery_time": // seconds, median
		limits := [3]float64{day, week, 30 * day}
		if metric == "recovery_time" {
			limits = [3]float64{hour, day, week}
		}
		switch {
		case v < limits[0]:
			return "elite"
		case v < limits[1]:
			return "high"
		case v < limits[2]:
			return "medium"
		default:
			return "low"
		}
	case "change_failure": // percent
		switch {
		case v <= 15:
			return "elite"
		case v <= 30:
			return "high"
		case v <= 45:
			return "medium"
		default:
			return "low"
		}
	}
	return "unknown"
}

// medianSec returns the median of a sample, nil for an empty one. Median
// rather than mean is what DORA specifies, and it is also what survives a
// single deployment that sat unreleased for six months.
func medianSec(values []int64) *int64 {
	if len(values) == 0 {
		return nil
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	var m int64
	if n := len(values); n%2 == 1 {
		m = values[n/2]
	} else {
		m = (values[n/2-1] + values[n/2]) / 2
	}
	return &m
}

func percentileSec(values []int64, p float64) *int64 {
	if len(values) == 0 {
		return nil
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	idx := int(p * float64(len(values)-1))
	return &values[idx]
}

type doraMetric struct {
	Band string `json:"band"`
}

type DORASummary struct {
	WindowDays int       `json:"window_days"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	// ScopeAllNamespaces says the figures count every namespace the caller can
	// see, staging included. Until production is declared somewhere, saying so
	// on the page is the difference between a number and a misleading one.
	ScopeAllNamespaces bool     `json:"scope_all_namespaces"`
	Namespaces         []string `json:"namespaces"`

	Deployments struct {
		doraMetric
		Total     int64   `json:"total"`
		PerDay    float64 `json:"per_day"`
		PerWeek   float64 `json:"per_week"`
		Workloads int64   `json:"workloads"`
		Rollbacks int64   `json:"rollbacks"`
	} `json:"deployments"`

	LeadTime struct {
		doraMetric
		MedianSec   *int64  `json:"median_sec"`
		P90Sec      *int64  `json:"p90_sec"`
		Linked      int     `json:"linked"`
		Unlinked    int     `json:"unlinked"`
		Pending     int     `json:"pending"`
		CoveragePct float64 `json:"coverage_pct"`
	} `json:"lead_time"`

	ChangeFailure struct {
		doraMetric
		Settled            int      `json:"settled"`
		Failed             int      `json:"failed"`
		RatePct            *float64 `json:"rate_pct"`
		Pending            int      `json:"pending"`
		DependencyExcluded int      `json:"dependency_excluded"`
	} `json:"change_failure"`

	Recovery struct {
		doraMetric
		MedianSec *int64 `json:"median_sec"`
		Recovered int    `json:"recovered"`
		Ongoing   int    `json:"ongoing"`
	} `json:"recovery"`

	// UnlinkedReasons says why lead time covers what it covers. A coverage
	// figure with no explanation is a number nobody can act on.
	UnlinkedReasons []LabelCount       `json:"unlinked_reasons"`
	FailureReasons  []LabelCount       `json:"failure_reasons"`
	TopWorkloads    []WorkloadDelivery `json:"top_workloads"`
}

type LabelCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type WorkloadDelivery struct {
	Namespace     string   `json:"namespace"`
	Workload      string   `json:"workload"`
	Kind          string   `json:"kind"`
	Deployments   int      `json:"deployments"`
	Failed        int      `json:"failed"`
	FailureRate   *float64 `json:"failure_rate"`
	LeadMedianSec *int64   `json:"lead_median_sec"`
	RepoName      string   `json:"repo_name"`
}

// scopedDeployments loads the deployments in the window the caller is allowed
// to see. Namespace scope is applied here, not in the aggregation, so no
// figure can be computed over a namespace the caller cannot open.
func scopedDeployments(c *fiber.Ctx) ([]models.Deployment, *models.Cluster, int, []string, error) {
	cl, err := clusterFromRequest(c)
	if err != nil {
		return nil, nil, 0, nil, err
	}
	days := c.QueryInt("days", 30)
	if days <= 0 {
		days = 30
	}
	if days > 180 {
		days = 180
	}
	allowed, restricted, err := requestNamespaces(c)
	if err != nil {
		return nil, nil, 0, nil, err
	}

	q := db.DB.Where("cluster_id = ? AND deployed_at >= ?", cl.ID, time.Now().AddDate(0, 0, -days))
	if restricted {
		if len(allowed) == 0 {
			return []models.Deployment{}, cl, days, allowed, nil
		}
		q = q.Where("namespace IN ?", allowed)
	}
	if ns := c.Query("namespace"); ns != "" {
		if !namespaceAllowed(c, ns) {
			return nil, nil, 0, nil, fmt.Errorf("namespace %q is out of scope", ns)
		}
		q = q.Where("namespace = ?", ns)
	}
	var out []models.Deployment
	if err := q.Order("deployed_at desc").Find(&out).Error; err != nil {
		return nil, nil, 0, nil, err
	}
	if !restricted {
		allowed = nil
	}
	return out, cl, days, allowed, nil
}

// GetDORASummary computes the four metrics over the window.
func GetDORASummary(c *fiber.Ctx) error {
	deps, _, days, allowed, err := scopedDeployments(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var s DORASummary
	s.WindowDays = days
	s.To = time.Now()
	s.From = s.To.AddDate(0, 0, -days)
	s.ScopeAllNamespaces = allowed == nil && c.Query("namespace") == ""
	s.Namespaces = allowed
	s.UnlinkedReasons = []LabelCount{}
	s.FailureReasons = []LabelCount{}
	s.TopWorkloads = []WorkloadDelivery{}

	workloads := map[string]*WorkloadDelivery{}
	leadByWorkload := map[string][]int64{}
	leads := []int64{}
	recoveries := []int64{}
	unlinkedReasons := map[string]int{}
	failureReasons := map[string]int{}

	for i := range deps {
		d := deps[i]
		s.Deployments.Total++
		if d.Rollback {
			s.Deployments.Rollbacks++
		}

		key := d.Namespace + "/" + d.Workload
		w, ok := workloads[key]
		if !ok {
			w = &WorkloadDelivery{Namespace: d.Namespace, Workload: d.Workload, Kind: d.WorkloadKind}
			workloads[key] = w
		}
		w.Deployments++
		if d.RepoName != "" {
			w.RepoName = d.RepoName
		}

		switch d.LinkStatus {
		case "linked":
			s.LeadTime.Linked++
			if d.LeadTimeSec != nil {
				leads = append(leads, *d.LeadTimeSec)
				leadByWorkload[key] = append(leadByWorkload[key], *d.LeadTimeSec)
			}
		case "unlinked":
			s.LeadTime.Unlinked++
			reason := d.LinkDetail
			if reason == "" {
				reason = "unknown"
			}
			unlinkedReasons[reason]++
		default:
			s.LeadTime.Pending++
		}

		switch d.Outcome {
		case "ok":
			s.ChangeFailure.Settled++
		case "failed":
			s.ChangeFailure.Settled++
			s.ChangeFailure.Failed++
			w.Failed++
			reason := d.FailedReason
			if reason == "" {
				reason = "unknown"
			}
			failureReasons[reason]++
			if d.RecoverySec != nil {
				s.Recovery.Recovered++
				recoveries = append(recoveries, *d.RecoverySec)
			} else {
				s.Recovery.Ongoing++
			}
		default:
			s.ChangeFailure.Pending++
		}
		if d.DependencyIncident && d.Outcome != "failed" {
			s.ChangeFailure.DependencyExcluded++
		}
	}

	s.Deployments.Workloads = int64(len(workloads))
	if days > 0 {
		s.Deployments.PerDay = float64(s.Deployments.Total) / float64(days)
		s.Deployments.PerWeek = s.Deployments.PerDay * 7
	}
	s.Deployments.Band = "unknown"
	if s.Deployments.Total > 0 {
		s.Deployments.Band = doraBand("deploy_frequency", s.Deployments.PerDay)
	}

	s.LeadTime.MedianSec = medianSec(leads)
	s.LeadTime.P90Sec = percentileSec(leads, 0.9)
	s.LeadTime.Band = "unknown"
	if s.LeadTime.MedianSec != nil {
		s.LeadTime.Band = doraBand("lead_time", float64(*s.LeadTime.MedianSec))
	}
	if total := s.LeadTime.Linked + s.LeadTime.Unlinked + s.LeadTime.Pending; total > 0 {
		s.LeadTime.CoveragePct = float64(s.LeadTime.Linked) / float64(total) * 100
	}

	s.ChangeFailure.Band = "unknown"
	if s.ChangeFailure.Settled > 0 {
		rate := float64(s.ChangeFailure.Failed) / float64(s.ChangeFailure.Settled) * 100
		s.ChangeFailure.RatePct = &rate
		s.ChangeFailure.Band = doraBand("change_failure", rate)
	}

	s.Recovery.MedianSec = medianSec(recoveries)
	s.Recovery.Band = "unknown"
	if s.Recovery.MedianSec != nil {
		s.Recovery.Band = doraBand("recovery_time", float64(*s.Recovery.MedianSec))
	}

	for label, n := range unlinkedReasons {
		s.UnlinkedReasons = append(s.UnlinkedReasons, LabelCount{Label: label, Count: n})
	}
	sort.Slice(s.UnlinkedReasons, func(i, j int) bool {
		return s.UnlinkedReasons[i].Count > s.UnlinkedReasons[j].Count
	})
	for label, n := range failureReasons {
		s.FailureReasons = append(s.FailureReasons, LabelCount{Label: label, Count: n})
	}
	sort.Slice(s.FailureReasons, func(i, j int) bool {
		return s.FailureReasons[i].Count > s.FailureReasons[j].Count
	})

	for key, w := range workloads {
		if w.Deployments > 0 {
			rate := float64(w.Failed) / float64(w.Deployments) * 100
			w.FailureRate = &rate
		}
		w.LeadMedianSec = medianSec(leadByWorkload[key])
		s.TopWorkloads = append(s.TopWorkloads, *w)
	}
	sort.Slice(s.TopWorkloads, func(i, j int) bool {
		if s.TopWorkloads[i].Deployments != s.TopWorkloads[j].Deployments {
			return s.TopWorkloads[i].Deployments > s.TopWorkloads[j].Deployments
		}
		return s.TopWorkloads[i].Workload < s.TopWorkloads[j].Workload
	})

	return c.JSON(s)
}

// GetDeployments lists the deployments behind the summary, newest first. The
// metrics are only believable if the events they were computed from can be
// read one by one.
func GetDeployments(c *fiber.Ctx) error {
	deps, _, _, _, err := scopedDeployments(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if outcome := c.Query("outcome"); outcome != "" {
		kept := deps[:0]
		for _, d := range deps {
			if d.Outcome == outcome {
				kept = append(kept, d)
			}
		}
		deps = kept
	}
	limit := c.QueryInt("limit", 200)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if len(deps) > limit {
		deps = deps[:limit]
	}
	return c.JSON(fiber.Map{"items": deps, "count": len(deps)})
}
