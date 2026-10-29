package handlers

import (
	"sort"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

// The code dashboard's totals mix three different problems: a CVE in a
// dependency, a misconfigured manifest, and a flaw in code the team wrote.
// Only the last one is fixed by changing that code, and it is the one the
// repository cards cannot answer anything about across repositories: which
// kinds of flaw keep turning up, where they concentrate, and how long they
// stay open. This endpoint is that view, over the same scope as the rest.

// cweNames are the weaknesses the CommitKube rules report, in words a
// dashboard can show without sending the reader to MITRE first.
var cweNames = map[string]string{
	"CWE-22":  "Path traversal",
	"CWE-78":  "OS command injection",
	"CWE-79":  "Cross-site scripting",
	"CWE-89":  "SQL injection",
	"CWE-95":  "Eval injection",
	"CWE-295": "Certificate validation disabled",
	"CWE-327": "Broken cipher",
	"CWE-328": "Weak hash",
	"CWE-489": "Debug mode left on",
	"CWE-502": "Unsafe deserialization",
	"CWE-601": "Open redirect",
	"CWE-611": "XML external entities",
	"CWE-918": "Server-side request forgery",
}

const (
	weaknessFixWindow     = 90 * 24 * time.Hour
	weaknessStaleAge      = 30 * 24 * time.Hour
	weaknessRankLimit     = 15
	weaknessOccurrenceCap = 200
)

type weaknessGroup struct {
	Key   string `json:"key"`  // the CWE or the rule id
	Name  string `json:"name"` // the CWE in words, or a rule's message
	CWE   string `json:"cwe,omitempty"`
	Open  int    `json:"open"`
	Repos int    `json:"repos"`
	severityCounts

	repos map[string]bool
}

type weaknessRepo struct {
	Repo   string    `json:"repo"`
	Open   int       `json:"open"`
	Oldest time.Time `json:"oldest"`
	severityCounts
}

type weaknessOccurrence struct {
	Repo      string    `json:"repo"`
	Target    string    `json:"target"`
	Line      int       `json:"line"`
	Rule      string    `json:"rule"`
	CWE       string    `json:"cwe,omitempty"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	FirstSeen time.Time `json:"first_seen"`
}

type weaknessFixTime struct {
	// Resolved is how many weaknesses stopped being reported in the window;
	// the days are from first seen to resolved. A weakness whose file was
	// deleted counts as fixed, which it is.
	Resolved   int     `json:"resolved"`
	MedianDays float64 `json:"median_days"`
	P90Days    float64 `json:"p90_days"`
	// Open ones, by how long they have been open.
	OpenMedianDays float64 `json:"open_median_days"`
	OpenStale      int     `json:"open_stale"` // open longer than weaknessStaleAge
}

type sastRepoError struct {
	Repo  string `json:"repo"`
	Error string `json:"error"`
}

// GetWeaknessDashboard aggregates the open code weaknesses of every
// repository in scope. With ?rule= or ?cwe= it also lists where that one
// occurs, which is what a click on a ranking row asks for.
func GetWeaknessDashboard(c *fiber.Ctx) error {
	repoNames := scanScopeRepoNames(c.QueryInt("workspace_id", 0), c.Query("project_key", ""), c.Query("search", ""))
	now := time.Now()
	resp := fiber.Map{
		"totals": severityCounts{}, "open": 0, "suppressed": 0,
		"repos_in_scope": 0, "repos_scanned": 0, "repos_affected": 0,
		"sast_errors": []sastRepoError{}, "by_cwe": []weaknessGroup{}, "by_rule": []weaknessGroup{},
		"by_repo": []weaknessRepo{}, "fix_time": weaknessFixTime{},
	}
	if len(repoNames) == 0 {
		return c.JSON(resp)
	}

	var results []models.ScanResult
	db.DB.Select("repo_name", "sast_scanned_at", "sast_error").Where("repo_name IN ?", repoNames).Find(&results)
	scanned := 0
	sastErrors := []sastRepoError{}
	for _, r := range results {
		if r.SastScannedAt != nil {
			scanned++
		}
		if r.SastError != "" {
			sastErrors = append(sastErrors, sastRepoError{r.RepoName, r.SastError})
		}
	}
	sort.Slice(sastErrors, func(i, j int) bool { return sastErrors[i].Repo < sastErrors[j].Repo })

	var rows []models.ScanFinding
	db.DB.Where("repo_name IN ? AND kind = ? AND (resolved_at IS NULL OR resolved_at >= ?)",
		repoNames, FindingWeakness, now.Add(-weaknessFixWindow)).Find(&rows)

	// Split into what is open -- with the triage decisions applied, so a
	// suppressed weakness is left out here as it is everywhere else -- and
	// what was fixed within the window.
	byRepo := map[string][]models.ScanFinding{}
	var fixDays []float64
	for _, r := range rows {
		if r.ResolvedAt != nil {
			fixDays = append(fixDays, r.ResolvedAt.Sub(r.FirstSeen).Hours()/24)
			continue
		}
		byRepo[r.RepoName] = append(byRepo[r.RepoName], r)
	}
	sups := suppressionsForRepos(repoNames, now)

	ruleFilter, cweFilter := c.Query("rule"), c.Query("cwe")
	var totals severityCounts
	open, suppressed := 0, 0
	cwes := map[string]*weaknessGroup{}
	rules := map[string]*weaknessGroup{}
	repos := map[string]*weaknessRepo{}
	var openDays []float64
	occurrences := []weaknessOccurrence{}
	for repo, list := range byRepo {
		plain := make([]finding, len(list))
		for i, r := range list {
			plain[i] = findingFromRow(r)
		}
		plain = applySuppressions(plain, append(sups[""], sups[repo]...))
		for i, f := range plain {
			if f.Suppressed {
				suppressed++
				continue
			}
			row := list[i]
			open++
			totals = totals.add(severityOf(f.Severity))
			openDays = append(openDays, now.Sub(row.FirstSeen).Hours()/24)

			cweKey := f.CWE
			if cweKey == "" {
				cweKey = "unclassified"
			}
			g := groupFor(cwes, cweKey)
			g.Name = cweNames[f.CWE]
			if g.Name == "" {
				g.Name = cweKey
			}
			g.CWE = f.CWE
			g.add(repo, f.Severity)

			rg := groupFor(rules, f.VulnID)
			if rg.Name == "" {
				rg.Name = f.Title
			}
			rg.CWE = f.CWE
			rg.add(repo, f.Severity)

			wr, ok := repos[repo]
			if !ok {
				wr = &weaknessRepo{Repo: repo, Oldest: row.FirstSeen}
				repos[repo] = wr
			}
			wr.Open++
			wr.severityCounts = wr.severityCounts.add(severityOf(f.Severity))
			if row.FirstSeen.Before(wr.Oldest) {
				wr.Oldest = row.FirstSeen
			}

			if (ruleFilter != "" && f.VulnID == ruleFilter) || (cweFilter != "" && cweKey == cweFilter) {
				occurrences = append(occurrences, weaknessOccurrence{
					Repo: repo, Target: f.Target, Line: f.Line, Rule: f.VulnID, CWE: f.CWE,
					Severity: f.Severity, Title: f.Title, FirstSeen: row.FirstSeen,
				})
			}
		}
	}

	stale := 0
	for _, d := range openDays {
		if d > weaknessStaleAge.Hours()/24 {
			stale++
		}
	}

	resp["totals"] = totals
	resp["open"] = open
	resp["suppressed"] = suppressed
	resp["repos_in_scope"] = len(repoNames)
	resp["repos_scanned"] = scanned
	resp["repos_affected"] = len(repos)
	resp["sast_errors"] = sastErrors
	resp["by_cwe"] = rankGroups(cwes)
	resp["by_rule"] = rankGroups(rules)
	resp["by_repo"] = rankRepos(repos)
	resp["fix_time"] = weaknessFixTime{
		Resolved: len(fixDays), MedianDays: percentile(fixDays, 0.5), P90Days: percentile(fixDays, 0.9),
		OpenMedianDays: percentile(openDays, 0.5), OpenStale: stale,
	}
	if ruleFilter != "" || cweFilter != "" {
		sort.Slice(occurrences, func(i, j int) bool {
			a, b := occurrences[i], occurrences[j]
			if severityRank[a.Severity] != severityRank[b.Severity] {
				return severityRank[a.Severity] < severityRank[b.Severity]
			}
			if a.Repo != b.Repo {
				return a.Repo < b.Repo
			}
			if a.Target != b.Target {
				return a.Target < b.Target
			}
			return a.Line < b.Line
		})
		resp["occurrences_total"] = len(occurrences)
		if len(occurrences) > weaknessOccurrenceCap {
			occurrences = occurrences[:weaknessOccurrenceCap]
		}
		resp["occurrences"] = occurrences
	}
	return c.JSON(resp)
}

// suppressionsForRepos reads every decision that applies to any of the
// repositories in one query, keyed by repository ("" for the global ones).
// activeSuppressions is one query per repository, which across a whole
// workspace is hundreds.
func suppressionsForRepos(repoNames []string, now time.Time) map[string][]models.ScanSuppression {
	var all []models.ScanSuppression
	db.DB.Where("repo_name IN ? OR repo_name = ''", repoNames).Find(&all)
	out := map[string][]models.ScanSuppression{}
	for _, s := range all {
		if s.ExpiresAt != nil && s.ExpiresAt.Before(now) {
			continue
		}
		out[s.RepoName] = append(out[s.RepoName], s)
	}
	return out
}

func severityOf(s string) severityCounts {
	switch s {
	case "CRITICAL":
		return severityCounts{Critical: 1}
	case "HIGH":
		return severityCounts{High: 1}
	case "MEDIUM":
		return severityCounts{Medium: 1}
	case "LOW":
		return severityCounts{Low: 1}
	}
	return severityCounts{}
}

func groupFor(m map[string]*weaknessGroup, key string) *weaknessGroup {
	g, ok := m[key]
	if !ok {
		g = &weaknessGroup{Key: key, repos: map[string]bool{}}
		m[key] = g
	}
	return g
}

func (g *weaknessGroup) add(repo, severity string) {
	g.Open++
	g.severityCounts = g.severityCounts.add(severityOf(severity))
	g.repos[repo] = true
	g.Repos = len(g.repos)
}

// rankGroups orders worst first: high-severity count, then how widely the
// weakness is spread, then how many there are.
func rankGroups(m map[string]*weaknessGroup) []weaknessGroup {
	out := make([]weaknessGroup, 0, len(m))
	for _, g := range m {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Critical+a.High != b.Critical+b.High {
			return a.Critical+a.High > b.Critical+b.High
		}
		if a.Repos != b.Repos {
			return a.Repos > b.Repos
		}
		if a.Open != b.Open {
			return a.Open > b.Open
		}
		return a.Key < b.Key
	})
	if len(out) > weaknessRankLimit {
		out = out[:weaknessRankLimit]
	}
	return out
}

func rankRepos(m map[string]*weaknessRepo) []weaknessRepo {
	out := make([]weaknessRepo, 0, len(m))
	for _, r := range m {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Critical+a.High != b.Critical+b.High {
			return a.Critical+a.High > b.Critical+b.High
		}
		if a.Open != b.Open {
			return a.Open > b.Open
		}
		return a.Repo < b.Repo
	})
	if len(out) > weaknessRankLimit {
		out = out[:weaknessRankLimit]
	}
	return out
}

// percentile by nearest rank, rounded to a tenth of a day; 0 for no data.
func percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	i := int(p*float64(len(s))+0.5) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(s) {
		i = len(s) - 1
	}
	return float64(int(s[i]*10+0.5)) / 10
}
