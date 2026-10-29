package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func weakness(repo, rule, cwe, sev, fp string, line int) finding {
	return finding{Domain: FindingDomainCode, Kind: FindingWeakness, Target: "main.go", VulnID: rule,
		Pkg: fp, Line: line, Severity: sev, CWE: cwe, Title: rule + " message"}
}

type weaknessResp struct {
	Totals       severityCounts  `json:"totals"`
	Open         int             `json:"open"`
	Suppressed   int             `json:"suppressed"`
	ReposInScope int             `json:"repos_in_scope"`
	ReposScanned int             `json:"repos_scanned"`
	ReposAffect  int             `json:"repos_affected"`
	SastErrors   []sastRepoError `json:"sast_errors"`
	ByCWE        []weaknessGroup `json:"by_cwe"`
	ByRule       []weaknessGroup `json:"by_rule"`
	ByRepo       []weaknessRepo  `json:"by_repo"`
	FixTime      weaknessFixTime `json:"fix_time"`
	Occurrences  []weaknessOccurrence
}

func getWeaknesses(t *testing.T, query string) weaknessResp {
	t.Helper()
	app := fiber.New()
	app.Get("/scan-weaknesses", GetWeaknessDashboard)
	res, err := app.Test(httptest.NewRequest("GET", "/scan-weaknesses"+query, nil))
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("GET: %v %v", res.StatusCode, err)
	}
	var out weaknessResp
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWeaknessDashboard(t *testing.T) {
	useScanDB(t)
	if err := db.DB.AutoMigrate(&models.Repository{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, name := range []string{"api", "web", "jobs"} {
		db.DB.Create(&models.Repository{Name: name})
	}
	db.DB.Create(&models.ScanResult{RepoName: "api", SastScannedAt: &now})
	db.DB.Create(&models.ScanResult{RepoName: "web", SastScannedAt: &now})
	db.DB.Create(&models.ScanResult{RepoName: "jobs", SastError: "opengrep is not installed"})

	tenDaysAgo := now.AddDate(0, 0, -10)
	if _, err := reconcileFindings("api", FindingDomainCode, []finding{
		weakness("api", "ck-go-sql-built-from-strings", "CWE-89", "HIGH", "a1", 10),
		weakness("api", "ck-go-sql-built-from-strings", "CWE-89", "HIGH", "a2", 20),
		weakness("api", "ck-go-weak-hash", "CWE-328", "LOW", "a3", 30),
		vuln("go.mod", "CVE-2026-0001", "golang.org/x/net", "CRITICAL"), // not a weakness
	}, tenDaysAgo); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileFindings("web", FindingDomainCode, []finding{
		weakness("web", "ck-js-sql-built-from-strings", "CWE-89", "HIGH", "w1", 5),
		weakness("web", "ck-js-eval", "CWE-95", "MEDIUM", "w2", 6),
	}, tenDaysAgo); err != nil {
		t.Fatal(err)
	}
	// web's eval goes away four days later: fixed in four days.
	if _, err := reconcileFindings("web", FindingDomainCode, []finding{
		weakness("web", "ck-js-sql-built-from-strings", "CWE-89", "HIGH", "w1", 5),
	}, tenDaysAgo.AddDate(0, 0, 4)); err != nil {
		t.Fatal(err)
	}
	// One of api's SQL findings is triaged away.
	db.DB.Create(&models.ScanSuppression{RepoName: "api", VulnID: "ck-go-sql-built-from-strings", Pkg: "a2", Reason: "false_positive"})

	got := getWeaknesses(t, "")
	if got.Open != 3 || got.Suppressed != 1 {
		t.Fatalf("open/suppressed = %d/%d, want 3/1", got.Open, got.Suppressed)
	}
	if got.Totals != (severityCounts{High: 2, Low: 1}) {
		t.Errorf("totals = %+v: the CVE and the suppressed one must not count", got.Totals)
	}
	if got.ReposInScope != 3 || got.ReposScanned != 2 || got.ReposAffect != 2 {
		t.Errorf("repos in scope/scanned/affected = %d/%d/%d, want 3/2/2", got.ReposInScope, got.ReposScanned, got.ReposAffect)
	}
	if len(got.SastErrors) != 1 || got.SastErrors[0].Repo != "jobs" {
		t.Errorf("sast errors = %+v", got.SastErrors)
	}
	if len(got.ByCWE) == 0 || got.ByCWE[0].Key != "CWE-89" || got.ByCWE[0].Repos != 2 || got.ByCWE[0].Name != "SQL injection" {
		t.Errorf("top CWE = %+v, want SQL injection across 2 repos", got.ByCWE)
	}
	if got.FixTime.Resolved != 1 || got.FixTime.MedianDays != 4 {
		t.Errorf("fix time = %+v, want one fixed in 4 days", got.FixTime)
	}

	occ := getWeaknesses(t, "?cwe=CWE-89")
	if len(occ.Occurrences) != 2 {
		t.Fatalf("occurrences of CWE-89 = %+v, want api:10 and web:5", occ.Occurrences)
	}
}

// Points recorded before a repository's first static-analysis pass carry
// zeros nobody measured; the SAST trend must start at the first real one,
// not show it as a regression from zero.
func TestSastTimelineIgnoresPointsBeforeFirstPass(t *testing.T) {
	useScanDB(t)
	if err := db.DB.AutoMigrate(&models.Repository{}); err != nil {
		t.Fatal(err)
	}
	db.DB.Create(&models.Repository{Name: "api"})
	now := time.Now()
	db.DB.Create(&models.ScanHistory{RepoName: "api", CreatedAt: now.Add(-48 * time.Hour), High: 5})
	db.DB.Create(&models.ScanHistory{RepoName: "api", CreatedAt: now.Add(-24 * time.Hour), High: 7, SastScanned: true, SastHigh: 2})

	app := fiber.New()
	app.Get("/scan-timeline", GetScanTimeline)
	res, err := app.Test(httptest.NewRequest("GET", "/scan-timeline?domain=sast&days=7", nil))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Domain    string           `json:"domain"`
		Points    []timelinePoint  `json:"points"`
		Regressed []timelineMover  `json:"regressed"`
		Changes   []timelineChange `json:"changes"`
	}
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Domain != "sast" {
		t.Fatalf("domain = %q", got.Domain)
	}
	if len(got.Changes) != 0 || len(got.Regressed) != 0 {
		t.Fatalf("changes = %+v, regressed = %+v: the first measured point is onboarding", got.Changes, got.Regressed)
	}
	if last := got.Points[len(got.Points)-1]; last.High != 2 {
		t.Fatalf("last point high = %d, want the 2 static-analysis findings, not the 7 code ones", last.High)
	}
}

// Static analysis arriving in a repository that was already scanned lifts
// its code counts on the day it first runs. The line shows that, but it is
// new coverage, not the code getting worse: no change, no regression.
func TestCodeTimelineTreatsFirstSastPassAsNewCoverage(t *testing.T) {
	loc := time.UTC
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, loc)
	before := []models.ScanHistory{{RepoName: "api", CreatedAt: start.Add(-time.Hour), High: 3}}
	within := []models.ScanHistory{
		// Next day: the same 3 dependency findings plus 4 from static analysis.
		{RepoName: "api", CreatedAt: start.AddDate(0, 0, 1), High: 7, SastScanned: true, SastHigh: 4},
		// A day later one of the dependency findings is fixed: a real change.
		{RepoName: "api", CreatedAt: start.AddDate(0, 0, 2), High: 6, SastScanned: true, SastHigh: 4},
	}
	points, movers, split, changes := buildScanTimeline(before, within, "code", start, 3, 24, loc)

	if last := points[len(points)-1]; last.High != 6 {
		t.Fatalf("last point high = %d, want 6: the line shows the real total", last.High)
	}
	if len(changes) != 1 || changes[0].Delta.High != -1 {
		t.Fatalf("changes = %+v, want only the fix (-1 high)", changes)
	}
	if len(movers) != 1 || movers[0].Delta.High != -1 {
		t.Fatalf("movers = %+v, want api improved by 1, not regressed by 3", movers)
	}
	if split.NewChecks.High != 4 || split.NewCheckRepos != 1 {
		t.Fatalf("new checks = %+v over %d repos, want 4 high over 1", split.NewChecks, split.NewCheckRepos)
	}
	if split.BaselineTo.High-split.BaselineFrom.High != -1 {
		t.Fatalf("baseline %d -> %d, want a drop of 1", split.BaselineFrom.High, split.BaselineTo.High)
	}
}
