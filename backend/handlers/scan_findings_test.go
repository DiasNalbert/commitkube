package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func useScanDB(t *testing.T) {
	t.Helper()
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "scan.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := gdb.AutoMigrate(&models.ScanResult{}, &models.ScanHistory{}, &models.ScanFinding{}, &models.ScanSuppression{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.DB = gdb
}

func vuln(target, id, pkg, sev string) finding {
	return finding{Domain: FindingDomainCode, Kind: FindingVulnerability, Target: target, VulnID: id, Pkg: pkg, Severity: sev, Title: id + " in " + pkg}
}

func openRows(t *testing.T, repo, domain string) map[identity]models.ScanFinding {
	t.Helper()
	var rows []models.ScanFinding
	db.DB.Where("repo_name = ? AND domain = ? AND resolved_at IS NULL", repo, domain).Find(&rows)
	out := map[identity]models.ScanFinding{}
	for _, r := range rows {
		out[identity{r.Domain, r.Kind, r.Target, r.VulnID, r.Pkg, r.Line}] = r
	}
	return out
}

// The whole point of rows: a finding keeps its first-seen date across
// rescans, is closed when it goes away, and is new again when it returns.
func TestReconcileFindingsKeepsIdentityAcrossScans(t *testing.T) {
	useScanDB(t)
	day1 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	day2 := day1.AddDate(0, 0, 1)
	day3 := day1.AddDate(0, 0, 2)

	a := vuln("go.mod", "CVE-2026-0001", "golang.org/x/net", "HIGH")
	b := vuln("go.mod", "CVE-2026-0002", "golang.org/x/crypto", "CRITICAL")

	n, err := reconcileFindings("api", FindingDomainCode, []finding{a, b, b}, day1)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("first scan: new = %d, want 2 (the duplicate row is one finding)", n)
	}

	// Day two: a is still there with a fix now known, b is gone.
	a2 := a
	a2.Fixed = "0.30.0"
	n, err = reconcileFindings("api", FindingDomainCode, []finding{a2}, day2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("second scan: new = %d, want 0", n)
	}
	open := openRows(t, "api", FindingDomainCode)
	if len(open) != 1 {
		t.Fatalf("open after day 2 = %d, want 1", len(open))
	}
	got := open[a.identity()]
	if !got.FirstSeen.Equal(day1) || !got.LastSeen.Equal(day2) || got.Fixed != "0.30.0" {
		t.Fatalf("a after day 2: first=%v last=%v fixed=%q", got.FirstSeen, got.LastSeen, got.Fixed)
	}
	var closed models.ScanFinding
	db.DB.Where("vuln_id = ?", b.VulnID).First(&closed)
	if closed.ResolvedAt == nil || !closed.ResolvedAt.Equal(day2) {
		t.Fatalf("b should be resolved on day 2, got %v", closed.ResolvedAt)
	}

	// Day three: b is back. It is a new finding, not the old one resumed.
	n, err = reconcileFindings("api", FindingDomainCode, []finding{a2, b}, day3)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("third scan: new = %d, want 1", n)
	}
	open = openRows(t, "api", FindingDomainCode)
	got = open[b.identity()]
	if got.ResolvedAt != nil || !got.FirstSeen.Equal(day3) {
		t.Fatalf("b after return: resolved=%v first=%v, want open since day 3", got.ResolvedAt, got.FirstSeen)
	}
	var total int64
	db.DB.Model(&models.ScanFinding{}).Count(&total)
	if total != 2 {
		t.Fatalf("rows = %d, want 2: a returning finding reuses its row", total)
	}
}

// The image half and the code half are reconciled separately: an image-only
// rescan must not close the code findings it did not look at.
func TestReconcileFindingsIsScopedToDomain(t *testing.T) {
	useScanDB(t)
	now := time.Now()
	code := vuln("go.mod", "CVE-1", "x", "LOW")
	img := vuln("alpine", "CVE-2", "musl", "HIGH")
	img.Domain = FindingDomainImage
	if _, err := reconcileFindings("api", FindingDomainCode, []finding{code}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileFindings("api", FindingDomainImage, []finding{img}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileFindings("api", FindingDomainImage, nil, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(openRows(t, "api", FindingDomainCode)) != 1 {
		t.Fatal("an empty image scan closed a code finding")
	}
	if len(openRows(t, "api", FindingDomainImage)) != 0 {
		t.Fatal("the image finding should be closed")
	}
}

func TestApplySuppressionsPrefersTheMostSpecificDecision(t *testing.T) {
	rows := []finding{
		vuln("go.mod", "CVE-1", "libA", "HIGH"),
		vuln("go.mod", "CVE-1", "libB", "HIGH"),
		vuln("go.mod", "CVE-2", "libA", "CRITICAL"),
		vuln("go.mod", "CVE-3", "libA", "LOW"),
	}
	sups := []models.ScanSuppression{
		{ID: 1, RepoName: "", VulnID: "CVE-1", Pkg: "", Reason: "not_affected"},          // global, any package
		{ID: 2, RepoName: "api", VulnID: "CVE-1", Pkg: "libA", Reason: "false_positive"}, // this repo, this package
		{ID: 3, RepoName: "api", VulnID: "CVE-2", Pkg: "libZ", Reason: "accepted_risk"},  // wrong package: does not apply
	}
	got := applySuppressions(rows, sups)

	if !got[0].Suppressed || got[0].Suppression.ID != 2 {
		t.Fatalf("CVE-1/libA should take the repo+package decision, got %+v", got[0].Suppression)
	}
	if !got[1].Suppressed || got[1].Suppression.ID != 1 {
		t.Fatalf("CVE-1/libB should fall back to the global decision, got %+v", got[1].Suppression)
	}
	if got[2].Suppressed {
		t.Fatal("CVE-2 is suppressed only for libZ, not libA")
	}
	if got[3].Suppressed {
		t.Fatal("CVE-3 has no decision")
	}

	counts := countFindings(got)
	if counts["HIGH"] != 0 || counts["CRITICAL"] != 1 || counts["LOW"] != 1 {
		t.Fatalf("counts with suppressions = %v", counts)
	}
	if countSuppressed(got) != 2 {
		t.Fatalf("suppressed = %d, want 2", countSuppressed(got))
	}
}

func TestActiveSuppressionsIgnoresExpired(t *testing.T) {
	useScanDB(t)
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	db.DB.Create(&models.ScanSuppression{RepoName: "api", VulnID: "CVE-OLD", Reason: "fix_planned", ExpiresAt: &past})
	db.DB.Create(&models.ScanSuppression{RepoName: "api", VulnID: "CVE-NEW", Reason: "fix_planned", ExpiresAt: &future})
	db.DB.Create(&models.ScanSuppression{RepoName: "", VulnID: "CVE-GLOBAL", Reason: "false_positive"})
	db.DB.Create(&models.ScanSuppression{RepoName: "other", VulnID: "CVE-OTHER", Reason: "false_positive"})

	got := activeSuppressions("api")
	ids := map[string]bool{}
	for _, s := range got {
		ids[s.VulnID] = true
	}
	if ids["CVE-OLD"] || ids["CVE-OTHER"] || !ids["CVE-NEW"] || !ids["CVE-GLOBAL"] {
		t.Fatalf("active for api = %v", ids)
	}
}

// A secret is a finding with a rule, a file and a line -- and nothing of what
// it matched. Misconfigurations that passed are not findings at all.
func TestFindingsFromReportCoversSecretsWithoutTheMatch(t *testing.T) {
	raw := `{"Results":[
	  {"Target":".env","Secrets":[
	    {"RuleID":"aws-access-key-id","Category":"AWS","Severity":"CRITICAL","Title":"AWS Access Key ID","StartLine":3,"Match":"AKIAIOSFODNN7EXAMPLE"}
	  ]},
	  {"Target":"Dockerfile","Misconfigurations":[
	    {"ID":"DS002","Type":"Dockerfile Security Check","Title":"root user","Severity":"HIGH","Status":"FAIL"},
	    {"ID":"DS001","Type":"Dockerfile Security Check","Title":"latest tag","Severity":"MEDIUM","Status":"PASS"}
	  ]},
	  {"Target":"go.mod","Vulnerabilities":[
	    {"VulnerabilityID":"CVE-2026-1","PkgName":"x","InstalledVersion":"1","FixedVersion":"2","Severity":"","Title":"t"}
	  ]}
	]}`
	var report TrivyReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatal(err)
	}
	rows := findingsFromReport(report, FindingDomainCode)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3 (secret, failed misconfig, vuln)", len(rows))
	}
	kinds := map[string]finding{}
	for _, r := range rows {
		kinds[r.Kind] = r
	}
	s := kinds[FindingSecret]
	if s.VulnID != "aws-access-key-id" || s.Line != 3 || s.Pkg != "AWS" || s.Severity != "CRITICAL" {
		t.Fatalf("secret row = %+v", s)
	}
	if kinds[FindingVulnerability].Severity != "UNKNOWN" {
		t.Fatalf("empty severity should read UNKNOWN, got %q", kinds[FindingVulnerability].Severity)
	}
	if countKind(rows, FindingSecret) != 1 {
		t.Fatal("secrets are counted")
	}

	// The matched text never reaches storage: re-marshalling the parsed
	// report drops it, which is what the backfill relies on to scrub old rows.
	if strings.Contains(marshalReport(report), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("the secret's matched text survived the round trip")
	}
	for _, f := range rows {
		b, _ := json.Marshal(f)
		if strings.Contains(string(b), "AKIAIOSFODNN7EXAMPLE") {
			t.Fatal("the secret's matched text is in a finding row")
		}
	}

	// The image domain carries vulnerabilities only.
	if n := len(findingsFromReport(report, FindingDomainImage)); n != 1 {
		t.Fatalf("image rows = %d, want 1", n)
	}
}

func TestBuildScanHTMLEscapesAndListsSuppressed(t *testing.T) {
	code := []finding{
		vuln("go.mod", "CVE-1", "lib<script>", "HIGH"),
		{Domain: FindingDomainCode, Kind: FindingSecret, Target: ".env", VulnID: "aws-access-key-id", Pkg: "AWS", Line: 3, Severity: "CRITICAL", Title: "AWS Access Key ID"},
	}
	code = append(code, vuln("go.mod", "CVE-2", "libB", "LOW"))
	code[2].Suppressed = true
	code[2].Suppression = &models.ScanSuppression{Reason: "accepted_risk", Note: "internal only", CreatedByEmail: "sec@example.com"}

	out := buildScanHTML("api", code, nil, "registry/api:1", "")
	if strings.Contains(out, "lib<script>") || !strings.Contains(out, "lib&lt;script&gt;") {
		t.Fatal("package names are not escaped")
	}
	if !strings.Contains(out, "line 3") || !strings.Contains(out, "SECRETS") {
		t.Fatal("the secret is missing from the mail")
	}
	if !strings.Contains(out, "Suppressed (1)") || !strings.Contains(out, "internal only") {
		t.Fatal("the suppressed finding should be listed under its own heading")
	}
	// Counts in the summary leave the suppressed one out: one HIGH, one
	// CRITICAL (the secret), zero LOW.
	if !strings.Contains(out, `<div class="badge L">0<span class="lbl">LOW</span></div>`) {
		t.Fatal("the suppressed LOW finding was counted")
	}
}

// Creating a suppression has to move the numbers the dashboard shows right
// away, without a rescan, and leave the "last scanned" date alone.
func TestRecountRepoAppliesSuppressionsWithoutAScan(t *testing.T) {
	useScanDB(t)
	scannedAt := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	db.DB.Create(&models.ScanResult{RepoName: "api", Critical: 1, High: 1})
	db.DB.Model(&models.ScanResult{}).Where("repo_name = ?", "api").UpdateColumn("updated_at", scannedAt)
	rows := []finding{vuln("go.mod", "CVE-1", "libA", "CRITICAL"), vuln("go.mod", "CVE-2", "libB", "HIGH")}
	if _, err := reconcileFindings("api", FindingDomainCode, rows, scannedAt); err != nil {
		t.Fatal(err)
	}

	db.DB.Create(&models.ScanSuppression{RepoName: "api", VulnID: "CVE-1", Reason: "false_positive"})
	recountRepo("api")

	var r models.ScanResult
	db.DB.Where("repo_name = ?", "api").First(&r)
	if r.Critical != 0 || r.High != 1 || r.Suppressed != 1 {
		t.Fatalf("after suppression: critical=%d high=%d suppressed=%d", r.Critical, r.High, r.Suppressed)
	}
	if !r.UpdatedAt.Equal(scannedAt) {
		t.Fatalf("recount moved the scan date from %v to %v", scannedAt, r.UpdatedAt)
	}
	var h int64
	db.DB.Model(&models.ScanHistory{}).Where("repo_name = ?", "api").Count(&h)
	if h != 1 {
		t.Fatalf("history points = %d, want 1: the total moved, the trend must say so", h)
	}
}

func suppressionApp(userID uint) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", float64(userID))
		return c.Next()
	})
	app.Get("/scan-suppressions", ListScanSuppressions)
	app.Post("/scan-suppressions", CreateScanSuppression)
	app.Delete("/scan-suppressions/:id", DeleteScanSuppression)
	app.Get("/scan-dashboard/:name", GetRepoScanDetail)
	return app
}

func postJSON(t *testing.T, app *fiber.App, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	res, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// The API end of triage: validation, the audit trail, and the detail page
// reflecting the decision as soon as it is made.
func TestSuppressionAPI(t *testing.T) {
	useScanDB(t)
	if err := db.DB.AutoMigrate(&models.User{}, &models.AuditLog{}, &models.Repository{}); err != nil {
		t.Fatal(err)
	}
	db.DB.Create(&models.User{Email: "sec@example.com"})
	db.DB.Create(&models.Repository{Name: "api"})
	at := time.Now().Add(-time.Hour)
	db.DB.Create(&models.ScanResult{RepoName: "api", High: 2})
	rows := []finding{vuln("go.mod", "CVE-1", "libA", "HIGH"), vuln("go.mod", "CVE-2", "libB", "HIGH")}
	if _, err := reconcileFindings("api", FindingDomainCode, rows, at); err != nil {
		t.Fatal(err)
	}
	app := suppressionApp(1)

	// Accepting a risk silently is refused; so is an unknown repository.
	if code, _ := postJSON(t, app, "/scan-suppressions", map[string]any{"repo_name": "api", "vuln_id": "CVE-1", "reason": "accepted_risk"}); code != 400 {
		t.Fatalf("accepted_risk without a note: %d, want 400", code)
	}
	if code, _ := postJSON(t, app, "/scan-suppressions", map[string]any{"repo_name": "nope", "vuln_id": "CVE-1", "reason": "false_positive"}); code != 404 {
		t.Fatalf("unknown repository: %d, want 404", code)
	}
	if code, _ := postJSON(t, app, "/scan-suppressions", map[string]any{"vuln_id": "CVE-1", "reason": "fix_planned", "note": "x", "expires_at": "2020-01-01"}); code != 400 {
		t.Fatalf("expiry in the past: %d, want 400", code)
	}

	code, body := postJSON(t, app, "/scan-suppressions", map[string]any{
		"repo_name": "api", "vuln_id": "CVE-1", "pkg": "libA", "reason": "accepted_risk", "note": "internal only", "expires_at": "2099-12-31",
	})
	if code != 201 {
		t.Fatalf("create: %d %v", code, body)
	}
	if body["created_by_email"] != "sec@example.com" {
		t.Fatalf("the decision should carry who made it, got %v", body["created_by_email"])
	}

	// The detail page shows it suppressed, with the decision, and the counts
	// dropped at once.
	res, _ := app.Test(httptest.NewRequest("GET", "/scan-dashboard/api", nil))
	var detail struct {
		High       int `json:"high"`
		Suppressed int `json:"suppressed"`
		Findings   []struct {
			VulnID      string `json:"vuln_id"`
			Suppressed  bool   `json:"suppressed"`
			Suppression *struct {
				Reason string `json:"reason"`
			} `json:"suppression"`
		} `json:"findings"`
	}
	_ = json.NewDecoder(res.Body).Decode(&detail)
	if detail.High != 1 || detail.Suppressed != 1 {
		t.Fatalf("detail after suppression: high=%d suppressed=%d", detail.High, detail.Suppressed)
	}
	// Suppressed rows sort last.
	last := detail.Findings[len(detail.Findings)-1]
	if last.VulnID != "CVE-1" || !last.Suppressed || last.Suppression == nil || last.Suppression.Reason != "accepted_risk" {
		t.Fatalf("suppressed row = %+v", last)
	}

	var audit int64
	db.DB.Model(&models.AuditLog{}).Where("action = ?", "suppress_finding").Count(&audit)
	if audit != 1 {
		t.Fatal("suppressing is not audited")
	}

	// Removing it brings the number back.
	id := int(body["id"].(float64))
	res, _ = app.Test(httptest.NewRequest("DELETE", fmt.Sprintf("/scan-suppressions/%d", id), nil))
	if res.StatusCode != 200 {
		t.Fatalf("delete: %d", res.StatusCode)
	}
	var r models.ScanResult
	db.DB.Where("repo_name = ?", "api").First(&r)
	if r.High != 2 || r.Suppressed != 0 {
		t.Fatalf("after unsuppress: high=%d suppressed=%d", r.High, r.Suppressed)
	}
}

// A database from before findings had rows: the backfill reads the stored
// report, dates every row to that scan, and scrubs the secret text the old
// struct used to keep.
func TestBackfillScanFindings(t *testing.T) {
	useScanDB(t)
	scannedAt := time.Now().Add(-72 * time.Hour).Truncate(time.Second)
	old := `{"Results":[{"Target":".env","Secrets":[{"RuleID":"aws-access-key-id","Category":"AWS","Severity":"CRITICAL","Title":"AWS key","StartLine":2,"Match":"AKIAIOSFODNN7EXAMPLE"}]},
	 {"Target":"go.mod","Vulnerabilities":[{"VulnerabilityID":"CVE-9","PkgName":"x","InstalledVersion":"1","Severity":"HIGH","Title":"t"}]}]}`
	img := `{"Results":[{"Target":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-8","PkgName":"musl","InstalledVersion":"1","Severity":"LOW","Title":"t"}]}]}`
	db.DB.Create(&models.ScanResult{RepoName: "legacy", High: 1, Report: old, ImageReport: img, ImageLow: 1})
	db.DB.Model(&models.ScanResult{}).Where("repo_name = ?", "legacy").UpdateColumn("updated_at", scannedAt)

	BackfillScanFindings()
	BackfillScanFindings() // a second start must not duplicate anything

	code := openRows(t, "legacy", FindingDomainCode)
	image := openRows(t, "legacy", FindingDomainImage)
	if len(code) != 2 || len(image) != 1 {
		t.Fatalf("backfilled rows: code=%d image=%d", len(code), len(image))
	}
	for _, r := range code {
		if !r.FirstSeen.Equal(scannedAt) {
			t.Fatalf("row dated %v, want the scan's %v", r.FirstSeen, scannedAt)
		}
	}
	var r models.ScanResult
	db.DB.Where("repo_name = ?", "legacy").First(&r)
	if strings.Contains(r.Report, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("the stored report still holds the secret's text")
	}
	// The secret now counts: it was CRITICAL in the report and never tallied.
	if r.Critical != 1 || r.High != 1 || r.Secrets != 1 || r.ImageLow != 1 {
		t.Fatalf("recounted: critical=%d high=%d secrets=%d imageLow=%d", r.Critical, r.High, r.Secrets, r.ImageLow)
	}
	if !r.UpdatedAt.Equal(scannedAt) {
		t.Fatal("backfill moved the scan date")
	}
}
