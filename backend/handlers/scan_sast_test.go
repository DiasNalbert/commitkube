package handlers

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writeRepoFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const sastReport = `{"results":[
 {"check_id":"tmp.commitkube-sast-rules-abc.ck-go-sql-built-from-strings","path":"api/users.go",
  "start":{"line":%LINE%,"col":2,"offset":0},"end":{"line":%LINE%,"col":40,"offset":0},
  "extra":{"message":"SQL text built with concatenation reaches a query.","severity":"ERROR",
   "metadata":{"cwe":["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]},
   "lines":"db.Query(\"SELECT * FROM users WHERE pass = 'hunter2'\" + id)"}},
 {"check_id":"ck-go-weak-hash","path":"./api/users.go",
  "start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":9,"offset":0},
  "extra":{"message":"MD5","severity":"INFO","metadata":{"cwe":"CWE-328: Use of Weak Hash"}}}
],"errors":[]}`

func reportAt(line int) []byte {
	return []byte(strings.ReplaceAll(sastReport, "%LINE%", strconv.Itoa(line)))
}

func TestFindingsFromOpengrep(t *testing.T) {
	root := t.TempDir()
	writeRepoFile(t, root, "api/users.go", "md5.Sum(b)\n\tdb.Query(\"SELECT * FROM users WHERE pass = 'hunter2'\" + id)\n")

	rows, err := findingsFromOpengrep(reportAt(2), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	sql := rows[0]
	if sql.VulnID != "ck-go-sql-built-from-strings" {
		t.Errorf("rule = %q: the on-disk namespace must be dropped", sql.VulnID)
	}
	if sql.Kind != FindingWeakness || sql.Domain != FindingDomainCode {
		t.Errorf("kind/domain = %s/%s", sql.Kind, sql.Domain)
	}
	if sql.Target != "api/users.go" || rows[1].Target != "api/users.go" {
		t.Errorf("targets = %q, %q: both spellings of the path must come out the same", sql.Target, rows[1].Target)
	}
	if sql.Severity != "HIGH" || rows[1].Severity != "LOW" {
		t.Errorf("severities = %s, %s; want HIGH, LOW", sql.Severity, rows[1].Severity)
	}
	if sql.CWE != "CWE-89" || rows[1].CWE != "CWE-328" {
		t.Errorf("cwes = %q, %q", sql.CWE, rows[1].CWE)
	}
	if sql.Line != 2 || len(sql.Pkg) != 16 {
		t.Errorf("line = %d, fingerprint = %q", sql.Line, sql.Pkg)
	}
	// The matched line held a password; nothing of it may survive.
	for _, f := range rows {
		for _, field := range []string{f.Title, f.Pkg, f.Version, f.Fixed, f.Target} {
			if strings.Contains(field, "hunter2") {
				t.Fatalf("matched text leaked into a finding: %+v", f)
			}
		}
	}
}

// Lines added above a weakness move it, and a moved weakness is the same
// weakness: same identity, so the same row, first-seen date and suppression.
func TestWeaknessIdentitySurvivesALineShift(t *testing.T) {
	root := t.TempDir()
	code := "\tdb.Query(\"SELECT * FROM users WHERE pass = 'hunter2'\" + id)\n"
	writeRepoFile(t, root, "api/users.go", "md5.Sum(b)\n"+code)
	before, err := findingsFromOpengrep(reportAt(2), root)
	if err != nil {
		t.Fatal(err)
	}

	// Ten lines inserted, and the line reindented.
	writeRepoFile(t, root, "api/users.go", "md5.Sum(b)\n"+strings.Repeat("// note\n", 10)+"    "+strings.TrimSpace(code)+"\n")
	after, err := findingsFromOpengrep(reportAt(12), root)
	if err != nil {
		t.Fatal(err)
	}
	if before[0].identity() != after[0].identity() {
		t.Fatalf("identity changed with the line: %+v vs %+v", before[0].identity(), after[0].identity())
	}

	useScanDB(t)
	day1 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	day2 := day1.AddDate(0, 0, 1)
	if _, err := reconcileFindings("api", FindingDomainCode, before, day1); err != nil {
		t.Fatal(err)
	}
	n, err := reconcileFindings("api", FindingDomainCode, after, day2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("new after a line shift = %d, want 0", n)
	}
	open := openFindings("api", FindingDomainCode)
	var got *finding
	for i := range open {
		if open[i].Kind == FindingWeakness && open[i].VulnID == "ck-go-sql-built-from-strings" {
			got = &open[i]
		}
	}
	if got == nil || got.Line != 12 {
		t.Fatalf("stored weakness = %+v, want it open at its new line 12", got)
	}
}

// The same code twice in one file is two findings, not one.
func TestRepeatedMatchInOneFileIsTwoFindings(t *testing.T) {
	root := t.TempDir()
	writeRepoFile(t, root, "a.py", "eval(x)\neval(x)\n")
	raw := []byte(`{"results":[
	 {"check_id":"ck-python-eval","path":"a.py","start":{"line":1},"extra":{"severity":"WARNING"}},
	 {"check_id":"ck-python-eval","path":"a.py","start":{"line":2},"extra":{"severity":"WARNING"}}]}`)
	rows, err := findingsFromOpengrep(raw, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].identity() == rows[1].identity() {
		t.Fatalf("rows = %+v: want two distinct identities", rows)
	}
}

// A static-analysis pass that did not run must not close what the last one
// found: that would report as fixed what nobody checked.
func TestReconcileLeavesKindsNotScannedOpen(t *testing.T) {
	useScanDB(t)
	day1 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	day2 := day1.AddDate(0, 0, 1)
	weak := finding{Domain: FindingDomainCode, Kind: FindingWeakness, Target: "a.go", VulnID: "ck-go-shell-command", Pkg: "0123456789abcdef", Line: 4, Severity: "HIGH"}
	cve := vuln("go.mod", "CVE-2026-0001", "golang.org/x/net", "HIGH")
	if _, err := reconcileFindings("api", FindingDomainCode, []finding{weak, cve}, day1); err != nil {
		t.Fatal(err)
	}

	// Day two: Trivy ran and the CVE is gone; Opengrep did not run.
	if _, err := reconcileFindings("api", FindingDomainCode, nil, day2, FindingWeakness); err != nil {
		t.Fatal(err)
	}
	open := openFindings("api", FindingDomainCode)
	if len(open) != 1 || open[0].Kind != FindingWeakness {
		t.Fatalf("open = %+v: want the weakness kept and the CVE closed", open)
	}

	// Day three: it ran, and the weakness is gone for real.
	if _, err := reconcileFindings("api", FindingDomainCode, nil, day2.AddDate(0, 0, 1)); err != nil {
		t.Fatal(err)
	}
	if open := openFindings("api", FindingDomainCode); len(open) != 0 {
		t.Fatalf("open = %+v: want nothing", open)
	}
}

func TestSastSeverity(t *testing.T) {
	for in, want := range map[string]string{"ERROR": "HIGH", "warning": "MEDIUM", "INFO": "LOW", "HIGH": "HIGH", "": "UNKNOWN"} {
		if got := sastSeverity(in); got != want {
			t.Errorf("sastSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}
