package handlers

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kubecommit/backend/sast"
)

// Trivy looks at what the code depends on and how it is configured. Nothing
// before this file looked at the code itself: an SQL query built from the
// request was invisible as long as the driver it went through had no CVE.
// Opengrep, with the rules in package sast, is that second look.

const (
	// sastJobs is per scan, and the scan queue already runs SCAN_WORKERS
	// scans at once, so this stays small.
	sastJobs = "2"
	// sastFileTimeout is per rule per file, in seconds; a file that hits it
	// is skipped and reported in errors, not fatal to the pass.
	sastFileTimeout = "30"
	// Generated and minified files over this size are not worth parsing.
	sastMaxTargetBytes = "1000000"
	sastPassTimeout    = 15 * time.Minute
)

// opengrepReport is the part of Opengrep's JSON output a finding is made of.
// Like TrivySecret it deliberately has no field for the matched lines: a
// rule that fires on a hardcoded password matched the password, and that
// text must not reach the database, the API or the email.
type opengrepReport struct {
	Results []opengrepResult `json:"results"`
}

type opengrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Metadata struct {
			CWE json.RawMessage `json:"cwe"` // a string or a list of them
		} `json:"metadata"`
	} `json:"extra"`
}

// errOpengrepMissing is what a pass returns where the binary is not
// installed -- a development machine, an image built before it was added.
var errOpengrepMissing = errors.New("opengrep is not installed")

// runSAST runs the CommitKube rules over a checked-out repository.
func runSAST(dir string) ([]finding, error) {
	if _, err := exec.LookPath("opengrep"); err != nil {
		return nil, errOpengrepMissing
	}
	rules, err := sast.RulesDir()
	if err != nil {
		return nil, fmt.Errorf("sast rules unavailable: %w", err)
	}
	reportFile := filepath.Join(os.TempDir(), "opengrep-report-"+uuid.New().String()+".json")
	defer os.Remove(reportFile)

	ctx, cancel := context.WithTimeout(context.Background(), sastPassTimeout)
	defer cancel()
	// Run from inside the checkout with "." as the target, so every path in
	// the report is relative to the repository root -- the same form Trivy
	// reports its targets in.
	cmd := exec.CommandContext(ctx, "opengrep", "scan",
		"--config", rules,
		"--json", "--output", reportFile,
		"--jobs", sastJobs,
		"--timeout", sastFileTimeout,
		"--max-target-bytes", sastMaxTargetBytes,
		"--quiet",
		".",
	)
	cmd.Dir = dir
	cmd.Env = sastEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("opengrep did not finish within %s", sastPassTimeout)
		}
		return nil, fmt.Errorf("opengrep failed: %s", strings.TrimSpace(lastLines(string(out), 5)))
	}
	raw, err := os.ReadFile(reportFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read opengrep report: %w", err)
	}
	return findingsFromOpengrep(raw, dir)
}

// findingsFromOpengrep turns a report into rows. Each row's package is a
// fingerprint of the rule, the file and the code on the matched line, so a
// weakness keeps its identity -- its first-seen date, its suppression -- when
// lines are added above it, and only becomes a new finding when the code
// that triggered it changes.
func findingsFromOpengrep(raw []byte, root string) ([]finding, error) {
	var report opengrepReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("failed to parse opengrep report: %w", err)
	}
	lines := sourceLines{root: root, files: map[string][]string{}}
	occurrences := map[string]int{}
	out := make([]finding, 0, len(report.Results))
	for _, r := range report.Results {
		rule := ruleName(r.CheckID)
		path := reportPath(r.Path, root)
		fp := weaknessFingerprint(rule, path, lines.at(path, r.Start.Line))
		// The same code twice in one file is two findings; the second gets
		// a suffix so the two do not collapse into one.
		occurrences[path+"\x00"+fp]++
		if n := occurrences[path+"\x00"+fp]; n > 1 {
			fp = fmt.Sprintf("%s-%d", fp, n)
		}
		out = append(out, finding{
			Domain: FindingDomainCode, Kind: FindingWeakness, Target: path,
			VulnID: rule, Pkg: fp, Line: r.Start.Line,
			Severity: sastSeverity(r.Extra.Severity), Title: strings.TrimSpace(r.Extra.Message),
			CWE: firstCWE(r.Extra.Metadata.CWE),
		})
	}
	return out, nil
}

// ruleName drops the namespace Opengrep puts in front of a rule's id, which
// is derived from where the rules file sat on disk -- a temp directory whose
// name changes with every build.
func ruleName(checkID string) string {
	if i := strings.LastIndex(checkID, "."); i >= 0 {
		return checkID[i+1:]
	}
	return checkID
}

func reportPath(p, root string) string {
	if filepath.IsAbs(p) {
		if rel, err := filepath.Rel(root, p); err == nil {
			p = rel
		}
	}
	return filepath.ToSlash(strings.TrimPrefix(p, "./"))
}

// sastSeverity maps Opengrep's three levels onto the four columns. Nothing
// static analysis finds is CRITICAL: a pattern match is a strong suspicion,
// not a known-exploitable CVE, and CRITICAL is what pages people.
func sastSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return "HIGH"
	case "WARNING":
		return "MEDIUM"
	case "INFO":
		return "LOW"
	}
	return normalizeSeverity(s)
}

var cweRE = regexp.MustCompile(`CWE-\d+`)

func firstCWE(raw json.RawMessage) string {
	return cweRE.FindString(string(raw))
}

var spaceRE = regexp.MustCompile(`\s+`)

// weaknessFingerprint hashes what makes a weakness this weakness. The code is
// whitespace-normalized so reindenting it does not make a new finding, and
// only the hash is kept: the line may hold a credential.
func weaknessFingerprint(rule, path, code string) string {
	code = spaceRE.ReplaceAllString(strings.TrimSpace(code), " ")
	sum := sha256.Sum256([]byte(rule + "\x00" + path + "\x00" + code))
	return hex.EncodeToString(sum[:])[:16]
}

// sourceLines reads each reported file once.
type sourceLines struct {
	root  string
	files map[string][]string
}

func (s sourceLines) at(path string, line int) string {
	lines, ok := s.files[path]
	if !ok {
		lines = readLines(s.root, path)
		s.files[path] = lines
	}
	if line < 1 || line > len(lines) {
		return ""
	}
	return lines[line-1]
}

func readLines(root, path string) []string {
	full := filepath.Join(root, filepath.FromSlash(path))
	// The path came out of a report about an untrusted repository; it is
	// only ever hashed, but there is no reason to read outside the checkout.
	if rel, err := filepath.Rel(root, full); err != nil || strings.HasPrefix(rel, "..") {
		return nil
	}
	f, err := os.Open(full)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
