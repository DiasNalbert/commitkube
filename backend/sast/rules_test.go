package sast

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Every rules file is written, and nothing else.
func TestWriteRules(t *testing.T) {
	dir, err := writeRules(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want, _ := fs.Glob(rulesFS, "rules/*.yaml")
	got, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(want) == 0 || len(got) != len(want) {
		t.Fatalf("wrote %d files, embedded %d", len(got), len(want))
	}
	again, err := writeRules(filepath.Dir(dir))
	if err != nil || again != dir {
		t.Fatalf("same rules gave a different directory: %q vs %q (%v)", again, dir, err)
	}
}

// Each rules file has a fixture of the same name in testdata, annotated with
// "ruleid:" above every line a rule must match and "ok:" above every line it
// must not. Opengrep's test mode checks both. Skipped where Opengrep is not
// installed; the image has it.
func TestRulesAgainstFixtures(t *testing.T) {
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("opengrep not installed")
	}
	rules, _ := filepath.Abs("rules")
	fixtures, _ := filepath.Abs("testdata")
	for _, f := range mustGlob(t, "rules/*.yaml") {
		stem := strings.TrimSuffix(filepath.Base(f), ".yaml")
		if len(mustGlob(t, filepath.Join("testdata", stem+".*"))) == 0 {
			t.Errorf("%s has no fixture in testdata", f)
		}
	}
	cmd := exec.Command("opengrep", "scan", "--test", "--config", rules, fixtures)
	cmd.Env = append(os.Environ(), "SEMGREP_ENABLE_VERSION_CHECK=0", "SEMGREP_SEND_METRICS=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rule tests failed: %v\n%s", err, out)
	}
}

func mustGlob(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
