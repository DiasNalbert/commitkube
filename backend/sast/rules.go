// Package sast holds CommitKube's own static-analysis rules for Opengrep.
//
// They are ours rather than the community's on purpose: the only ready-made
// set Opengrep has, opengrep-rules, is LGPL with the Commons Clause attached,
// and that clause forbids selling or hosting for a fee anything whose value
// comes substantially from the rules. A security scanner is exactly that. So
// the rules here are few, written for precision over coverage -- a SAST tab
// full of noise is a tab nobody reads -- and every one has a fixture under
// testdata that says what it must and must not match.
package sast

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

//go:embed rules/*.yaml
var rulesFS embed.FS

var (
	rulesOnce sync.Once
	rulesDir  string
	rulesErr  error
)

// RulesDir writes the embedded rules to disk once and returns the directory,
// which is what Opengrep's --config takes. The name carries a hash of the
// contents, so an upgrade never scans with a previous build's rules left in
// a shared temp directory.
func RulesDir() (string, error) {
	rulesOnce.Do(func() { rulesDir, rulesErr = writeRules(os.TempDir()) })
	return rulesDir, rulesErr
}

func writeRules(base string) (string, error) {
	files, err := fs.Glob(rulesFS, "rules/*.yaml")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	contents := make(map[string][]byte, len(files))
	for _, f := range files {
		b, err := rulesFS.ReadFile(f)
		if err != nil {
			return "", err
		}
		contents[filepath.Base(f)] = b
		fmt.Fprintf(h, "%s\x00%d\x00", f, len(b))
		h.Write(b)
	}
	dir := filepath.Join(base, "commitkube-sast-rules-"+hex.EncodeToString(h.Sum(nil))[:12])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for name, b := range contents {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return "", err
		}
	}
	return dir, nil
}
