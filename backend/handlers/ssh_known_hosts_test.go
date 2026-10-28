package handlers

import (
	"net"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"golang.org/x/crypto/ssh"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestKnownHostsName(t *testing.T) {
	for url, want := range map[string]string{
		"git@bitbucket.org:acme/shop.git":            "bitbucket.org",
		"git@GitHub.com:acme/shop.git":               "github.com",
		"ssh://git@gitlab.example.com/acme/shop.git": "gitlab.example.com",
		"ssh://git@git.example.com:2222/a/b.git":     "[git.example.com]:2222",
		"ssh://git@git.example.com:22/a/b.git":       "git.example.com",
		"https://github.com/acme/shop.git":           "",
	} {
		if got := knownHostsName(url); got != want {
			t.Errorf("%s: %q, want %q", url, got, want)
		}
	}
}

// The built-in keys are long base64 strings typed into source; a slip in
// one would refuse every clone from that host. These are the fingerprints
// each provider documents.
func TestBuiltInHostKeysMatchThePublishedFingerprints(t *testing.T) {
	want := map[string][]string{
		"github.com":    {"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM", "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s"},
		"bitbucket.org": {"SHA256:ybgmFkzwOSotHTHLJgHO0QN8L0xErw6vd0VhFA9m3SM", "SHA256:FC73VB6C4OQLSCrjEayhMp9UMxS97caD/Yyi2bhW/J0", "SHA256:46OSHA1Rmj8E8ERTC6xkNcmGOw9oFxYr0WF6zWW8l1E"},
		"gitlab.com":    {"SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8", "SHA256:HbW3g8zUjNSksFbqTiUWPWg2Bq1x8xdGUrliXFzSnUw", "SHA256:ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ"},
	}
	for host, fps := range want {
		content, ok := pinnedKnownHosts("git@" + host + ":a/b.git")
		if !ok {
			t.Fatalf("%s is not built in", host)
		}
		var got []string
		for _, k := range knownHostsKeys(content) {
			got = append(got, ssh.FingerprintSHA256(k))
		}
		sort.Strings(got)
		sort.Strings(fps)
		if strings.Join(got, ",") != strings.Join(fps, ",") {
			t.Errorf("%s: %v, want %v", host, got, fps)
		}
	}
}

// A host nobody pinned is trusted on the first clone and pinned for every
// later one; a server answering later with another key is refused.
func TestFirstCloneToAHostPinsItsKey(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not installed")
	}
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "kh.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	gdb.AutoMigrate(&models.SSHKnownHost{})
	db.DB = gdb

	root := t.TempDir()
	src := writeRepo(t, map[string]string{"app.yaml": cmNamed("app")})
	for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"add", "."}, {"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"},
		{"clone", "-q", "--bare", src, filepath.Join(root, "acme/shop.git")}} {
		if out, err := exec.Command("git", append([]string{"-C", src}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
	}
	key, _ := generateRepoDeployKey("t")
	authorized, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(key.PublicKey))
	srv := startGitSSHServer(t, root, authorized)
	_, port, _ := net.SplitHostPort(srv.addr)
	url := "ssh://git@127.0.0.1:" + port + "/acme/shop.git"

	clone := func() error {
		acc, err := newSCMAccess(url, key.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		defer acc.close()
		_, _, cleanup, err := gitopsCheckout(acc, "main")
		if err == nil {
			cleanup()
		}
		return err
	}
	if err := clone(); err != nil {
		t.Fatalf("first clone: %v", err)
	}
	var row models.SSHKnownHost
	if gdb.First(&row).Error != nil || row.Host != "[127.0.0.1]:"+port || !strings.HasPrefix(row.Fingerprint, "ssh-ed25519 SHA256:") {
		t.Fatalf("not pinned: %+v", row)
	}
	if err := clone(); err != nil {
		t.Fatalf("clone against the pinned key: %v", err)
	}

	// Same address, another server with another host key.
	srv.ln.Close()
	impostor := startGitSSHServerOn(t, srv.addr, root, authorized)
	_ = impostor
	if err := clone(); err == nil || !strings.Contains(err.Error(), "different host key") {
		t.Fatalf("impostor accepted: %v", err)
	}
}
