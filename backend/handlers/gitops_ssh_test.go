package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"golang.org/x/crypto/ssh"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// gitSSHServer is a minimal Git host: it accepts one public key and serves
// git-upload-pack for repositories under root, which is all a clone or an
// ls-remote asks of it. The real ssh and git binaries talk to it, so the
// connection flow is exercised as it runs in production.
type gitSSHServer struct {
	addr string
	ln   net.Listener
}

func startGitSSHServer(t *testing.T, root string, authorized ssh.PublicKey) *gitSSHServer {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(authorized.Marshal()) {
			return nil, nil
		}
		return nil, fmt.Errorf("unknown key")
	}}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveGitSSH(conn, cfg, root)
		}
	}()
	return &gitSSHServer{addr: ln.Addr().String(), ln: ln}
}

func serveGitSSH(conn net.Conn, cfg *ssh.ServerConfig, root string) {
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range reqs {
				if req.Type != "exec" {
					req.Reply(req.Type == "env", nil)
					continue
				}
				n := binary.BigEndian.Uint32(req.Payload[:4])
				command := string(req.Payload[4 : 4+n])
				repo, ok := strings.CutPrefix(command, "git-upload-pack ")
				if !ok {
					req.Reply(false, nil)
					return
				}
				req.Reply(true, nil)
				repo = strings.Trim(repo, "'")
				cmd := exec.Command("git-upload-pack", filepath.Join(root, filepath.Clean("/"+repo)))
				cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
				status := 0
				if err := cmd.Run(); err != nil {
					status = 1
				}
				ch.CloseWrite()
				ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, uint32(status)))
				return
			}
		}()
	}
}

func TestConnectionOverRealSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not installed")
	}
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "gitops.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	gdb.AutoMigrate(&models.GitOpsRepo{})
	db.DB = gdb

	root := t.TempDir()
	src := writeRepo(t, map[string]string{"k8s/app.yaml": cmNamed("app")})
	for _, args := range [][]string{{"init", "-q", "-b", "trunk"}, {"add", "."}, {"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"},
		{"branch", "release"}, {"clone", "-q", "--bare", src, filepath.Join(root, "acme/shop.git")}} {
		if out, err := exec.Command("git", append([]string{"-C", src}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
	}

	r := models.GitOpsRepo{Name: "shop", Status: "pending"}
	if err := setRepoKey(&r, ""); err != nil {
		t.Fatal(err)
	}
	authorized, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(r.SSHPubKey))
	srv := startGitSSHServer(t, root, authorized)
	_, port, _ := net.SplitHostPort(srv.addr)
	r.URL = "ssh://git@127.0.0.1:" + port + "/acme/shop.git"
	if msg := validGitopsURL(r.URL); msg != "" {
		t.Fatal(msg)
	}
	gdb.Create(&r)

	// First contact: the key works, the host key gets pinned, HEAD is read.
	remote, err := testGitopsRepo(&r)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "connected" || remote.DefaultBranch != "trunk" || strings.Join(remote.Branches, ",") != "release,trunk" {
		t.Fatalf("status %s default %q branches %v", r.Status, remote.DefaultBranch, remote.Branches)
	}
	if r.KnownHosts == "" || !strings.HasPrefix(r.HostKey, "ssh-ed25519 SHA256:") {
		t.Fatalf("host key not pinned: %q", r.HostKey)
	}

	// Pinned: a clone works and renders.
	acc, err := connectionAccess(&r)
	if err != nil || !acc.pinned {
		t.Fatalf("access: %v pinned=%v", err, acc != nil && acc.pinned)
	}
	dir, _, cleanup, err := gitopsCheckout(acc, "release")
	acc.close()
	if err != nil {
		t.Fatal(err)
	}
	m, err := readManifests(filepath.Join(dir, "k8s"))
	cleanup()
	if err != nil || manifestNames(m) != "ConfigMap/app" {
		t.Fatalf("%s %v", manifestNames(m), err)
	}

	// Another server answering on the same address is refused, not trusted.
	srv.ln.Close()
	impostor := startGitSSHServer(t, root, authorized)
	_, newPort, _ := net.SplitHostPort(impostor.addr)
	r.URL = strings.Replace(r.URL, ":"+port+"/", ":"+newPort+"/", 1)
	r.KnownHosts = strings.Replace(r.KnownHosts, ":"+port+"]", ":"+newPort+"]", 1)
	if _, err := testGitopsRepo(&r); err == nil || !strings.Contains(err.Error(), "different host key") {
		t.Fatalf("changed host key: %v", err)
	}

	// A key the server does not know says what to do about it.
	r.KnownHosts = ""
	other, _ := generateRepoDeployKey("other")
	r.SSHPrivKey = crypto.EncryptField(crypto.MasterKey(), other.PrivateKey)
	if _, err := testGitopsRepo(&r); err == nil || !strings.Contains(err.Error(), "deploy key") {
		t.Fatalf("unknown key: %v", err)
	}
	if r.Status != "failed" {
		t.Fatalf("status %s after a failed test", r.Status)
	}
}
