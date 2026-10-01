package handlers

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateRepoDeployKeyRoundTrips(t *testing.T) {
	k, err := generateRepoDeployKey("my-repo")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(k.PrivateKey))
	if err != nil {
		t.Fatalf("private key does not parse as OpenSSH: %v", err)
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(k.PublicKey))
	if err != nil {
		t.Fatalf("public key does not parse: %v", err)
	}
	if string(pub.Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Fatal("public key does not belong to the private key")
	}
	if comment != "commitkube-my-repo" || !strings.HasPrefix(k.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("unexpected public key %q", k.PublicKey)
	}
	if k.Fingerprint != ssh.FingerprintSHA256(pub) {
		t.Fatal("fingerprint mismatch")
	}

	other, _ := generateRepoDeployKey("my-repo")
	if other.PublicKey == k.PublicKey {
		t.Fatal("two repositories got the same key")
	}
}
