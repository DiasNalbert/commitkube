package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/models"
	"golang.org/x/crypto/ssh"
)

// Every repository gets its own deploy key. One key shared across a whole
// workspace means one leaked key opens every repository at once, rotating it
// means touching all of them on the same day, and on providers that refuse to
// reuse a deploy key the second repository silently ends up with none -- and
// then ArgoCD cannot clone it.

// RepoDeployKey is what the person creating a repository is shown once, so
// they can keep a copy. CommitKube keeps the private half, encrypted, because
// it still has to clone the repository to scan it.
type RepoDeployKey struct {
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
	Fingerprint string `json:"fingerprint"`
}

// generateRepoDeployKey makes an ed25519 key pair in the formats Bitbucket
// (authorized_keys line) and ArgoCD / ssh (OpenSSH private key) expect.
func generateRepoDeployKey(repoName string) (RepoDeployKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return RepoDeployKey{}, fmt.Errorf("generate key: %w", err)
	}
	comment := "commitkube-" + repoName
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return RepoDeployKey{}, fmt.Errorf("encode private key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return RepoDeployKey{}, fmt.Errorf("encode public key: %w", err)
	}
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment
	return RepoDeployKey{
		PublicKey:   authorized,
		PrivateKey:  string(pem.EncodeToMemory(block)),
		Fingerprint: ssh.FingerprintSHA256(sshPub),
	}, nil
}

// repoCloneKey is the private key CommitKube clones a repository with: its own
// key when it has one, the workspace key for repositories created before
// per-repository keys existed.
func repoCloneKey(repo models.Repository, ws models.BitbucketWorkspace) string {
	if repo.SSHPrivKey != "" {
		if k := crypto.DecryptField(crypto.MasterKey(), repo.SSHPrivKey); k != "" {
			return k
		}
	}
	return crypto.DecryptField(crypto.MasterKey(), ws.SSHPrivKey)
}
