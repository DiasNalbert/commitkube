package handlers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

// The source of a GitOps application is a repository CommitKube already
// knows: it holds the deploy key and the workspace it belongs to, so there
// is no second set of credentials to configure.

type gitopsRepoAccess struct {
	url     string
	keyFile string
}

func (a *gitopsRepoAccess) env() []string {
	return append(os.Environ(),
		fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s", a.keyFile, a.keyFile+".known_hosts"),
		"GIT_TERMINAL_PROMPT=0",
	)
}

func (a *gitopsRepoAccess) close() {
	os.Remove(a.keyFile)
	os.Remove(a.keyFile + ".known_hosts")
}

// gitopsAccess writes the repository's key to a private temporary file and
// works out its clone URL. close() removes the key.
func gitopsAccess(repoName string) (*gitopsRepoAccess, error) {
	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return nil, fmt.Errorf("repository %s is not in CommitKube", repoName)
	}
	ws, err := resolveWorkspace(repo.UserID, repo.WorkspaceID)
	if err != nil {
		return nil, fmt.Errorf("repository %s has no workspace: %v", repoName, err)
	}
	key := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(repoCloneKey(repo, ws), `\n`, "\n"), "\r\n", "\n")) + "\n"
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("repository %s has no deploy key", repoName)
	}
	keyFile := filepath.Join(os.TempDir(), "gitops-key-"+uuid.New().String())
	if err := os.WriteFile(keyFile, []byte(key), 0600); err != nil {
		return nil, fmt.Errorf("could not prepare the key: %w", err)
	}
	provider := repo.Provider
	if provider == "" {
		provider = "bitbucket"
	}
	url := services.NewSCMClient(provider, ws.Username, "", ws.WorkspaceID).CloneURL(ws.WorkspaceID, repoName)
	return &gitopsRepoAccess{url: url, keyFile: keyFile}, nil
}

// gitopsHeadRevision asks the remote which commit a branch points at,
// without cloning: the loop runs this every few minutes for every app.
func gitopsHeadRevision(repoName, branch string) (string, error) {
	acc, err := gitopsAccess(repoName)
	if err != nil {
		return "", err
	}
	defer acc.close()
	cmd := exec.Command("git", "ls-remote", acc.url, "refs/heads/"+branch)
	cmd.Env = acc.env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git ls-remote: %s", strings.TrimSpace(string(out)))
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", fmt.Errorf("branch %s does not exist in %s", branch, repoName)
	}
	return fields[0], nil
}

// gitopsCheckout clones one branch, shallow, and returns the directory, the
// commit it is at, and a cleanup function.
func gitopsCheckout(repoName, branch string) (dir, revision string, cleanup func(), err error) {
	acc, err := gitopsAccess(repoName)
	if err != nil {
		return "", "", nil, err
	}
	defer acc.close()
	dir, err = os.MkdirTemp("", "gitops-src-")
	if err != nil {
		return "", "", nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }
	clone := exec.Command("git", "clone", "--quiet", "--depth=1", "--branch", branch, acc.url, dir)
	clone.Env = acc.env()
	if out, err := clone.CombinedOutput(); err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("git clone: %s", strings.TrimSpace(string(out)))
	}
	rev, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("git rev-parse: %v", err)
	}
	return dir, strings.TrimSpace(string(rev)), cleanup, nil
}
