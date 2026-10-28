package handlers

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
	"golang.org/x/crypto/ssh"
)

// The source of a GitOps application is either a repository connected for
// GitOps (any SSH host, with a key of its own) or a repository CommitKube
// created, which already holds a deploy key and a workspace.

type gitopsRepoAccess struct {
	url        string
	keyFile    string
	knownHosts string
	// pinned: the host key is known, and any other key is refused. Unpinned,
	// the first key seen is accepted and written to knownHosts.
	pinned bool
	// sshOnly: refuse every transport but ssh, so a URL cannot reach for
	// ext:: or file:// on the server.
	sshOnly bool
	// pinGlobally: an unpinned host's key is pinned for every clone once
	// this one succeeds (see pinIfNew). Connected repositories pin their
	// own key on the connection instead.
	pinGlobally bool
}

func (a *gitopsRepoAccess) env() []string {
	check := "accept-new"
	if a.pinned {
		check = "yes"
	}
	env := append(os.Environ(),
		fmt.Sprintf("GIT_SSH_COMMAND=ssh -F /dev/null -i %s -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=%s -o UserKnownHostsFile=%s",
			a.keyFile, check, a.knownHosts),
		"GIT_TERMINAL_PROMPT=0",
	)
	if a.sshOnly {
		env = append(env, "GIT_ALLOW_PROTOCOL=ssh")
	}
	return env
}

func (a *gitopsRepoAccess) close() {
	os.Remove(a.keyFile)
	os.Remove(a.knownHosts)
}

// writeAccessKey puts a private key in a private temporary file, the way
// ssh -i wants it: LF line ends and a trailing newline.
func writeAccessKey(key string) (string, error) {
	key = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(key, `\n`, "\n"), "\r\n", "\n")) + "\n"
	if strings.TrimSpace(key) == "" {
		return "", fmt.Errorf("no SSH key")
	}
	f := filepath.Join(os.TempDir(), "gitops-key-"+uuid.New().String())
	if err := os.WriteFile(f, []byte(key), 0600); err != nil {
		return "", fmt.Errorf("could not prepare the key: %w", err)
	}
	return f, nil
}

// gitopsAccess is the access for a repository CommitKube created.
func gitopsAccess(repoName string) (*gitopsRepoAccess, error) {
	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return nil, fmt.Errorf("repository %s is not in CommitKube", repoName)
	}
	ws, err := resolveWorkspace(repo.UserID, repo.WorkspaceID)
	if err != nil {
		return nil, fmt.Errorf("repository %s has no workspace: %v", repoName, err)
	}
	provider := repo.Provider
	if provider == "" {
		provider = "bitbucket"
	}
	url := services.NewSCMClient(provider, ws.Username, "", ws.WorkspaceID).CloneURL(ws.WorkspaceID, repoName)
	acc, err := newSCMAccess(url, repoCloneKey(repo, ws))
	if err != nil {
		return nil, fmt.Errorf("repository %s: %v", repoName, err)
	}
	return acc, nil
}

// connectionAccess is the access for a connected repository.
func connectionAccess(r *models.GitOpsRepo) (*gitopsRepoAccess, error) {
	key := crypto.DecryptField(crypto.MasterKey(), r.SSHPrivKey)
	if key == "" {
		return nil, fmt.Errorf("repository %s has no usable SSH key", r.Name)
	}
	keyFile, err := writeAccessKey(key)
	if err != nil {
		return nil, err
	}
	acc := &gitopsRepoAccess{url: r.URL, keyFile: keyFile, knownHosts: keyFile + ".known_hosts", sshOnly: true}
	if r.KnownHosts != "" {
		if err := os.WriteFile(acc.knownHosts, []byte(r.KnownHosts), 0600); err != nil {
			acc.close()
			return nil, fmt.Errorf("could not prepare known_hosts: %w", err)
		}
		acc.pinned = true
	}
	return acc, nil
}

// appAccess is the access an application's source needs.
func appAccess(app *models.GitOpsApp) (*gitopsRepoAccess, error) {
	if app.GitOpsRepoID == nil {
		return gitopsAccess(app.RepoName)
	}
	var r models.GitOpsRepo
	if err := db.DB.First(&r, *app.GitOpsRepoID).Error; err != nil {
		return nil, fmt.Errorf("the repository connection of %s no longer exists", app.Name)
	}
	return connectionAccess(&r)
}

// ---- validating what people type ------------------------------------------------------

var (
	scpLikeURL = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]*@[A-Za-z0-9.][A-Za-z0-9.-]*:[^\s]+$`)
	sshURL     = regexp.MustCompile(`^ssh://([A-Za-z0-9._][A-Za-z0-9._-]*@)?[A-Za-z0-9.\[][A-Za-z0-9.:\]-]*(:[0-9]+)?/[^\s]+$`)
	branchName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]*$`)
)

// validGitopsURL accepts an SSH clone URL and nothing a shell or ssh could
// read as an option: the host can never start with a dash.
func validGitopsURL(u string) string {
	switch {
	case u == "":
		return "the SSH URL is required"
	case scpLikeURL.MatchString(u), sshURL.MatchString(u):
		return ""
	case strings.HasPrefix(u, "https://"), strings.HasPrefix(u, "http://"):
		return "use the repository's SSH URL (git@host:org/repo.git), not the HTTPS one"
	}
	return "not an SSH clone URL: expected git@host:org/repo.git or ssh://git@host/org/repo.git"
}

func validBranch(b string) bool {
	return branchName.MatchString(b) && !strings.Contains(b, "..") && !strings.HasSuffix(b, "/") && !strings.HasSuffix(b, ".lock")
}

// ---- keys -------------------------------------------------------------------------------

// importedKey checks a pasted private key and derives what is shown for it.
// A passphrase would have to be stored next to the key to be of any use, so
// a protected key is refused rather than stored with its passphrase.
func importedKey(priv string) (pub, fingerprint string, err error) {
	priv = strings.TrimSpace(strings.ReplaceAll(priv, "\r\n", "\n")) + "\n"
	signer, err := ssh.ParsePrivateKey([]byte(priv))
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			return "", "", fmt.Errorf("the key is protected by a passphrase; use a deploy key without one")
		}
		return "", "", fmt.Errorf("not an SSH private key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), ssh.FingerprintSHA256(signer.PublicKey()), nil
}

// hostKeyFingerprint names the first key in a known_hosts file.
func hostKeyFingerprint(knownHosts string) string {
	_, _, key, _, _, err := ssh.ParseKnownHosts([]byte(knownHosts))
	if err != nil {
		return ""
	}
	return key.Type() + " " + ssh.FingerprintSHA256(key)
}

// ---- talking to the remote -------------------------------------------------------------

type gitopsRemote struct {
	DefaultBranch string
	Branches      []string
	Heads         map[string]string
}

// gitopsLsRemote lists the remote's branches, and which one HEAD names,
// without cloning. When the host key was not pinned yet, the one ssh
// accepted comes back in knownHosts so the caller can pin it.
func gitopsLsRemote(acc *gitopsRepoAccess) (remote gitopsRemote, knownHosts string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--symref", acc.url, "HEAD", "refs/heads/*")
	cmd.Env = acc.env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return remote, "", fmt.Errorf("%s", explainGitError(string(out), err))
	}
	remote.Heads = map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "ref: refs/heads/") && strings.HasSuffix(line, "\tHEAD") {
			remote.DefaultBranch = strings.TrimSuffix(strings.TrimPrefix(line, "ref: refs/heads/"), "\tHEAD")
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) == 2 && strings.HasPrefix(f[1], "refs/heads/") {
			b := strings.TrimPrefix(f[1], "refs/heads/")
			remote.Heads[b] = f[0]
			remote.Branches = append(remote.Branches, b)
		}
	}
	sort.Strings(remote.Branches)
	if !acc.pinned {
		if b, err := os.ReadFile(acc.knownHosts); err == nil {
			knownHosts = string(b)
		}
	}
	return remote, knownHosts, nil
}

// explainGitError turns what ssh and git print into what to do about it.
func explainGitError(out string, err error) string {
	out = strings.TrimSpace(out)
	switch {
	case strings.Contains(out, "REMOTE HOST IDENTIFICATION HAS CHANGED"), strings.Contains(out, "Host key verification failed"):
		return "the server presented a different host key than the one pinned at the first connection. If the server really changed its key, forget the pinned key and test again; otherwise someone may be in the middle"
	case strings.Contains(out, "Permission denied (publickey)"):
		return "the server refused the key: add the public key as a deploy key (read access is enough) on the repository, then test again"
	case strings.Contains(out, "Could not resolve hostname"):
		return "the host name does not resolve from CommitKube: " + lastLine(out)
	case strings.Contains(out, "Connection timed out"), strings.Contains(out, "Connection refused"), strings.Contains(out, "No route to host"):
		return "CommitKube cannot reach the server on the SSH port: " + lastLine(out)
	case strings.Contains(out, "Repository not found"), strings.Contains(out, "does not appear to be a git repository"), strings.Contains(out, "not found"):
		return "the server has no repository at that path, or the key cannot see it: " + lastLine(out)
	}
	if out == "" {
		return err.Error()
	}
	return lastLine(out)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// gitopsCheckout clones one branch, shallow, and returns the directory, the
// commit it is at, and a cleanup function. Symlinks that point outside the
// checkout are removed: rendering follows them, and a repository must not
// be able to read the server's own files into a manifest.
func gitopsCheckout(acc *gitopsRepoAccess, branch string) (dir, revision string, cleanup func(), err error) {
	if !validBranch(branch) {
		return "", "", nil, fmt.Errorf("%q is not a branch name", branch)
	}
	dir, err = os.MkdirTemp("", "gitops-src-")
	if err != nil {
		return "", "", nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	clone := exec.CommandContext(ctx, "git", "clone", "--quiet", "--depth=1", "--single-branch", "--branch", branch, "--", acc.url, dir)
	clone.Env = acc.env()
	if out, err := clone.CombinedOutput(); err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("git clone: %s", explainGitError(string(out), err))
	}
	rev, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("git rev-parse: %v", err)
	}
	if err := dropEscapingSymlinks(dir); err != nil {
		cleanup()
		return "", "", nil, err
	}
	acc.pinIfNew()
	return dir, strings.TrimSpace(string(rev)), cleanup, nil
}

func dropEscapingSymlinks(root string) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		target, err := filepath.EvalSymlinks(p)
		if err != nil || (target != realRoot && !strings.HasPrefix(target, realRoot+string(filepath.Separator))) {
			return os.Remove(p)
		}
		return nil
	})
}

// ---- browsing a branch ------------------------------------------------------------------

type gitopsTreeEntry struct {
	Path string `json:"path"`
	Dir  bool   `json:"dir"`
	// Kind, for a directory, is what auto-detection would make of it:
	// kustomize, helm, directory (holds manifests) or "" (nothing to apply).
	Kind string `json:"kind,omitempty"`
}

const gitopsTreeLimit = 5000

// gitopsTree lists the directories and YAML files of a checkout, so a path
// can be picked instead of typed.
func gitopsTree(root string) ([]gitopsTreeEntry, bool) {
	var out []gitopsTreeEntry
	var charts []string
	truncated := false
	if detectSourceType(root) == SourceHelm {
		charts = append(charts, "")
	}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == root {
			return nil
		}
		if len(out) >= gitopsTreeLimit {
			truncated = true
			return filepath.SkipAll
		}
		rel := relPath(root, p)
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			kind := ""
			// Inside a chart, templates and subcharts only mean something
			// rendered with the chart; none is a source on its own.
			if !insideChart(charts, rel) {
				kind = detectSourceType(p)
			}
			if kind == SourceHelm {
				charts = append(charts, rel+"/")
			}
			out = append(out, gitopsTreeEntry{Path: rel, Dir: true, Kind: kind})
			return nil
		}
		if isYAML(d.Name()) {
			out = append(out, gitopsTreeEntry{Path: rel})
		}
		return nil
	})
	return out, truncated
}

func insideChart(charts []string, rel string) bool {
	for _, c := range charts {
		if strings.HasPrefix(rel+"/", c) {
			return true
		}
	}
	return false
}
