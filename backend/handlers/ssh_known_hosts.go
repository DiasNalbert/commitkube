package handlers

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"golang.org/x/crypto/ssh"
)

// Every SSH clone checks the server's host key. The big hosts publish
// theirs, so they are pinned here and a clone to them never trusts anything
// it is shown; any other host (a self-hosted GitLab, Bitbucket Data Center)
// is trusted on the first successful connection and pinned in the database
// from then on, the way ssh's own known_hosts works. Before this the scan
// clone ran with StrictHostKeyChecking=no, and the repositories CommitKube
// created were cloned with a fresh known_hosts every time -- either way,
// whoever answered on the address got the deploy key's signature and served
// the code that was scanned or deployed.
//
// Published at https://api.github.com/meta, https://bitbucket.org/site/ssh
// and in GitLab's documentation (fingerprints checked against the
// documented ones on 2026-10-28).
const scmKnownHosts = `github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=
bitbucket.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIazEu89wgQZ4bqs3d63QSMzYVa0MuJ2e2gKTKqu+UUO
bitbucket.org ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPIQmuzMBuKdWeF4+a2sjSSpBK0iqitSQ+5BM9KhpexuGt20JpTVM7u5BDZngncgrqDMbWdxMWWOGtZ9UgbqgZE=
bitbucket.org ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQeJzhupRu0u0cdegZIa8e86EG2qOCsIsD1Xw0xSeiPDlCr7kq97NLmMbpKTX6Esc30NuoqEEHCuc7yWtwp8dI76EEEB1VqY9QJq6vk+aySyboD5QF61I/1WeTwu+deCbgKMGbUijeXhtfbxSxm6JwGrXrhBdofTsbKRUsrN1WoNgUa8uqN1Vx6WAJw1JHPhglEGGHea6QICwJOAr/6mrui/oB7pkaWKHj3z7d1IC4KWLtY47elvjbaTlkN04Kc/5LFEirorGYVbt15kAUlqGM65pk6ZBxtaO3+30LVlORZkxOh+LKL/BvbZ/iRNhItLqNyieoQj/uh/7Iv4uyH/cV/0b4WDSd3DptigWq84lJubb9t/DnZlrJazxyDCulTmKdOR7vs9gMTo+uoIrPSb8ScTtvw65+odKAlBj59dhnVp9zd7QUojOpXlL62Aw56U4oO+FALuevvMjiWeavKhJqlR7i5n9srYcrNV7ttmDw7kf/97P5zauIhxcjX+xHv4M=
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf
gitlab.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=
gitlab.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9
`

var (
	scpHost = regexp.MustCompile(`^[^@/:]+@([^:/]+):`)
	sshHost = regexp.MustCompile(`^ssh://(?:[^@/]+@)?(\[[^\]]+\]|[^:/]+)(?::([0-9]+))?/`)
)

// knownHostsName is how a clone URL's server appears in known_hosts:
// "host", or "[host]:port" off the default port. Empty when the URL is not
// an SSH one.
func knownHostsName(url string) string {
	if m := scpHost.FindStringSubmatch(url); m != nil {
		return strings.ToLower(m[1])
	}
	if m := sshHost.FindStringSubmatch(url); m != nil {
		host := strings.ToLower(strings.Trim(m[1], "[]"))
		if m[2] != "" && m[2] != "22" {
			return "[" + host + "]:" + m[2]
		}
		return host
	}
	return ""
}

// pinnedKnownHosts is what the server at url must present: the published
// keys of a big host, or what was pinned at the first connection to any
// other. ok is false for a server never connected to before.
func pinnedKnownHosts(url string) (content string, ok bool) {
	name := knownHostsName(url)
	if name == "" {
		return "", false
	}
	var lines []string
	for _, l := range strings.Split(scmKnownHosts, "\n") {
		if strings.HasPrefix(l, name+" ") {
			lines = append(lines, l)
		}
	}
	if len(lines) > 0 {
		return strings.Join(lines, "\n") + "\n", true
	}
	var row models.SSHKnownHost
	if db.DB != nil && db.DB.Where("host = ?", name).First(&row).Error == nil && row.KnownHosts != "" {
		return row.KnownHosts, true
	}
	return "", false
}

// rememberKnownHosts pins what ssh accepted at a first connection. It never
// replaces a pin: a key that changed is refused by ssh before this runs,
// and replacing one is a decision for a person, not for a clone.
func rememberKnownHosts(url, content string) {
	name := knownHostsName(url)
	if name == "" || strings.TrimSpace(content) == "" {
		return
	}
	if _, ok := pinnedKnownHosts(url); ok {
		return
	}
	row := models.SSHKnownHost{Host: name, KnownHosts: content, Fingerprint: hostKeyFingerprint(content)}
	if err := db.DB.Create(&row).Error; err == nil {
		fmt.Printf("ssh: pinned host key of %s (%s)\n", name, row.Fingerprint)
	}
}

// newSCMAccess prepares a clone of url with key, checking the server against
// its pinned keys -- or, at the first connection to a host nobody pinned,
// accepting its key and pinning it once the clone succeeds (see pinIfNew).
func newSCMAccess(url, key string) (*gitopsRepoAccess, error) {
	keyFile, err := writeAccessKey(key)
	if err != nil {
		return nil, err
	}
	acc := &gitopsRepoAccess{url: url, keyFile: keyFile, knownHosts: keyFile + ".known_hosts", sshOnly: true, pinGlobally: true}
	if content, ok := pinnedKnownHosts(url); ok {
		if err := os.WriteFile(acc.knownHosts, []byte(content), 0600); err != nil {
			acc.close()
			return nil, fmt.Errorf("could not prepare known_hosts: %w", err)
		}
		acc.pinned = true
	}
	return acc, nil
}

// pinIfNew records the host key a first connection accepted. Call it only
// after the connection did what it was for.
func (a *gitopsRepoAccess) pinIfNew() {
	if a.pinned || !a.pinGlobally {
		return
	}
	if b, err := os.ReadFile(a.knownHosts); err == nil {
		rememberKnownHosts(a.url, string(b))
	}
}

// knownHostsKeys parses a known_hosts text, for tests and for display.
func knownHostsKeys(content string) []ssh.PublicKey {
	var keys []ssh.PublicKey
	rest := []byte(content)
	for len(rest) > 0 {
		_, _, k, _, r, err := ssh.ParseKnownHosts(rest)
		if err != nil {
			break
		}
		keys = append(keys, k)
		rest = r
	}
	return keys
}
