package handlers

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// A repository is connected long before anything it builds reaches the cluster,
// and the image scan reads the image off a running workload -- so a freshly
// connected repository has no container findings at all until someone deploys
// it. Reading the Dockerfile closes that gap: the base image it declares is
// where the overwhelming majority of image CVEs live, and pulling that base is
// cheap and, unlike building, runs none of the repository's own instructions.

var (
	fromRe = regexp.MustCompile(`(?i)^\s*FROM\s+(.+?)\s*$`)
	argRe  = regexp.MustCompile(`(?i)^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$`)
)

// findDockerfiles returns the Dockerfiles in a checkout, nearest the root
// first: a repository with both a root Dockerfile and one under a sample or
// test directory means the root one.
func findDockerfiles(root string) []string {
	var found []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// Vendored trees carry Dockerfiles that belong to someone else.
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile.") ||
			strings.HasSuffix(strings.ToLower(name), ".dockerfile") {
			found = append(found, path)
		}
		return nil
	})

	sort.Slice(found, func(i, j int) bool {
		di := strings.Count(found[i], string(os.PathSeparator))
		dj := strings.Count(found[j], string(os.PathSeparator))
		if di != dj {
			return di < dj
		}
		return found[i] < found[j]
	})
	return found
}

// baseImageFromDockerfile resolves the image the final stage actually starts
// from. Multi-stage builds are the normal case, and only the last stage ships:
// a builder stage on golang:1.22 tells you nothing about what runs in
// production. Stage aliases are followed back until an external image is
// reached, and build ARGs with defaults are substituted the way docker does.
func baseImageFromDockerfile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	args := map[string]string{}
	stages := map[string]string{} // alias -> image (or another alias)
	var order []string            // every FROM target, in file order

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if m := argRe.FindStringSubmatch(line); m != nil {
			args[m[1]] = strings.Trim(m[2], `"'`)
			continue
		}

		m := fromRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		fields := strings.Fields(m[1])
		if len(fields) == 0 {
			continue
		}
		// FROM [--platform=...] <image> [AS <stage>]
		i := 0
		for i < len(fields) && strings.HasPrefix(fields[i], "--") {
			i++
		}
		if i >= len(fields) {
			continue
		}
		image := expandArgs(fields[i], args)
		alias := ""
		if len(fields) >= i+3 && strings.EqualFold(fields[i+1], "AS") {
			alias = fields[i+2]
		}
		if alias != "" {
			stages[strings.ToLower(alias)] = image
		}
		order = append(order, image)
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if len(order) == 0 {
		return "", fmt.Errorf("no FROM instruction in %s", filepath.Base(path))
	}

	// Walk back from the last stage through any alias references.
	image := order[len(order)-1]
	for range order {
		next, ok := stages[strings.ToLower(image)]
		if !ok || next == image {
			break
		}
		image = next
	}

	if strings.EqualFold(image, "scratch") {
		return "", fmt.Errorf("final stage is scratch: nothing to scan")
	}
	if strings.Contains(image, "$") {
		return "", fmt.Errorf("base image %q depends on a build argument with no default", image)
	}
	return image, nil
}

// expandArgs substitutes ${NAME} and $NAME using the ARG defaults declared
// above the FROM, which is the only value available without a real build.
func expandArgs(s string, args map[string]string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	for k, v := range args {
		s = strings.ReplaceAll(s, "${"+k+"}", v)
		s = strings.ReplaceAll(s, "$"+k, v)
	}
	return s
}

// resolveBaseImage picks the first Dockerfile in a checkout whose final stage
// resolves to a real image, and says which file it came from.
func resolveBaseImage(root string) (image string, dockerfile string, err error) {
	files := findDockerfiles(root)
	if len(files) == 0 {
		return "", "", fmt.Errorf("no Dockerfile in the repository")
	}
	var lastErr error
	for _, f := range files {
		img, e := baseImageFromDockerfile(f)
		if e == nil {
			rel, _ := filepath.Rel(root, f)
			return img, rel, nil
		}
		lastErr = e
	}
	rel, _ := filepath.Rel(root, files[0])
	return "", rel, lastErr
}
