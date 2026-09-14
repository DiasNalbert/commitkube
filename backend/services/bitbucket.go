package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"text/template"
)

// bitbucketHTTPClient preserves the original HTTP method (POST) when following
// 301/302 redirects. Go's http.DefaultClient silently downgrades POST→GET on
// redirect, which causes collection endpoints to return empty GET responses
// instead of creating the resource.
var bitbucketHTTPClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		orig := via[0]
		req.Method = orig.Method
		if orig.GetBody != nil {
			body, err := orig.GetBody()
			if err != nil {
				return err
			}
			req.Body = body
		}
		for key, vals := range orig.Header {
			req.Header[key] = vals
		}
		return nil
	},
}

type BitbucketClient struct {
	Username  string
	AppPass   string
	Workspace string
}

func NewBitbucketClient(user, pass, workspace string) *BitbucketClient {
	return &BitbucketClient{
		Username:  user,
		AppPass:   pass,
		Workspace: workspace,
	}
}

func (client *BitbucketClient) request(method, path string, body io.Reader) (*http.Response, error) {
	url := fmt.Sprintf("https://api.bitbucket.org/2.0/%s", path)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	username := strings.TrimSpace(client.Username)
	appPass := strings.TrimSpace(client.AppPass)
	req.SetBasicAuth(username, appPass)

	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Add("Content-Type", "application/json")
	}

	return bitbucketHTTPClient.Do(req)
}

func (client *BitbucketClient) CreateRepository(repoName, projectKey string) error {
	path := fmt.Sprintf("repositories/%s/%s", client.Workspace, repoName)
	payload := map[string]interface{}{
		"scm":        "git",
		"is_private": true,
	}
	if projectKey != "" {
		payload["project"] = map[string]string{"key": projectKey}
	}

	bodyBytes, _ := json.Marshal(payload)
	res, err := client.request("POST", path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 && res.StatusCode != 409 {
		resBody, _ := io.ReadAll(res.Body)
		bodyStr := string(resBody)

		if res.StatusCode == 401 || res.StatusCode == 403 {
			fmt.Printf("WARNING: Bitbucket auth error (%d) creating repo %s — skipping creation\n", res.StatusCode, repoName)
			return nil
		}

		if strings.Contains(bodyStr, "already exists") || strings.Contains(bodyStr, "slug is already") {
			fmt.Printf("INFO: Bitbucket repo %s already exists, continuing\n", repoName)
			return nil
		}

		return fmt.Errorf("HTTP %d: %s", res.StatusCode, bodyStr)
	}

	return nil
}

func (client *BitbucketClient) RegisterWebhook(repoName, callbackURL, secret string) error {
	path := fmt.Sprintf("repositories/%s/%s/hooks", client.Workspace, repoName)
	payload := map[string]interface{}{
		"description": "CommitKube Security Scan",
		"url":         callbackURL,
		"active":      true,
		"secret":      secret,
		"events":      []string{"repo:push"},
	}
	bodyBytes, _ := json.Marshal(payload)
	res, err := client.request("POST", path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("webhook HTTP %d: %s", res.StatusCode, string(body))
	}
	return nil
}

func (client *BitbucketClient) AddDeployKey(repoName, pubKey, label string) error {
	// bitbucketHTTPClient preserves POST on any 301 redirect, so no trailing slash needed
	path := fmt.Sprintf("repositories/%s/%s/deploy-keys", client.Workspace, repoName)
	payload := map[string]interface{}{
		"key":   strings.TrimSpace(pubKey),
		"label": label,
	}
	bodyBytes, _ := json.Marshal(payload)
	res, err := client.request("POST", path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("deploy key request error: %w", err)
	}
	defer res.Body.Close()
	resBody, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		bodyStr := string(resBody)
		if strings.Contains(bodyStr, "already in use") || strings.Contains(bodyStr, "key is already") {
			fmt.Printf("Deploy key already exists for %s, skipping.\n", repoName)
			return nil
		}
		return fmt.Errorf("deploy key HTTP %d: %s", res.StatusCode, bodyStr)
	}
	return nil
}

type TemplateData struct {
	ProjectName string
}

func renderTemplate(tmplString string, data TemplateData) (string, error) {
	tmpl, err := template.New("tmpl").Parse(tmplString)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	return buf.String(), err
}

func (client *BitbucketClient) CommitFiles(repoName, message, branch string, files map[string]string) error {
	if branch == "" {
		branch = "main"
	}

	type kv struct{ k, v string }
	pairs := make([]kv, 0, len(files))
	for k, v := range files {
		pairs = append(pairs, kv{k, v})
	}

	const batchSize = 50
	for i := 0; i < len(pairs); i += batchSize {
		end := i + batchSize
		if end > len(pairs) {
			end = len(pairs)
		}
		batch := pairs[i:end]

		batchMsg := message
		if len(pairs) > batchSize {
			batchMsg = fmt.Sprintf("%s (%d/%d)", message, (i/batchSize)+1, (len(pairs)+batchSize-1)/batchSize)
		}

		path := fmt.Sprintf("repositories/%s/%s/src", client.Workspace, repoName)
		fullURL := fmt.Sprintf("https://api.bitbucket.org/2.0/%s", path)

		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		writer.WriteField("message", batchMsg)
		writer.WriteField("branch", branch)
		for _, p := range batch {
			writer.WriteField(p.k, p.v)
		}
		writer.Close()

		req, _ := http.NewRequest("POST", fullURL, &buf)
		req.SetBasicAuth(strings.TrimSpace(client.Username), strings.TrimSpace(client.AppPass))
		req.Header.Add("Content-Type", writer.FormDataContentType())

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		resBody, _ := io.ReadAll(res.Body)
		res.Body.Close()

		if res.StatusCode >= 400 {
			if strings.Contains(string(resBody), "nothing to commit") {
				continue
			}
			return fmt.Errorf("HTTP %d: %s", res.StatusCode, string(resBody))
		}
	}
	return nil
}

func (client *BitbucketClient) CreateBranch(repoName, branchName, fromBranch string) error {
	path := fmt.Sprintf("repositories/%s/%s/refs/branches", client.Workspace, repoName)
	payload := map[string]interface{}{
		"name": branchName,
		"target": map[string]string{
			"hash": fromBranch,
		},
	}
	bodyBytes, _ := json.Marshal(payload)
	res, err := client.request("POST", path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		resBody, _ := io.ReadAll(res.Body)
		return fmt.Errorf("create branch HTTP %d: %s", res.StatusCode, string(resBody))
	}
	return nil
}

func (client *BitbucketClient) ListPipelines(repoName string) ([]byte, int, error) {
	path := fmt.Sprintf("repositories/%s/%s/pipelines/?sort=-created_on&pagelen=20", client.Workspace, repoName)
	res, err := client.request("GET", path, nil)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return data, res.StatusCode, nil
}

func (client *BitbucketClient) GetPipelineSteps(repoName, pipelineUUID string) ([]byte, error) {
	path := fmt.Sprintf("repositories/%s/%s/pipelines/%s/steps/", client.Workspace, repoName, pipelineUUID)
	res, err := client.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)
}

func (client *BitbucketClient) GetStepLog(repoName, pipelineUUID, stepUUID string) ([]byte, error) {
	path := fmt.Sprintf("repositories/%s/%s/pipelines/%s/steps/%s/log", client.Workspace, repoName, pipelineUUID, stepUUID)
	res, err := client.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)
}

func (client *BitbucketClient) ListSrc(repoName, filePath, branch string) ([]byte, int, string, error) {
	ref := branch
	if ref == "" {
		ref = "HEAD"
	}
	apiPath := fmt.Sprintf("repositories/%s/%s/src/%s/%s", client.Workspace, repoName, ref, filePath)
	res, err := client.request("GET", apiPath, nil)
	if err != nil {
		return nil, 0, "", err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return data, res.StatusCode, res.Header.Get("Content-Type"), nil
}

func (client *BitbucketClient) ListBranches(repoName string) ([]byte, error) {
	path := fmt.Sprintf("repositories/%s/%s/refs/branches?pagelen=50", client.Workspace, repoName)
	res, err := client.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)
}

func (client *BitbucketClient) TriggerPipeline(repoName, branch string) ([]byte, error) {
	path := fmt.Sprintf("repositories/%s/%s/pipelines/", client.Workspace, repoName)
	payload := map[string]interface{}{
		"target": map[string]interface{}{
			"ref_type": "branch",
			"type":     "pipeline_ref_target",
			"ref_name": branch,
		},
	}
	bodyBytes, _ := json.Marshal(payload)
	res, err := client.request("POST", path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, string(data))
	}
	return data, nil
}

func (client *BitbucketClient) StopPipeline(repoName, pipelineUUID string) error {
	path := fmt.Sprintf("repositories/%s/%s/pipelines/%s/stopPipeline", client.Workspace, repoName, pipelineUUID)
	res, err := client.request("POST", path, bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		resBody, _ := io.ReadAll(res.Body)
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, string(resBody))
	}
	return nil
}

func (client *BitbucketClient) EnablePipelines(repoName string) error {
	path := fmt.Sprintf("repositories/%s/%s/pipelines_config", client.Workspace, repoName)
	payload := map[string]interface{}{
		"enabled": true,
		"type":    "repository_pipeline_settings",
	}
	bodyBytes, _ := json.Marshal(payload)
	res, err := client.request("PUT", path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		resBody, _ := io.ReadAll(res.Body)
		return fmt.Errorf("enable pipelines HTTP %d: %s", res.StatusCode, string(resBody))
	}
	return nil
}

func (client *BitbucketClient) GetBranchHash(repoName, branch string) (string, error) {
	path := fmt.Sprintf("repositories/%s/%s/refs/branches/%s", client.Workspace, repoName, branch)
	res, err := client.request("GET", path, nil)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var data struct {
		Target struct {
			Hash string `json:"hash"`
		} `json:"target"`
	}
	if err := json.NewDecoder(res.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Target.Hash, nil
}

func (client *BitbucketClient) DeleteRepository(repoName string) error {
	path := fmt.Sprintf("repositories/%s/%s", client.Workspace, repoName)
	res, err := client.request("DELETE", path, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 && res.StatusCode != 404 {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("delete repo HTTP %d: %s", res.StatusCode, string(body))
	}
	return nil
}

func (client *BitbucketClient) CloneURL(workspace, repoName string) string {
	ws := workspace
	if ws == "" {
		ws = client.Workspace
	}
	return "git@bitbucket.org:" + ws + "/" + repoName + ".git"
}

func (client *BitbucketClient) ListRepositoriesByProject(projectKey string) ([]string, error) {
	path := fmt.Sprintf("repositories/%s?pagelen=100&q=project.key%%3D%%22%s%%22", client.Workspace, projectKey)
	res, err := client.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, string(body))
	}
	var result struct {
		Values []struct {
			Slug string `json:"slug"`
		} `json:"values"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(result.Values))
	for _, v := range result.Values {
		names = append(names, v.Slug)
	}
	return names, nil
}

type CommitInfo struct {
	Hash      string `json:"hash"`
	Message   string `json:"message"`
	Author    string `json:"author"`
	Date      string `json:"date"`
	ShortHash string `json:"short_hash"`
}

func (client *BitbucketClient) GetRecentCommits(repoName, branch string, limit int) ([]CommitInfo, error) {
	if branch == "" {
		branch = "main"
	}
	if limit <= 0 {
		limit = 10
	}
	path := fmt.Sprintf("repositories/%s/%s/commits/%s?pagelen=%d", client.Workspace, repoName, branch, limit)
	res, err := client.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var result struct {
		Values []struct {
			Hash    string `json:"hash"`
			Message string `json:"message"`
			Date    string `json:"date"`
			Author  struct {
				Raw  string `json:"raw"`
				User struct {
					DisplayName string `json:"display_name"`
				} `json:"user"`
			} `json:"author"`
		} `json:"values"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}
	commits := make([]CommitInfo, 0, len(result.Values))
	for _, v := range result.Values {
		author := v.Author.Raw
		if v.Author.User.DisplayName != "" {
			author = v.Author.User.DisplayName
		}
		short := v.Hash
		if len(short) > 7 {
			short = short[:7]
		}
		commits = append(commits, CommitInfo{
			Hash:      v.Hash,
			ShortHash: short,
			Message:   strings.SplitN(v.Message, "\n", 2)[0],
			Author:    author,
			Date:      v.Date,
		})
	}
	return commits, nil
}

// --- repo-wide file fetching for Code Analyze ---

var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, "__pycache__": true,
	".next": true, "dist": true, "build": true, ".gradle": true, "target": true,
	".terraform": true, "venv": true, ".venv": true, "coverage": true,
}

var skipFiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"go.sum": true, "Gemfile.lock": true, "poetry.lock": true, "Pipfile.lock": true,
}

var codeExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".tsx": true, ".jsx": true,
	".java": true, ".kt": true, ".rb": true, ".php": true, ".rs": true,
	".c": true, ".cpp": true, ".h": true, ".hpp": true, ".cs": true, ".swift": true,
	".yaml": true, ".yml": true, ".json": true, ".toml": true, ".sh": true,
	".bash": true, ".tf": true, ".hcl": true, ".sql": true, ".graphql": true,
	".proto": true, ".xml": true, ".env": true,
}

const maxPerFileFetchBytes = 30_000

func fileBaseName(path string) string {
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func isCodeFile(name string) bool {
	lower := strings.ToLower(name)
	if lower == "dockerfile" || lower == "makefile" || lower == "jenkinsfile" || lower == ".env" {
		return true
	}
	idx := strings.LastIndex(name, ".")
	if idx < 0 || idx == len(name)-1 {
		return false
	}
	return codeExtensions[strings.ToLower(name[idx:])]
}

// FetchAllSrc walks the repository tree and returns a map of filepath → content
// for code files, respecting size limits and skipping non-code directories.
func (client *BitbucketClient) FetchAllSrc(repoName, branch string) (map[string]string, error) {
	files := make(map[string]string)
	client.fetchSrcRecursive(repoName, branch, "", files, 0)
	return files, nil
}

func (client *BitbucketClient) fetchSrcRecursive(repoName, branch, dirPath string, files map[string]string, depth int) {
	if depth > 8 {
		return
	}
	ref := branch
	if ref == "" {
		ref = "HEAD"
	}
	apiPath := fmt.Sprintf("repositories/%s/%s/src/%s/%s?pagelen=100", client.Workspace, repoName, ref, dirPath)
	res, err := client.request("GET", apiPath, nil)
	if err != nil {
		return
	}
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode >= 400 {
		return
	}

	var listing struct {
		Values []struct {
			Type string `json:"type"`
			Path string `json:"path"`
			Size int    `json:"size"`
		} `json:"values"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		return
	}

	for _, entry := range listing.Values {
		name := fileBaseName(entry.Path)
		if entry.Type == "commit_directory" {
			if skipDirs[name] {
				continue
			}
			client.fetchSrcRecursive(repoName, branch, entry.Path, files, depth+1)
		} else if entry.Type == "commit_file" {
			if skipFiles[name] || !isCodeFile(name) || entry.Size > maxPerFileFetchBytes {
				continue
			}
			content, status, _, fetchErr := client.ListSrc(repoName, entry.Path, branch)
			if fetchErr != nil || status >= 400 {
				continue
			}
			files[entry.Path] = string(content)
		}
	}
}

func (client *BitbucketClient) AddRepoVariable(repoName, key, value string, secured bool) error {
	// trailing slash required — Bitbucket returns 301 without it and Go re-issues as GET (no body)
	path := fmt.Sprintf("repositories/%s/%s/pipelines_config/variables/", client.Workspace, repoName)
	payload := map[string]interface{}{
		"key":     key,
		"value":   value,
		"secured": secured,
	}
	bodyBytes, _ := json.Marshal(payload)
	res, err := client.request("POST", path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		resBody, _ := io.ReadAll(res.Body)
		bodyStr := string(resBody)
		if strings.Contains(bodyStr, "already exists") {
			return nil
		}
		return fmt.Errorf("repo variable HTTP %d: %s", res.StatusCode, bodyStr)
	}
	return nil
}
