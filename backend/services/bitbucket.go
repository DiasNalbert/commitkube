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

	return http.DefaultClient.Do(req)
}

func (client *BitbucketClient) CreateRepository(repoName, projectKey string) error {
	path := fmt.Sprintf("repositories/%s/%s", client.Workspace, repoName)
	payload := map[string]interface{}{
		"scm":        "git",
		"is_private": true,
		"project": map[string]string{
			"key": projectKey,
		},
	}

	bodyBytes, _ := json.Marshal(payload)
	res, err := client.request("POST", path, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 && res.StatusCode != 409 {
		resBody, _ := io.ReadAll(res.Body)

		if res.StatusCode == 401 || res.StatusCode == 403 {
			return nil
		}

		return fmt.Errorf("HTTP %d: %s", res.StatusCode, string(resBody))
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
	path := fmt.Sprintf("repositories/%s/%s/src", client.Workspace, repoName)
	fullURL := fmt.Sprintf("https://api.bitbucket.org/2.0/%s", path)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("message", message)
	writer.WriteField("branch", branch)

	for filePath, content := range files {
		writer.WriteField(filePath, content)
	}
	writer.Close()

	req, _ := http.NewRequest("POST", fullURL, &buf)
	req.SetBasicAuth(strings.TrimSpace(client.Username), strings.TrimSpace(client.AppPass))
	req.Header.Add("Content-Type", writer.FormDataContentType())

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resBody, _ := io.ReadAll(res.Body)

	if res.StatusCode >= 400 {
		if strings.Contains(string(resBody), "nothing to commit") {
			return nil
		}
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, string(resBody))
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

func (client *BitbucketClient) EnablePipelines(repoName string) error {
	path := fmt.Sprintf("repositories/%s/%s/pipelines_config", client.Workspace, repoName)
	payload := map[string]interface{}{"enabled": true}
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

func (client *BitbucketClient) AddRepoVariable(repoName, key, value string, secured bool) error {
	path := fmt.Sprintf("repositories/%s/%s/pipelines_config/variables", client.Workspace, repoName)
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
