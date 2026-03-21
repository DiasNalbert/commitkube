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

func (client *BitbucketClient) ListPipelines(repoName string) ([]byte, error) {
	path := fmt.Sprintf("repositories/%s/%s/pipelines/?sort=-created_on&pagelen=20", client.Workspace, repoName)
	res, err := client.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)
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

func (client *BitbucketClient) ListSrc(repoName, filePath string) ([]byte, int, string, error) {
	apiPath := fmt.Sprintf("repositories/%s/%s/src/HEAD/%s", client.Workspace, repoName, filePath)
	res, err := client.request("GET", apiPath, nil)
	if err != nil {
		return nil, 0, "", err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return data, res.StatusCode, res.Header.Get("Content-Type"), nil
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
