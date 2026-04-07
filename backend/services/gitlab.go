package services

import "fmt"

// GitlabClient is a preview stub for GitLab SCM support.
// All mutating operations return errNotImplemented until fully implemented.
type GitlabClient struct {
	Token     string
	Namespace string // GitLab group or user
	BaseURL   string // e.g. "https://gitlab.com" or self-hosted URL
}

func NewGitlabClient(token, namespace, baseURL string) *GitlabClient {
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	return &GitlabClient{Token: token, Namespace: namespace, BaseURL: baseURL}
}

func (g *GitlabClient) CloneURL(_, repoName string) string {
	host := "gitlab.com"
	if g.BaseURL != "" && g.BaseURL != "https://gitlab.com" {
		host = g.BaseURL
	}
	return fmt.Sprintf("git@%s:%s/%s.git", host, g.Namespace, repoName)
}

func (g *GitlabClient) CreateRepository(name, _ string) error {
	return errNotImplemented("gitlab", "CreateRepository")
}

func (g *GitlabClient) RegisterWebhook(repoName, callbackURL, secret string) error {
	return errNotImplemented("gitlab", "RegisterWebhook")
}

func (g *GitlabClient) AddDeployKey(repoName, pubKey, label string) error {
	return errNotImplemented("gitlab", "AddDeployKey")
}

func (g *GitlabClient) CommitFiles(repoName, message, branch string, files map[string]string) error {
	return errNotImplemented("gitlab", "CommitFiles")
}

func (g *GitlabClient) CreateBranch(repoName, branchName, fromBranch string) error {
	return errNotImplemented("gitlab", "CreateBranch")
}

func (g *GitlabClient) ListPipelines(repoName string) ([]byte, int, error) {
	return nil, 501, errNotImplemented("gitlab", "ListPipelines")
}

func (g *GitlabClient) GetPipelineSteps(repoName, pipelineUUID string) ([]byte, error) {
	return nil, errNotImplemented("gitlab", "GetPipelineSteps")
}

func (g *GitlabClient) GetStepLog(repoName, pipelineUUID, stepUUID string) ([]byte, error) {
	return nil, errNotImplemented("gitlab", "GetStepLog")
}

func (g *GitlabClient) ListSrc(repoName, filePath, branch string) ([]byte, int, string, error) {
	return nil, 501, "", errNotImplemented("gitlab", "ListSrc")
}

func (g *GitlabClient) ListBranches(repoName string) ([]byte, error) {
	return nil, errNotImplemented("gitlab", "ListBranches")
}

func (g *GitlabClient) EnablePipelines(repoName string) error {
	return nil // GitLab CI is enabled by default
}

func (g *GitlabClient) GetBranchHash(repoName, branch string) (string, error) {
	return "", errNotImplemented("gitlab", "GetBranchHash")
}

func (g *GitlabClient) AddRepoVariable(repoName, key, value string, secured bool) error {
	return errNotImplemented("gitlab", "AddRepoVariable")
}
