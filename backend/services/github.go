package services

import "fmt"

type GithubClient struct {
	Token string
	Owner string // GitHub org or user
}

func NewGithubClient(token, owner string) *GithubClient {
	return &GithubClient{Token: token, Owner: owner}
}

func (g *GithubClient) CloneURL(_, repoName string) string {
	return fmt.Sprintf("git@github.com:%s/%s.git", g.Owner, repoName)
}

func (g *GithubClient) CreateRepository(name, _ string) error {
	return errNotImplemented("github", "CreateRepository")
}

func (g *GithubClient) RegisterWebhook(repoName, callbackURL, secret string) error {
	return errNotImplemented("github", "RegisterWebhook")
}

func (g *GithubClient) AddDeployKey(repoName, pubKey, label string) error {
	return errNotImplemented("github", "AddDeployKey")
}

func (g *GithubClient) CommitFiles(repoName, message, branch string, files map[string]string) error {
	return errNotImplemented("github", "CommitFiles")
}

func (g *GithubClient) CreateBranch(repoName, branchName, fromBranch string) error {
	return errNotImplemented("github", "CreateBranch")
}

func (g *GithubClient) ListPipelines(repoName string) ([]byte, int, error) {
	return nil, 501, errNotImplemented("github", "ListPipelines")
}

func (g *GithubClient) GetPipelineSteps(repoName, pipelineUUID string) ([]byte, error) {
	return nil, errNotImplemented("github", "GetPipelineSteps")
}

func (g *GithubClient) GetStepLog(repoName, pipelineUUID, stepUUID string) ([]byte, error) {
	return nil, errNotImplemented("github", "GetStepLog")
}

func (g *GithubClient) ListSrc(repoName, filePath, branch string) ([]byte, int, string, error) {
	return nil, 501, "", errNotImplemented("github", "ListSrc")
}

func (g *GithubClient) ListBranches(repoName string) ([]byte, error) {
	return nil, errNotImplemented("github", "ListBranches")
}

func (g *GithubClient) EnablePipelines(repoName string) error {
	return nil // GitHub Actions are always available
}

func (g *GithubClient) GetBranchHash(repoName, branch string) (string, error) {
	return "", errNotImplemented("github", "GetBranchHash")
}

func (g *GithubClient) AddRepoVariable(repoName, key, value string, secured bool) error {
	return errNotImplemented("github", "AddRepoVariable")
}
