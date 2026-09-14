package services

import "fmt"

type SCMProvider interface {
	CreateRepository(name, projectKey string) error
	RegisterWebhook(repoName, callbackURL, secret string) error
	AddDeployKey(repoName, pubKey, label string) error
	CommitFiles(repoName, message, branch string, files map[string]string) error
	CreateBranch(repoName, branchName, fromBranch string) error
	ListPipelines(repoName string) ([]byte, int, error)
	GetPipelineSteps(repoName, pipelineUUID string) ([]byte, error)
	GetStepLog(repoName, pipelineUUID, stepUUID string) ([]byte, error)
	ListSrc(repoName, filePath, branch string) ([]byte, int, string, error)
	ListBranches(repoName string) ([]byte, error)
	EnablePipelines(repoName string) error
	GetBranchHash(repoName, branch string) (string, error)
	AddRepoVariable(repoName, key, value string, secured bool) error
	CloneURL(workspace, repoName string) string
}

func NewSCMClient(provider, usernameOrToken, appPassOrEmpty, workspace string) SCMProvider {
	switch provider {
	case "github":
		return NewGithubClient(usernameOrToken, workspace)
	case "gitlab":
		return NewGitlabClient(usernameOrToken, workspace, "")
	default:
		return NewBitbucketClient(usernameOrToken, appPassOrEmpty, workspace)
	}
}

var _ SCMProvider = (*BitbucketClient)(nil)
var _ SCMProvider = (*GithubClient)(nil)
var _ SCMProvider = (*GitlabClient)(nil)

func errNotImplemented(provider, method string) error {
	return fmt.Errorf("%s: %s not yet implemented — provider is in preview", provider, method)
}
