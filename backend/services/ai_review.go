package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type ReviewFinding struct {
	Severity    string `json:"severity"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Snippet     string `json:"snippet,omitempty"` // problematic code as-is
	Fix         string `json:"fix,omitempty"`     // corrected version
}

type ReviewResult struct {
	Security      []ReviewFinding `json:"security"`
	Performance   []ReviewFinding `json:"performance"`
	BestPractices []ReviewFinding `json:"best_practices"`
}

const maxReviewBytes = 80_000 // ~20k tokens — stay well within claude-haiku context

func ReviewCode(filename, content string) (*ReviewResult, error) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not configured on the server")
	}
	if len(content) > maxReviewBytes {
		return nil, fmt.Errorf("file is too large to review (%d KB). Maximum supported size is %d KB", len(content)/1024, maxReviewBytes/1024)
	}

	model := os.Getenv("ANTHROPIC_REVIEW_MODEL")
	if model == "" {
		model = "claude-haiku-4-5-20251001"
	}

	prompt := fmt.Sprintf(`You are a code review assistant. Analyze the following file and provide actionable improvement suggestions.

File: %s

`+"```"+`
%s
`+"```"+`

Return ONLY a valid JSON object (no markdown fences, no extra text) with this exact structure:
{
  "security": [{"severity": "high|medium|low", "title": "short title", "description": "detailed explanation and how to fix"}],
  "performance": [{"severity": "high|medium|low", "title": "short title", "description": "detailed explanation and how to fix"}],
  "best_practices": [{"severity": "high|medium|low", "title": "short title", "description": "detailed explanation and how to fix"}]
}

Rules:
- Only include real issues found in the code above
- If a category has no issues, return an empty array for it
- Keep descriptions concise and actionable (2-3 sentences max)
- Maximum 5 findings per category
- All text must be in English`, filename, content)

	body, _ := json.Marshal(map[string]interface{}{
		"model":      model,
		"max_tokens": 2048,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Anthropic API: %w", err)
	}
	defer res.Body.Close()

	respBody, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		// Detect context-window exceeded so the UI can show a friendly message
		bodyStr := string(respBody)
		if strings.Contains(bodyStr, "context_length") || strings.Contains(bodyStr, "too long") || strings.Contains(bodyStr, "max_tokens") {
			return nil, fmt.Errorf("file is too large to review — try a smaller file or section")
		}
		return nil, fmt.Errorf("Anthropic API error %d: %s", res.StatusCode, bodyStr)
	}

	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}
	if len(apiResp.Content) == 0 {
		return nil, fmt.Errorf("empty response from Anthropic API")
	}

	text := strings.TrimSpace(apiResp.Content[0].Text)
	// Strip markdown code fences if the model wrapped the JSON anyway
	if strings.HasPrefix(text, "```") {
		lines := strings.Split(text, "\n")
		if len(lines) > 2 {
			text = strings.Join(lines[1:len(lines)-1], "\n")
		}
	}

	var result ReviewResult
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		return nil, fmt.Errorf("failed to parse review JSON: %w", err)
	}

	if result.Security == nil {
		result.Security = []ReviewFinding{}
	}
	if result.Performance == nil {
		result.Performance = []ReviewFinding{}
	}
	if result.BestPractices == nil {
		result.BestPractices = []ReviewFinding{}
	}

	return &result, nil
}

const maxRepoAnalyzeBytes = 100_000 // ~25k tokens for full-repo scan

// AnalyzeRepository analyzes multiple files from a repository as a whole.
// files is a map of filepath → content.
func AnalyzeRepository(repoName string, files map[string]string) (*ReviewResult, error) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not configured on the server")
	}

	model := os.Getenv("ANTHROPIC_REVIEW_MODEL")
	if model == "" {
		model = "claude-haiku-4-5-20251001"
	}

	// Build a single context with all files, respecting the token budget
	var sb strings.Builder
	totalBytes := 0
	filesIncluded := 0
	for path, content := range files {
		block := fmt.Sprintf("\n\n### File: %s\n```\n%s\n```", path, content)
		if totalBytes+len(block) > maxRepoAnalyzeBytes {
			break
		}
		sb.WriteString(block)
		totalBytes += len(block)
		filesIncluded++
	}

	if filesIncluded == 0 {
		return nil, fmt.Errorf("no files could be included for analysis (all files exceeded size limit)")
	}

	prompt := fmt.Sprintf(`You are a senior code reviewer and DevSecOps engineer analyzing the repository "%s". Review ALL files below — including application code, Dockerfiles, Kubernetes manifests, CI/CD pipelines, and configuration files.

%s

Pay special attention to these patterns (non-exhaustive — flag anything you find):

SECURITY — check for:
- Dockerfile running as root (missing USER instruction)
- Hardcoded secrets, tokens, passwords, or API keys in any file
- SSL/TLS verification disabled
- Sensitive data exposed in environment variables or logs
- Kubernetes pods without securityContext (runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation)
- Overly permissive RBAC or pod security policies

PERFORMANCE — check for:
- Kubernetes Deployments/StatefulSets missing resource requests and limits (cpu, memory)
- Missing Horizontal Pod Autoscaler
- Inefficient database queries or missing indexes
- Blocking I/O in async code
- Missing connection pooling or keep-alive

BEST PRACTICES — check for:
- Kubernetes liveness/readiness probes missing
- Dockerfile missing HEALTHCHECK instruction
- No .dockerignore file or overly broad COPY instructions
- Hardcoded image tags (should use digest or versioned tags, not "latest")
- Missing error handling, timeouts, or retry logic
- Inconsistent logging patterns

Return ONLY a valid JSON object (no markdown fences, no extra text) with this exact structure:
{
  "security": [{
    "severity": "high|medium|low",
    "file": "path/to/file",
    "line": 42,
    "title": "short title",
    "description": "explain the problem and why it is a risk (1-2 sentences)",
    "snippet": "the exact problematic code lines as they appear in the file (1-5 lines)",
    "fix": "the corrected version of those same lines"
  }],
  "performance": [{
    "severity": "high|medium|low",
    "file": "path/to/file",
    "line": 10,
    "title": "short title",
    "description": "explain the problem (1-2 sentences)",
    "snippet": "the exact problematic code lines (1-5 lines)",
    "fix": "the corrected version of those same lines"
  }],
  "best_practices": [{
    "severity": "high|medium|low",
    "file": "path/to/file",
    "line": 5,
    "title": "short title",
    "description": "explain the problem (1-2 sentences)",
    "snippet": "the exact problematic code lines (1-5 lines)",
    "fix": "the corrected version of those same lines"
  }]
}

Rules:
- Always set "file" to the relative path of the file where the issue was found
- Always set "line" to the starting line number of the problematic code in that file
- "snippet" must be the actual code from the file, exactly as written — no paraphrasing
- "fix" must be a direct replacement for the snippet — same lines, corrected
- Do NOT invent issues — only report what is actually present in the files above
- If a category has no issues, return an empty array for it
- Maximum 10 findings per category
- All text must be in English`, repoName, sb.String())

	body, _ := json.Marshal(map[string]interface{}{
		"model":      model,
		"max_tokens": 8192,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Anthropic API: %w", err)
	}
	defer res.Body.Close()

	respBody, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		bodyStr := string(respBody)
		if strings.Contains(bodyStr, "context_length") || strings.Contains(bodyStr, "too long") {
			return nil, fmt.Errorf("repository has too much code to analyze at once — try reviewing individual files")
		}
		return nil, fmt.Errorf("Anthropic API error %d: %s", res.StatusCode, bodyStr)
	}

	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}
	if len(apiResp.Content) == 0 {
		return nil, fmt.Errorf("empty response from Anthropic API")
	}

	text := strings.TrimSpace(apiResp.Content[0].Text)
	if strings.HasPrefix(text, "```") {
		lines := strings.Split(text, "\n")
		if len(lines) > 2 {
			text = strings.Join(lines[1:len(lines)-1], "\n")
		}
	}

	var result ReviewResult
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		return nil, fmt.Errorf("failed to parse review JSON: %w", err)
	}

	if result.Security == nil {
		result.Security = []ReviewFinding{}
	}
	if result.Performance == nil {
		result.Performance = []ReviewFinding{}
	}
	if result.BestPractices == nil {
		result.BestPractices = []ReviewFinding{}
	}

	return &result, nil
}
