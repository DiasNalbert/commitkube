package handlers

import (
	"fmt"
	"strings"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

// repoFiles is everything a new repository's first commit will hold, and
// where its manifests live. Creation, approval and the preflight scan all
// build it here, so the files scanned are the files committed.
type repoFiles struct {
	Files       map[string]string
	ArgoAppPath string
	Warnings    []string
	Golden      *goldenPlan
}

// goldenPolicyError lists every rule the rendered files break.
type goldenPolicyError struct{ Problems []string }

func (e *goldenPolicyError) Error() string {
	return "the files break this golden path's rules:\n- " + strings.Join(e.Problems, "\n- ")
}

// repoScope resolves the SCM workspace slug and project key a request is
// for, the two things that decide which templates apply.
func repoScope(req *CreateRepoRequest) (bbWorkspace, projectKey string) {
	projectKey = req.ProjectKey
	if req.WorkspaceID > 0 {
		var ws models.BitbucketWorkspace
		if db.DB.Where("id = ?", req.WorkspaceID).First(&ws).Error == nil {
			bbWorkspace = ws.WorkspaceID
			if projectKey == "" {
				projectKey = ws.ProjectKey
			}
		}
	}
	return bbWorkspace, projectKey
}

// assembleRepoFiles applies, in order, the global and project templates,
// then the golden path's own (which win where both write the same file),
// then the files uploaded with the request. With a golden path it also
// checks the result against the path's rules and refuses on any break.
func assembleRepoFiles(req *CreateRepoRequest, bbWorkspace, projectKey string) (*repoFiles, error) {
	out := &repoFiles{Files: map[string]string{}, ArgoAppPath: "."}

	edited := map[uint]string{}
	for _, e := range req.EditedTemplates {
		edited[e.ID] = e.Content
	}
	skipped := map[uint]bool{}
	for _, id := range req.SkippedTemplateIDs {
		skipped[id] = true
	}

	var matched []models.YamlTemplate
	if res := db.DB.Raw(`
		SELECT yt.* FROM yaml_templates yt
		LEFT JOIN bitbucket_workspaces bw ON yt.workspace_id = bw.id
		WHERE yt.is_active = 1
		  AND yt.deleted_at IS NULL
		  AND yt.golden_path_id IS NULL
		  AND (
		    bw.workspace_id = ?
		    OR (yt.workspace_id IS NULL AND (yt.project_key = '' OR yt.project_key = ?))
		  )
		ORDER BY yt.type DESC, yt.id ASC
	`, bbWorkspace, projectKey).Scan(&matched); res.Error != nil {
		// Said on the result, not only in the log: without its templates the
		// repository is created with no pipeline and no manifests.
		out.Warnings = append(out.Warnings, fmt.Sprintf("templates: could not load them (%v), so none were committed", res.Error))
	}
	for _, t := range matched {
		if !t.IsActive || skipped[t.ID] {
			continue
		}
		content := t.Content
		if e, ok := edited[t.ID]; ok {
			content = e
		}
		file := strings.TrimPrefix(strings.TrimSuffix(t.Path, "/")+"/"+t.Name, "/")
		if t.Path == "" {
			file = t.Name
		}
		out.Files[file] = renderTplWithInputs(content, req.Name, req.GoldenPathInputs)
		if t.Type == "manifest" && t.Path != "" {
			out.ArgoAppPath = strings.TrimPrefix(t.Path, "/")
		}
	}

	if req.GoldenPathID > 0 {
		var gp models.GoldenPath
		if err := db.DB.Where("id = ? AND is_active = ?", req.GoldenPathID, true).First(&gp).Error; err != nil {
			return nil, fmt.Errorf("golden path not found or inactive")
		}
		var tmpls []models.YamlTemplate
		db.DB.Where("golden_path_id = ? AND is_active = ?", gp.ID, true).Order("type desc, id asc").Find(&tmpls)
		plan, err := planGoldenPath(&gp, req.Name, req.GoldenPathInputs, edited, tmpls)
		if err != nil {
			return nil, err
		}
		for f, c := range plan.Files {
			out.Files[f] = c
		}
		if plan.ManifestPath != "" {
			out.ArgoAppPath = plan.ManifestPath
		}
		out.Golden = plan
	}

	for _, f := range req.UploadedFiles {
		if f.Path != "" && f.Content != "" {
			out.Files[f.Path] = f.Content
		}
	}

	if out.Golden != nil {
		if problems := checkGoldenPolicy(out.Golden.Path, out.Golden.Namespace, out.Files); len(problems) > 0 {
			return nil, &goldenPolicyError{Problems: problems}
		}
	}
	return out, nil
}
