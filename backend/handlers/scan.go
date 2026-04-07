package handlers

import (
	"encoding/json"
	"fmt"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
	"gorm.io/gorm"
)

type TrivyReport struct {
	Results []TrivyTarget `json:"Results"`
}

type TrivyTarget struct {
	Target            string         `json:"Target"`
	Vulnerabilities   []TrivyVuln    `json:"Vulnerabilities"`
	Misconfigurations []TrivyMisconf `json:"Misconfigurations"`
}

type TrivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
}

type TrivyMisconf struct {
	ID       string `json:"ID"`
	Type     string `json:"Type"`
	Title    string `json:"Title"`
	Severity string `json:"Severity"`
	Status   string `json:"Status"`
}

func TriggerScanBackground(repoName string) {
	go func() {
		time.Sleep(30 * time.Second)
		if err := runScanAndSave(repoName, ""); err != nil {
			fmt.Printf("Background scan failed for %s: %v\n", repoName, err)
		}
	}()
}

func runImageScanFromRegistry(repoName string, userID uint) (TrivyReport, map[string]int, string, error) {
	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return TrivyReport{}, nil, "", fmt.Errorf("repo not found")
	}
	if repo.ArgoApp == "" {
		return TrivyReport{}, nil, "", fmt.Errorf("no ArgoCD app linked to repo")
	}

	var snapshot models.ServiceSnapshot
	if err := db.DB.Where("app_name = ?", repo.ArgoApp).Order("recorded_at desc").First(&snapshot).Error; err != nil {
		return TrivyReport{}, nil, "", fmt.Errorf("no monitoring snapshot for app %s", repo.ArgoApp)
	}
	if snapshot.Image == "" {
		return TrivyReport{}, nil, "", fmt.Errorf("no image in latest snapshot")
	}

	image := snapshot.Image
	scanID := uuid.New().String()
	reportFile := filepath.Join(os.TempDir(), "trivy-image-"+scanID+".json")
	defer os.Remove(reportFile)

	args := []string{
		"image",
		"--format", "json",
		"--output", reportFile,
		"--exit-code", "0",
		"--scanners", "vuln",
		"--no-progress",
	}

	env := os.Environ()
	cred := ResolveRegistryCredential(image, userID)
	if cred != nil {
		switch cred.Type {
		case "ecr":
			env = append(env,
				"AWS_ACCESS_KEY_ID="+cred.AWSAccessKey,
				"AWS_SECRET_ACCESS_KEY="+cred.AWSSecretKey,
				"AWS_REGION="+cred.AWSRegion,
			)
		case "gcr":
			keyFile := filepath.Join(os.TempDir(), "gcr-key-"+scanID+".json")
			defer os.Remove(keyFile)
			if err := os.WriteFile(keyFile, []byte(cred.GCRKeyJSON), 0600); err == nil {
				env = append(env, "GOOGLE_APPLICATION_CREDENTIALS="+keyFile)
			}
		default: // generic
			env = append(env,
				"TRIVY_USERNAME="+cred.Username,
				"TRIVY_PASSWORD="+cred.Password,
			)
		}
	}

	args = append(args, image)
	trivyCmd := exec.Command("trivy", args...)
	trivyCmd.Env = env
	if out, err := trivyCmd.CombinedOutput(); err != nil {
		return TrivyReport{}, nil, image, fmt.Errorf("trivy image scan failed: %s", strings.TrimSpace(string(out)))
	}

	reportBytes, err := os.ReadFile(reportFile)
	if err != nil {
		return TrivyReport{}, nil, image, fmt.Errorf("failed to read image report: %w", err)
	}

	var report TrivyReport
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		return TrivyReport{}, nil, image, fmt.Errorf("failed to parse image report: %w", err)
	}

	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, target := range report.Results {
		for _, v := range target.Vulnerabilities {
			counts[v.Severity]++
		}
	}

	return report, counts, image, nil
}

func runScanAndSave(repoName string, sshKeyOverride string) error {
	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return fmt.Errorf("repo not found: %w", err)
	}

	var user models.User
	db.DB.First(&user, repo.UserID)

	ws, err := resolveWorkspace(repo.UserID, repo.WorkspaceID)
	if err != nil {
		return fmt.Errorf("workspace not found: %w", err)
	}

	scanID := uuid.New().String()
	scanDir := filepath.Join(os.TempDir(), "trivy-scan-"+scanID)
	defer os.RemoveAll(scanDir)

	sshKey := crypto.DecryptField(crypto.MasterKey(), ws.SSHPrivKey)
	if sshKeyOverride != "" {
		sshKey = sshKeyOverride
	}
	sshKey = strings.ReplaceAll(sshKey, `\n`, "\n")
	sshKey = strings.ReplaceAll(sshKey, "\r\n", "\n")
	sshKey = strings.TrimSpace(sshKey) + "\n"

	keyFile := filepath.Join(os.TempDir(), "trivy-key-"+scanID)
	defer os.Remove(keyFile)
	if err := os.WriteFile(keyFile, []byte(sshKey), 0600); err != nil {
		return fmt.Errorf("failed to prepare credentials: %w", err)
	}

	provider := repo.Provider
	if provider == "" {
		provider = "bitbucket"
	}
	scmClient := services.NewSCMClient(provider, ws.Username, "", ws.WorkspaceID)
	repoURL := scmClient.CloneURL(ws.WorkspaceID, repoName)
	cloneCmd := exec.Command("git", "clone", "--depth=1", repoURL, scanDir)
	cloneCmd.Env = append(os.Environ(),
		fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=no", keyFile),
	)
	if out, err := cloneCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to clone repository: %s", string(out))
	}

	reportFile := filepath.Join(os.TempDir(), "trivy-report-"+scanID+".json")
	defer os.Remove(reportFile)

	trivyCmd := exec.Command("trivy", "fs",
		"--format", "json",
		"--output", reportFile,
		"--exit-code", "0",
		"--scanners", "vuln,misconfig,secret",
		scanDir,
	)
	if out, err := trivyCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("trivy scan failed: %s", string(out))
	}

	reportBytes, err := os.ReadFile(reportFile)
	if err != nil {
		return fmt.Errorf("failed to read scan report: %w", err)
	}

	var report TrivyReport
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		return fmt.Errorf("failed to parse scan report: %w", err)
	}

	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, target := range report.Results {
		for _, v := range target.Vulnerabilities {
			counts[v.Severity]++
		}
		for _, m := range target.Misconfigurations {
			if m.Status != "PASS" {
				counts[m.Severity]++
			}
		}
	}

	reportJSON, _ := json.Marshal(report)

	imageReport, imageCounts, scannedImage, imageErr := runImageScanFromRegistry(repoName, repo.UserID)
	imageReportJSON, _ := json.Marshal(imageReport)
	imageErrStr := ""
	if imageErr != nil {
		imageErrStr = imageErr.Error()
		fmt.Printf("Image scan skipped for %s: %v\n", repoName, imageErr)
	}

	var existing models.ScanResult
	if db.DB.Where("repo_name = ?", repoName).First(&existing).Error == nil {
		existing.Critical = counts["CRITICAL"]
		existing.High = counts["HIGH"]
		existing.Medium = counts["MEDIUM"]
		existing.Low = counts["LOW"]
		existing.Report = string(reportJSON)
		existing.ScannedImage = scannedImage
		existing.ImageCritical = imageCounts["CRITICAL"]
		existing.ImageHigh = imageCounts["HIGH"]
		existing.ImageMedium = imageCounts["MEDIUM"]
		existing.ImageLow = imageCounts["LOW"]
		existing.ImageReport = string(imageReportJSON)
		existing.ImageError = imageErrStr
		db.DB.Save(&existing)
	} else {
		db.DB.Create(&models.ScanResult{
			RepoName:      repoName,
			Critical:      counts["CRITICAL"],
			High:          counts["HIGH"],
			Medium:        counts["MEDIUM"],
			Low:           counts["LOW"],
			Report:        string(reportJSON),
			ScannedImage:  scannedImage,
			ImageCritical: imageCounts["CRITICAL"],
			ImageHigh:     imageCounts["HIGH"],
			ImageMedium:   imageCounts["MEDIUM"],
			ImageLow:      imageCounts["LOW"],
			ImageReport:   string(imageReportJSON),
			ImageError:    imageErrStr,
		})
	}

	go DispatchWebhook(services.WebhookEvent{
		Event: "scan.completed",
		Payload: map[string]interface{}{
			"repo_name":      repoName,
			"critical":       counts["CRITICAL"],
			"high":           counts["HIGH"],
			"medium":         counts["MEDIUM"],
			"low":            counts["LOW"],
			"image_critical": imageCounts["CRITICAL"],
		},
	})

	if counts["CRITICAL"] > 0 {
		for _, target := range report.Results {
			for _, v := range target.Vulnerabilities {
				if v.Severity == "CRITICAL" {
					v := v
					go DispatchWebhook(services.WebhookEvent{
						Event: "vulnerability.critical_found",
						Payload: map[string]interface{}{
							"repo_name": repoName,
							"cve_id":    v.VulnerabilityID,
							"pkg_name":  v.PkgName,
							"severity":  v.Severity,
							"title":     v.Title,
						},
					})
				}
			}
		}
	}

	if user.Email != "" {
		html := buildScanHTML(repoName, report, counts, imageReport, imageCounts, scannedImage, imageErrStr)
		subject := fmt.Sprintf("[CommitKube] Security Scan: %s — Code C:%d H:%d M:%d L:%d",
			repoName, counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"])
		if err := sendScanEmail(user.Email, subject, html); err != nil {
			fmt.Printf("Scan email failed for %s: %v\n", repoName, err)
		}
	}

	return nil
}

func RunTrivyScan(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	repoName := c.Params("name")

	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}

	if err := runScanAndSave(repoName, ""); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	var result models.ScanResult
	db.DB.Where("repo_name = ?", repoName).First(&result)

	return c.JSON(fiber.Map{
		"message":  fmt.Sprintf("Scan completed. Report sent to %s", user.Email),
		"critical": result.Critical,
		"high":     result.High,
		"medium":   result.Medium,
		"low":      result.Low,
	})
}

func sendScanEmail(to, subject, htmlBody string) error {
	var cfg models.SMTPConfig
	db.DB.First(&cfg)

	host := cfg.Host
	port := cfg.Port
	user := cfg.User
	pass := crypto.DecryptField(crypto.MasterKey(), cfg.Password)
	from := cfg.From

	if host == "" {
		host = os.Getenv("SMTP_HOST")
	}
	if port == "" {
		port = os.Getenv("SMTP_PORT")
	}
	if user == "" {
		user = os.Getenv("SMTP_USER")
	}
	if pass == "" {
		pass = os.Getenv("SMTP_PASS")
	}
	if from == "" {
		from = os.Getenv("SMTP_FROM")
	}
	if from == "" {
		from = user
	}

	if host == "" || port == "" || user == "" || pass == "" {
		return fmt.Errorf("SMTP not configured (set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS)")
	}
	auth := smtp.PlainAuth("", user, pass, host)
	msg := fmt.Sprintf(
		"From: CommitKube <%s>\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, to, subject, htmlBody,
	)
	return smtp.SendMail(host+":"+port, auth, from, []string{to}, []byte(msg))
}

func buildScanHTML(repoName string, report TrivyReport, counts map[string]int, imageReport TrivyReport, imageCounts map[string]int, scannedImage, imageError string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
body{font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:20px}
.wrap{max-width:900px;margin:0 auto;background:#161b22;border-radius:8px;padding:24px;border:1px solid #30363d}
h1{color:#10b981;margin:0 0 4px}
.sub{color:#8b949e;margin-bottom:20px}
.summary{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.badge{padding:10px 18px;border-radius:8px;font-weight:bold;font-size:16px;text-align:center;min-width:70px}
.lbl{font-size:10px;font-weight:normal;display:block;margin-top:2px}
.C{background:#3d0000;color:#ff4444;border:1px solid #ff4444}
.H{background:#2d1a00;color:#ff8800;border:1px solid #ff8800}
.M{background:#2d2600;color:#ffd700;border:1px solid #ffd700}
.L{background:#1a2d1a;color:#00cc44;border:1px solid #00cc44}
.sec{color:#10b981;font-size:15px;font-weight:bold;margin:18px 0 6px}
table{width:100%%;border-collapse:collapse;font-size:12px}
th{background:#21262d;padding:7px 10px;text-align:left;color:#8b949e}
td{padding:7px 10px;border-top:1px solid #21262d;vertical-align:top}
.CRITICAL{color:#ff4444;font-weight:bold}.HIGH{color:#ff8800;font-weight:bold}
.MEDIUM{color:#ffd700}.LOW{color:#00cc44}
a{color:#58a6ff}
.ok{background:#1a2d1a;border:1px solid #00cc44;border-radius:8px;padding:14px;color:#00cc44;text-align:center;font-size:16px;margin-top:12px}
.footer{margin-top:20px;padding-top:12px;border-top:1px solid #30363d;color:#8b949e;font-size:11px}
</style></head><body><div class="wrap">
<h1>Security Scan Report</h1>
<div class="sub">Repository: <strong>%s</strong></div>
<div class="summary">
  <div class="badge C">%d<span class="lbl">CRITICAL</span></div>
  <div class="badge H">%d<span class="lbl">HIGH</span></div>
  <div class="badge M">%d<span class="lbl">MEDIUM</span></div>
  <div class="badge L">%d<span class="lbl">LOW</span></div>
</div>`, repoName, counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"]))

	hasFindings := false
	for _, target := range report.Results {
		vulns := target.Vulnerabilities
		var misconfs []TrivyMisconf
		for _, m := range target.Misconfigurations {
			if m.Status != "PASS" {
				misconfs = append(misconfs, m)
			}
		}

		if len(vulns) == 0 && len(misconfs) == 0 {
			continue
		}
		hasFindings = true

		sb.WriteString(fmt.Sprintf(`<div class="sec">%s</div>`, target.Target))

		if len(vulns) > 0 {
			sb.WriteString(`<table><tr><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Severity</th><th>Title</th></tr>`)
			for _, v := range vulns {
				sb.WriteString(fmt.Sprintf(`<tr>
					<td><a href="https://nvd.nist.gov/vuln/detail/%s">%s</a></td>
					<td>%s</td><td>%s</td><td>%s</td>
					<td class="%s">%s</td><td>%s</td>
				</tr>`, v.VulnerabilityID, v.VulnerabilityID,
					v.PkgName, v.InstalledVersion, v.FixedVersion,
					v.Severity, v.Severity, v.Title))
			}
			sb.WriteString(`</table>`)
		}

		if len(misconfs) > 0 {
			sb.WriteString(`<table style="margin-top:8px"><tr><th>ID</th><th>Type</th><th>Title</th><th>Severity</th></tr>`)
			for _, m := range misconfs {
				sb.WriteString(fmt.Sprintf(`<tr>
					<td>%s</td><td>%s</td><td>%s</td>
					<td class="%s">%s</td>
				</tr>`, m.ID, m.Type, m.Title, m.Severity, m.Severity))
			}
			sb.WriteString(`</table>`)
		}
	}

	if !hasFindings {
		sb.WriteString(`<div class="ok">No vulnerabilities or misconfigurations found!</div>`)
	}

	// Image scan section
	sb.WriteString(`<div style="margin-top:32px;border-top:2px solid #30363d;padding-top:20px">`)
	sb.WriteString(`<h2 style="color:#58a6ff;margin:0 0 8px;font-size:18px">Image Scan</h2>`)
	if imageError != "" {
		sb.WriteString(fmt.Sprintf(`<div style="background:#21262d;border:1px solid #30363d;border-radius:6px;padding:12px;color:#8b949e;font-size:13px">Image scan skipped: %s</div>`, imageError))
	} else {
		sb.WriteString(fmt.Sprintf(`<div style="color:#8b949e;font-size:12px;margin-bottom:12px">Image: <code style="color:#e6edf3">%s</code></div>`, scannedImage))
		sb.WriteString(fmt.Sprintf(`<div class="summary">
  <div class="badge C">%d<span class="lbl">CRITICAL</span></div>
  <div class="badge H">%d<span class="lbl">HIGH</span></div>
  <div class="badge M">%d<span class="lbl">MEDIUM</span></div>
  <div class="badge L">%d<span class="lbl">LOW</span></div>
</div>`, imageCounts["CRITICAL"], imageCounts["HIGH"], imageCounts["MEDIUM"], imageCounts["LOW"]))

		hasImageFindings := false
		for _, target := range imageReport.Results {
			if len(target.Vulnerabilities) == 0 {
				continue
			}
			hasImageFindings = true
			sb.WriteString(fmt.Sprintf(`<div class="sec">%s</div>`, target.Target))
			sb.WriteString(`<table><tr><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Severity</th><th>Title</th></tr>`)
			for _, v := range target.Vulnerabilities {
				sb.WriteString(fmt.Sprintf(`<tr>
					<td><a href="https://nvd.nist.gov/vuln/detail/%s">%s</a></td>
					<td>%s</td><td>%s</td><td>%s</td>
					<td class="%s">%s</td><td>%s</td>
				</tr>`, v.VulnerabilityID, v.VulnerabilityID,
					v.PkgName, v.InstalledVersion, v.FixedVersion,
					v.Severity, v.Severity, v.Title))
			}
			sb.WriteString(`</table>`)
		}
		if !hasImageFindings {
			sb.WriteString(`<div class="ok">No vulnerabilities found in image!</div>`)
		}
	}
	sb.WriteString(`</div>`)

	sb.WriteString(`<div class="footer">Generated by CommitKube · Powered by <a href="https://trivy.dev">Trivy</a></div></div></body></html>`)
	return sb.String()
}

func GetScanDashboard(c *fiber.Ctx) error {
	wsID := c.QueryInt("workspace_id", 0)
	projectKey := c.Query("project_key", "")
	page := c.QueryInt("page", 1)
	limit := c.QueryInt("limit", 20)
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	var existingRepoNames []string
	db.DB.Model(&models.Repository{}).Pluck("name", &existingRepoNames)

	filtered := wsID > 0 || projectKey != ""
	var repoNames []string
	if filtered {
		repoQ := db.DB.Model(&models.Repository{})
		if wsID > 0 {
			repoQ = repoQ.Where("workspace_id = ?", wsID)
		}
		if projectKey != "" {
			repoQ = repoQ.Where("project_key = ?", projectKey)
		}
		repoQ.Pluck("name", &repoNames)
	} else {
		repoNames = existingRepoNames
	}

	baseQ := func() *gorm.DB {
		q := db.DB.Model(&models.ScanResult{})
		q = q.Where("repo_name IN ?", repoNames)
		return q
	}

	var allResults []models.ScanResult
	baseQ().Find(&allResults)
	totals := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, r := range allResults {
		totals["critical"] += r.Critical + r.ImageCritical
		totals["high"] += r.High + r.ImageHigh
		totals["medium"] += r.Medium + r.ImageMedium
		totals["low"] += r.Low + r.ImageLow
	}

	var total int64
	baseQ().Count(&total)

	var results []models.ScanResult
	baseQ().Order("created_at desc").Offset((page - 1) * limit).Limit(limit).Find(&results)

	pages := int(total) / limit
	if int(total)%limit > 0 {
		pages++
	}

	return c.JSON(fiber.Map{
		"totals":  totals,
		"results": results,
		"total":   total,
		"page":    page,
		"pages":   pages,
		"limit":   limit,
	})
}

func GetRepoScanDetail(c *fiber.Ctx) error {
	repoName := c.Params("name")

	var result models.ScanResult
	if err := db.DB.Where("repo_name = ?", repoName).First(&result).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "no scan found for this repository"})
	}

	var report TrivyReport
	if err := json.Unmarshal([]byte(result.Report), &report); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to parse report"})
	}

	type Finding struct {
		Target   string `json:"target"`
		Type     string `json:"type"`
		VulnID   string `json:"vuln_id"`
		Pkg      string `json:"pkg"`
		Version  string `json:"version"`
		Fixed    string `json:"fixed"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
	}

	var findings []Finding
	for _, target := range report.Results {
		for _, v := range target.Vulnerabilities {
			findings = append(findings, Finding{
				Target:   target.Target,
				Type:     "vulnerability",
				VulnID:   v.VulnerabilityID,
				Pkg:      v.PkgName,
				Version:  v.InstalledVersion,
				Fixed:    v.FixedVersion,
				Severity: v.Severity,
				Title:    v.Title,
			})
		}
		for _, m := range target.Misconfigurations {
			if m.Status == "PASS" {
				continue
			}
			findings = append(findings, Finding{
				Target:   target.Target,
				Type:     "misconfiguration",
				VulnID:   m.ID,
				Pkg:      m.Type,
				Severity: m.Severity,
				Title:    m.Title,
			})
		}
	}

	var imageFindings []Finding
	if result.ImageReport != "" {
		var imageReportParsed TrivyReport
		if err := json.Unmarshal([]byte(result.ImageReport), &imageReportParsed); err == nil {
			for _, target := range imageReportParsed.Results {
				for _, v := range target.Vulnerabilities {
					imageFindings = append(imageFindings, Finding{
						Target:   target.Target,
						Type:     "vulnerability",
						VulnID:   v.VulnerabilityID,
						Pkg:      v.PkgName,
						Version:  v.InstalledVersion,
						Fixed:    v.FixedVersion,
						Severity: v.Severity,
						Title:    v.Title,
					})
				}
			}
		}
	}

	return c.JSON(fiber.Map{
		"repo_name":      result.RepoName,
		"scanned_at":     result.CreatedAt,
		"critical":       result.Critical,
		"high":           result.High,
		"medium":         result.Medium,
		"low":            result.Low,
		"findings":       findings,
		"scanned_image":  result.ScannedImage,
		"image_critical": result.ImageCritical,
		"image_high":     result.ImageHigh,
		"image_medium":   result.ImageMedium,
		"image_low":      result.ImageLow,
		"image_error":    result.ImageError,
		"image_findings": imageFindings,
	})
}

