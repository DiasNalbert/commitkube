package handlers

import (
	"encoding/json"
	"fmt"
	"html"
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

// TrivySecret deliberately has no Match field. Trivy reports the line that
// matched, and that line is the credential; parsing it into this struct would
// put it in the database, the API and the email. The rule, the file and the
// line number are enough to go and look.
type TrivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
}

func unmarshalReport(raw string, into *TrivyReport) error {
	if raw == "" {
		return nil
	}
	return json.Unmarshal([]byte(raw), into)
}

func marshalReport(r TrivyReport) string {
	b, _ := json.Marshal(r)
	return string(b)
}

type TrivyTarget struct {
	Target            string         `json:"Target"`
	Vulnerabilities   []TrivyVuln    `json:"Vulnerabilities"`
	Misconfigurations []TrivyMisconf `json:"Misconfigurations"`
	Secrets           []TrivySecret  `json:"Secrets"`
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

// deployedImage is the image the repository actually has running in the
// cluster, which is the authoritative thing to scan when it exists.
//
// live asks the clusters directly. The stored workload samples are up to a
// poll interval old, so a scan started right after a deploy -- the moment
// someone most wants to see the new numbers -- read the previous image and
// scanned that. Full and manual scans go live; the periodic image-only pass
// over every repository keeps reading the samples, which is what keeps it
// cheap, and falls behind a deploy by one poll at most.
func deployedImage(repoName string, live bool) (string, error) {
	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return "", fmt.Errorf("repo not found")
	}
	// The workload name follows the ArgoCD application name when one was used
	// to deploy, and the repository name otherwise.
	workloadName := repo.ArgoApp
	if workloadName == "" {
		workloadName = repo.Name
	}
	if live {
		if image, err := liveWorkloadImage(workloadName); err == nil && image != "" {
			return image, nil
		}
	}
	return latestWorkloadImage(workloadName)
}

// scanImage runs Trivy against one image reference, with whatever registry
// credential resolves for it.
func scanImage(image string, userID uint) (TrivyReport, error) {
	scanID := uuid.New().String()
	reportFile := filepath.Join(os.TempDir(), "trivy-image-"+scanID+".json")
	defer os.Remove(reportFile)

	args := []string{"image"}
	args = append(args, trivyCacheArgs()...)
	args = append(args,
		"--format", "json",
		"--output", reportFile,
		"--exit-code", "0",
		"--scanners", "vuln",
		"--no-progress",
	)

	var env []string
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
	trivyCmd.Env = trivyEnv(env...)
	if out, err := trivyCmd.CombinedOutput(); err != nil {
		return TrivyReport{}, fmt.Errorf("trivy image scan failed: %s", strings.TrimSpace(string(out)))
	}

	reportBytes, err := os.ReadFile(reportFile)
	if err != nil {
		return TrivyReport{}, fmt.Errorf("failed to read image report: %w", err)
	}

	var report TrivyReport
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		return TrivyReport{}, fmt.Errorf("failed to parse image report: %w", err)
	}
	return report, nil
}

// ImageSource records which image a container scan actually looked at, because
// the two answer different questions and a number without that label is a lie.
// A deployed image is what is running; a base image is what the Dockerfile
// declares, scanned before anything has been built, so a repository has
// container findings from the moment it is connected.
const (
	ImageSourceDeployed = "deployed"
	ImageSourceBase     = "base"
)

// resolveImageScan scans the deployed image when the repository has one and
// falls back to the base image its Dockerfile declares. checkoutDir may be
// empty -- an image-only pass has no checkout, so it simply has no fallback.
func resolveImageScan(repoName, checkoutDir string, userID uint, live bool) (report TrivyReport, image, source string, err error) {
	image, deployErr := deployedImage(repoName, live)
	if deployErr == nil && image != "" {
		report, err = scanImage(image, userID)
		if err == nil {
			return report, image, ImageSourceDeployed, nil
		}
	}

	if checkoutDir == "" {
		if deployErr != nil {
			return TrivyReport{}, "", "", deployErr
		}
		return TrivyReport{}, image, "", err
	}

	base, dockerfile, baseErr := resolveBaseImage(checkoutDir)
	if baseErr != nil {
		// Report the reason the preferred scan failed, not the fallback's:
		// "no workload deployed yet" is the actionable half.
		if deployErr != nil {
			return TrivyReport{}, "", "", fmt.Errorf("%v; and no base image to fall back to: %v", deployErr, baseErr)
		}
		return TrivyReport{}, image, "", err
	}

	report, err = scanImage(base, userID)
	if err != nil {
		return TrivyReport{}, base, "", fmt.Errorf("base image %s from %s: %w", base, dockerfile, err)
	}
	return report, base, ImageSourceBase, nil
}

// runImageOnlyScan refreshes just the container half of a repository's result.
// It is the cheap pass: no clone, no filesystem scan. New CVEs land against an
// image that has not changed, so this is the one worth running often.
func runImageOnlyScan(repoName string) error {
	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return fmt.Errorf("repo not found")
	}

	var existing models.ScanResult
	if db.DB.Where("repo_name = ?", repoName).First(&existing).Error != nil {
		// Nothing stored yet: there is no code half to preserve, so the full
		// pass is the only one that makes sense.
		return runScanAndSave(repoName, "", false)
	}

	report, image, source, err := resolveImageScan(repoName, "", repo.UserID, false)
	if err != nil {
		existing.ImageError = err.Error()
		db.DB.Save(&existing)
		return err
	}

	now := time.Now()
	sups := activeSuppressions(repoName)
	rows := applySuppressions(findingsFromReport(report, FindingDomainImage), sups)
	counts := countFindings(rows)
	if _, err := reconcileFindings(repoName, FindingDomainImage, rows, now); err != nil {
		return fmt.Errorf("failed to record findings: %w", err)
	}
	codeRows := openFindings(repoName, FindingDomainCode)

	previous := existing
	existing.ScannedImage = image
	existing.ImageSource = source
	existing.ImageCritical = counts["CRITICAL"]
	existing.ImageHigh = counts["HIGH"]
	existing.ImageMedium = counts["MEDIUM"]
	existing.ImageLow = counts["LOW"]
	existing.ImageReport = marshalReport(report)
	existing.ImageError = ""
	existing.Suppressed = countSuppressed(codeRows) + countSuppressed(rows)
	if err := db.DB.Save(&existing).Error; err != nil {
		return err
	}
	recordScanHistory(existing)

	// This pass exists to catch a CVE published against an image nobody
	// touched, so a worse result is exactly the thing worth an email -- and an
	// unchanged one is exactly the thing that must stay quiet.
	if counts["CRITICAL"] > previous.ImageCritical || counts["HIGH"] > previous.ImageHigh {
		notifyImageRegression(repo, existing, codeRows, rows, image)
	}
	return nil
}

// notifyImageRegression mails the same report the full scan would, rebuilding
// the code half from what is stored so the reader gets the whole picture
// rather than a fragment that raises more questions than it answers.
func notifyImageRegression(repo models.Repository, result models.ScanResult, codeRows, imageRows []finding, image string) {
	var user models.User
	if db.DB.First(&user, repo.UserID).Error != nil || user.Email == "" {
		return
	}

	html := buildScanHTML(repo.Name, codeRows, imageRows, image, "")
	subject := fmt.Sprintf("[CommitKube] Novas vulnerabilidades na imagem: %s — C:%d H:%d",
		repo.Name, result.ImageCritical, result.ImageHigh)
	if err := sendScanEmail(user.Email, subject, html); err != nil {
		fmt.Printf("Image regression email failed for %s: %v\n", repo.Name, err)
	}
}

// shouldNotify decides whether a finished scan is worth an email. A person who
// pressed the button is always told. Otherwise only two things are news: the
// first scan of a repository, and findings that got worse. A scheduled rescan
// that confirms yesterday's numbers is not news, and mailing it every hour is
// how a security alert stops being read.
//
// Only CRITICAL and HIGH move the needle. Medium and low churn with every
// database update, and letting them trigger mail would put the whole estate
// back in the inbox daily.
func shouldNotify(manual, hadPrevious bool, previous models.ScanResult, counts, imageCounts map[string]int) bool {
	if manual || !hadPrevious {
		return true
	}
	return counts["CRITICAL"] > previous.Critical ||
		counts["HIGH"] > previous.High ||
		imageCounts["CRITICAL"] > previous.ImageCritical ||
		imageCounts["HIGH"] > previous.ImageHigh
}

// manual says a person asked for this scan and is waiting for the report;
// scheduled passes leave it false and only mail when something got worse.
func runScanAndSave(repoName string, sshKeyOverride string, manual bool) error {
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

	sshKey := repoCloneKey(repo, ws)
	if sshKeyOverride != "" {
		sshKey = sshKeyOverride
	}

	provider := repo.Provider
	if provider == "" {
		provider = "bitbucket"
	}
	scmClient := services.NewSCMClient(provider, ws.Username, "", ws.WorkspaceID)
	repoURL := scmClient.CloneURL(ws.WorkspaceID, repoName)
	// The server must present its pinned host key: the scanned code is only
	// worth anything if it came from the repository.
	acc, err := newSCMAccess(repoURL, sshKey)
	if err != nil {
		return fmt.Errorf("failed to prepare credentials: %w", err)
	}
	defer acc.close()
	cloneCmd := exec.Command("git", "clone", "--depth=1", "--", repoURL, scanDir)
	cloneCmd.Env = acc.env()
	if out, err := cloneCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to clone repository: %s", explainGitError(string(out), err))
	}
	acc.pinIfNew()

	reportFile := filepath.Join(os.TempDir(), "trivy-report-"+scanID+".json")
	defer os.Remove(reportFile)

	fsArgs := []string{"fs"}
	fsArgs = append(fsArgs, trivyCacheArgs()...)
	fsArgs = append(fsArgs,
		"--format", "json",
		"--output", reportFile,
		"--exit-code", "0",
		"--scanners", "vuln,misconfig,secret",
		scanDir,
	)
	trivyCmd := exec.Command("trivy", fsArgs...)
	trivyCmd.Env = trivyEnv()
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

	imageReport, scannedImage, imageSource, imageErr := resolveImageScan(repoName, scanDir, repo.UserID, true)
	imageErrStr := ""
	if imageErr != nil {
		imageErrStr = imageErr.Error()
		fmt.Printf("Image scan skipped for %s: %v\n", repoName, imageErr)
	}

	// Rows first, counts from the rows: what a person has suppressed is left
	// out of every number from here on, and every row gets its identity
	// before anything is mailed or stored.
	now := time.Now()
	sups := activeSuppressions(repoName)
	rows := applySuppressions(findingsFromReport(report, FindingDomainCode), sups)
	counts := countFindings(rows)
	newCode, err := reconcileFindings(repoName, FindingDomainCode, rows, now)
	if err != nil {
		return fmt.Errorf("failed to record findings: %w", err)
	}
	var imageRows []finding
	newImage := 0
	if imageErr == nil {
		imageRows = applySuppressions(findingsFromReport(imageReport, FindingDomainImage), sups)
		if newImage, err = reconcileFindings(repoName, FindingDomainImage, imageRows, now); err != nil {
			return fmt.Errorf("failed to record findings: %w", err)
		}
	}
	imageCounts := countFindings(imageRows)

	var existing models.ScanResult
	hadPrevious := db.DB.Where("repo_name = ?", repoName).First(&existing).Error == nil
	previous := existing // counts as they stood before this pass

	existing.RepoName = repoName
	existing.CodeScannedAt = &now
	existing.Critical = counts["CRITICAL"]
	existing.High = counts["HIGH"]
	existing.Medium = counts["MEDIUM"]
	existing.Low = counts["LOW"]
	existing.Report = marshalReport(report)
	existing.ScannedImage = scannedImage
	existing.ImageSource = imageSource
	existing.ImageCritical = imageCounts["CRITICAL"]
	existing.ImageHigh = imageCounts["HIGH"]
	existing.ImageMedium = imageCounts["MEDIUM"]
	existing.ImageLow = imageCounts["LOW"]
	existing.ImageReport = marshalReport(imageReport)
	existing.ImageError = imageErrStr
	existing.Secrets = countKind(rows, FindingSecret)
	existing.Suppressed = countSuppressed(rows) + countSuppressed(imageRows)
	db.DB.Save(&existing)

	recordScanHistory(models.ScanResult{
		RepoName:      repoName,
		Critical:      counts["CRITICAL"],
		High:          counts["HIGH"],
		Medium:        counts["MEDIUM"],
		Low:           counts["LOW"],
		ImageCritical: imageCounts["CRITICAL"],
		ImageHigh:     imageCounts["HIGH"],
		ImageMedium:   imageCounts["MEDIUM"],
		ImageLow:      imageCounts["LOW"],
	})

	go DispatchWebhook(services.WebhookEvent{
		Event: "scan.completed",
		Payload: map[string]interface{}{
			"repo_name":      repoName,
			"critical":       counts["CRITICAL"],
			"high":           counts["HIGH"],
			"medium":         counts["MEDIUM"],
			"low":            counts["LOW"],
			"image_critical": imageCounts["CRITICAL"],
			"secrets":        existing.Secrets,
			"new_findings":   newCode + newImage,
		},
	})

	if existing.Secrets > 0 && existing.Secrets > previous.Secrets {
		go SendNotifications("scan.secret", "Leaked Secret Found",
			fmt.Sprintf("%d secret(s) found in the code of %s", existing.Secrets, repoName),
			repoName, "system")
	}

	if counts["CRITICAL"] > 0 {
		go SendNotifications("scan.critical", "Critical Vulnerabilities Found",
			fmt.Sprintf("%d critical vulnerabilities found in %s", counts["CRITICAL"], repoName),
			repoName, "system")
	}

	for _, f := range rows {
		if f.Kind == FindingVulnerability && f.Severity == "CRITICAL" && !f.Suppressed {
			f := f
			go DispatchWebhook(services.WebhookEvent{
				Event: "vulnerability.critical_found",
				Payload: map[string]interface{}{
					"repo_name": repoName,
					"cve_id":    f.VulnID,
					"pkg_name":  f.Pkg,
					"severity":  f.Severity,
					"title":     f.Title,
				},
			})
		}
	}

	if user.Email != "" && shouldNotify(manual, hadPrevious, previous, counts, imageCounts) {
		html := buildScanHTML(repoName, rows, imageRows, scannedImage, imageErrStr)
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

	if err := runScanAndSave(repoName, "", true); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	var result models.ScanResult
	db.DB.Where("repo_name = ?", repoName).First(&result)
	db.LogAudit(userID, "run_scan", "repository", repoName, fmt.Sprintf(`{"critical":%d,"high":%d,"medium":%d,"low":%d}`, result.Critical, result.High, result.Medium, result.Low), c.IP())

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

// buildScanHTML renders the report that is mailed. Suppressed findings are
// listed last, under their own heading, so the reader sees that a decision
// was made rather than wondering why a CVE they know about is missing.
func buildScanHTML(repoName string, codeRows, imageRows []finding, scannedImage, imageError string) string {
	counts := countFindings(codeRows)
	imageCounts := countFindings(imageRows)
	esc := html.EscapeString

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
.S{background:#2d1a2d;color:#e879f9;border:1px solid #e879f9}
.sec{color:#10b981;font-size:15px;font-weight:bold;margin:18px 0 6px}
.muted{color:#8b949e}
table{width:100%%;border-collapse:collapse;font-size:12px}
th{background:#21262d;padding:7px 10px;text-align:left;color:#8b949e}
td{padding:7px 10px;border-top:1px solid #21262d;vertical-align:top}
.CRITICAL{color:#ff4444;font-weight:bold}.HIGH{color:#ff8800;font-weight:bold}
.MEDIUM{color:#ffd700}.LOW{color:#00cc44}.UNKNOWN{color:#8b949e}
a{color:#58a6ff}
.ok{background:#1a2d1a;border:1px solid #00cc44;border-radius:8px;padding:14px;color:#00cc44;text-align:center;font-size:16px;margin-top:12px}
.footer{margin-top:20px;padding-top:12px;border-top:1px solid #30363d;color:#8b949e;font-size:11px}
</style></head><body><div class="wrap">
<h1>Security Scan Report</h1>
<div class="sub">Repository: <strong>%s</strong></div>`, esc(repoName)))

	writeSummary := func(counts map[string]int, secrets int) {
		sb.WriteString(fmt.Sprintf(`<div class="summary">
  <div class="badge C">%d<span class="lbl">CRITICAL</span></div>
  <div class="badge H">%d<span class="lbl">HIGH</span></div>
  <div class="badge M">%d<span class="lbl">MEDIUM</span></div>
  <div class="badge L">%d<span class="lbl">LOW</span></div>`,
			counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"]))
		if secrets > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="badge S">%d<span class="lbl">SECRETS</span></div>`, secrets))
		}
		sb.WriteString(`</div>`)
	}

	// One table per target, in the order the rows come (worst first within
	// a target), with secrets and misconfigurations in the same table as the
	// CVEs: the columns are close enough, and a leaked key next to an old
	// library is where it belongs on a list sorted by severity.
	writeRows := func(rows []finding) {
		byTarget := map[string][]finding{}
		var order []string
		for _, f := range rows {
			if _, ok := byTarget[f.Target]; !ok {
				order = append(order, f.Target)
			}
			byTarget[f.Target] = append(byTarget[f.Target], f)
		}
		for _, t := range order {
			sb.WriteString(fmt.Sprintf(`<div class="sec">%s</div>`, esc(t)))
			sb.WriteString(`<table><tr><th>Severity</th><th>ID</th><th>Type</th><th>Package / Location</th><th>Installed</th><th>Fixed</th><th>Title</th></tr>`)
			for _, f := range byTarget[t] {
				id := esc(f.VulnID)
				if f.Kind == FindingVulnerability && strings.HasPrefix(f.VulnID, "CVE-") {
					id = fmt.Sprintf(`<a href="https://nvd.nist.gov/vuln/detail/%s">%s</a>`, esc(f.VulnID), esc(f.VulnID))
				}
				where := esc(f.Pkg)
				if f.Kind == FindingSecret {
					where = fmt.Sprintf("%s · line %d", esc(f.Pkg), f.Line)
				}
				sb.WriteString(fmt.Sprintf(`<tr><td class="%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
					esc(f.Severity), esc(f.Severity), id, esc(f.Kind), where, esc(f.Version), esc(f.Fixed), esc(f.Title)))
			}
			sb.WriteString(`</table>`)
		}
	}

	writeSuppressed := func(rows []finding) {
		var sup []finding
		for _, f := range rows {
			if f.Suppressed {
				sup = append(sup, f)
			}
		}
		if len(sup) == 0 {
			return
		}
		sb.WriteString(fmt.Sprintf(`<div class="sec muted">Suppressed (%d) — not counted above</div>`, len(sup)))
		sb.WriteString(`<table><tr><th>ID</th><th>Package</th><th>Reason</th><th>By</th><th>Note</th></tr>`)
		for _, f := range sup {
			s := f.Suppression
			sb.WriteString(fmt.Sprintf(`<tr class="muted"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				esc(f.VulnID), esc(f.Pkg), esc(s.Reason), esc(s.CreatedByEmail), esc(s.Note)))
		}
		sb.WriteString(`</table>`)
	}

	split := func(rows []finding) (active []finding) {
		for _, f := range rows {
			if !f.Suppressed {
				active = append(active, f)
			}
		}
		return
	}

	writeSummary(counts, countKind(codeRows, FindingSecret))
	active := split(codeRows)
	if len(active) == 0 {
		sb.WriteString(`<div class="ok">No vulnerabilities, misconfigurations or secrets found!</div>`)
	} else {
		writeRows(active)
	}
	writeSuppressed(codeRows)

	sb.WriteString(`<div style="margin-top:32px;border-top:2px solid #30363d;padding-top:20px">`)
	sb.WriteString(`<h2 style="color:#58a6ff;margin:0 0 8px;font-size:18px">Image Scan</h2>`)
	if imageError != "" {
		sb.WriteString(fmt.Sprintf(`<div style="background:#21262d;border:1px solid #30363d;border-radius:6px;padding:12px;color:#8b949e;font-size:13px">Image scan skipped: %s</div>`, esc(imageError)))
	} else {
		sb.WriteString(fmt.Sprintf(`<div style="color:#8b949e;font-size:12px;margin-bottom:12px">Image: <code style="color:#e6edf3">%s</code></div>`, esc(scannedImage)))
		writeSummary(imageCounts, 0)
		active := split(imageRows)
		if len(active) == 0 {
			sb.WriteString(`<div class="ok">No vulnerabilities found in image!</div>`)
		} else {
			writeRows(active)
		}
		writeSuppressed(imageRows)
	}
	sb.WriteString(`</div>`)

	sb.WriteString(`<div class="footer">Generated by CommitKube · Powered by <a href="https://trivy.dev">Trivy</a></div></div></body></html>`)
	return sb.String()
}

// scanScopeRepoNames is the set of repositories a security dashboard covers
// for a workspace / project / search filter. Only repositories that still
// exist count, so a deleted one stops weighing on the totals and the history.
func scanScopeRepoNames(wsID int, projectKey, search string) []string {
	var wsIDs []uint
	if wsID > 0 {
		var targetWs models.BitbucketWorkspace
		if db.DB.Where("id = ?", wsID).First(&targetWs).Error == nil {
			db.DB.Model(&models.BitbucketWorkspace{}).
				Where("workspace_id = ?", targetWs.WorkspaceID).
				Pluck("id", &wsIDs)
		}
		if len(wsIDs) == 0 {
			wsIDs = []uint{uint(wsID)}
		}
	}

	repoQ := db.DB.Model(&models.Repository{})
	if len(wsIDs) > 0 {
		repoQ = repoQ.Where("workspace_id IN ?", wsIDs)
	}
	if projectKey != "" {
		repoQ = repoQ.Where("project_key = ?", projectKey)
	}
	var repoNames []string
	repoQ.Pluck("name", &repoNames)

	if search != "" {
		filtered := make([]string, 0, len(repoNames))
		lower := strings.ToLower(search)
		for _, n := range repoNames {
			if strings.Contains(strings.ToLower(n), lower) {
				filtered = append(filtered, n)
			}
		}
		repoNames = filtered
	}
	return repoNames
}

func GetScanDashboard(c *fiber.Ctx) error {
	wsID := c.QueryInt("workspace_id", 0)
	projectKey := c.Query("project_key", "")
	search := c.Query("search", "")
	page := c.QueryInt("page", 1)
	limit := c.QueryInt("limit", 20)
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	repoNames := scanScopeRepoNames(wsID, projectKey, search)

	baseQ := func() *gorm.DB {
		q := db.DB.Model(&models.ScanResult{})
		q = q.Where("repo_name IN ?", repoNames)
		return q
	}

	// Only the counts are needed here, and the two report columns are the
	// whole Trivy JSON of every repository -- megabytes per refresh, which
	// the live dashboard would otherwise pull every time a scan lands.
	var allResults []models.ScanResult
	baseQ().Omit("report", "image_report").Find(&allResults)

	// Three tallies from the same rows. The code and image totals are what the
	// two security dashboards each show on their own; the combined one is kept
	// because the platform summary still reports a single security number.
	totals := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	codeTotals := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	imageTotals := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, r := range allResults {
		codeTotals["critical"] += r.Critical
		codeTotals["high"] += r.High
		codeTotals["medium"] += r.Medium
		codeTotals["low"] += r.Low

		imageTotals["critical"] += r.ImageCritical
		imageTotals["high"] += r.ImageHigh
		imageTotals["medium"] += r.ImageMedium
		imageTotals["low"] += r.ImageLow
	}
	for k := range totals {
		totals[k] = codeTotals[k] + imageTotals[k]
	}

	var total int64
	baseQ().Count(&total)

	var results []models.ScanResult
	baseQ().Omit("report", "image_report").Order("created_at desc").Offset((page - 1) * limit).Limit(limit).Find(&results)

	pages := int(total) / limit
	if int(total)%limit > 0 {
		pages++
	}

	return c.JSON(fiber.Map{
		"totals":       totals,
		"code_totals":  codeTotals,
		"image_totals": imageTotals,
		"results":      results,
		"total":        total,
		"page":         page,
		"pages":        pages,
		"limit":        limit,
	})
}

func GetRepoScanDetail(c *fiber.Ctx) error {
	repoName := c.Params("name")

	var result models.ScanResult
	if err := db.DB.Where("repo_name = ?", repoName).First(&result).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "no scan found for this repository"})
	}

	findings := detailFindings(repoName, FindingDomainCode)
	imageFindings := detailFindings(repoName, FindingDomainImage)
	newCount := 0
	for _, f := range findings {
		if f.IsNew && !f.Suppressed {
			newCount++
		}
	}
	for _, f := range imageFindings {
		if f.IsNew && !f.Suppressed {
			newCount++
		}
	}

	// How many were closed in the last month: the half of the picture a
	// list of open problems never shows.
	var resolved int64
	db.DB.Model(&models.ScanFinding{}).
		Where("repo_name = ? AND resolved_at >= ?", repoName, time.Now().AddDate(0, 0, -30)).
		Count(&resolved)

	return c.JSON(fiber.Map{
		"repo_name": result.RepoName,
		// UpdatedAt: the row is rewritten by every scan, so CreatedAt is the
		// first scan ever and was being shown as "Last scan".
		"scanned_at":       result.UpdatedAt,
		"first_scanned_at": result.CreatedAt,
		"critical":         result.Critical,
		"high":             result.High,
		"medium":           result.Medium,
		"low":              result.Low,
		"secrets":          result.Secrets,
		"suppressed":       result.Suppressed,
		"new_findings":     newCount,
		"resolved_30d":     resolved,
		"findings":         findings,
		"scanned_image":    result.ScannedImage,
		"image_source":     result.ImageSource,
		"image_critical":   result.ImageCritical,
		"image_high":       result.ImageHigh,
		"image_medium":     result.ImageMedium,
		"image_low":        result.ImageLow,
		"image_error":      result.ImageError,
		"image_findings":   imageFindings,
	})
}
