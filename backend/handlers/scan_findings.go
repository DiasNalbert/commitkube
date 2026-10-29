package handlers

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"gorm.io/gorm"
)

// The scan used to be a number: Trivy's JSON, stored whole, and four counts
// derived from it. That cannot answer when a CVE arrived, how long it stayed,
// or whether anyone has already decided it does not matter. This file gives
// each finding a row of its own, keeps that row across rescans, and applies
// the triage decisions before anything is counted.

const (
	FindingDomainCode  = "code"
	FindingDomainImage = "image"

	FindingVulnerability    = "vulnerability"
	FindingMisconfiguration = "misconfiguration"
	FindingSecret           = "secret"
	// FindingWeakness is a flaw in the code itself -- an injection, a path
	// built from the request -- found by static analysis (Opengrep), as
	// opposed to a known CVE in something the code depends on.
	FindingWeakness = "weakness"
)

// finding is one row of a report, before it is stored or counted.
type finding struct {
	Domain   string `json:"domain"`
	Kind     string `json:"type"`
	Target   string `json:"target"`
	VulnID   string `json:"vuln_id"`
	Pkg      string `json:"pkg"`
	Line     int    `json:"line,omitempty"`
	Version  string `json:"version"`
	Fixed    string `json:"fixed"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	CWE      string `json:"cwe,omitempty"`

	// Set by applySuppressions.
	Suppressed  bool                    `json:"suppressed"`
	Suppression *models.ScanSuppression `json:"suppression,omitempty"`
}

// identity is what makes two sightings the same finding.
type identity struct {
	Domain, Kind, Target, VulnID, Pkg string
	Line                              int
}

func (f finding) identity() identity {
	line := f.Line
	if f.Kind == FindingWeakness {
		// The fingerprint in Pkg already places it; the line moves with
		// every edit above it, and a moved weakness is not a new one.
		line = 0
	}
	return identity{f.Domain, f.Kind, f.Target, f.VulnID, f.Pkg, line}
}

// findingFromRow is the inverse of what reconcileFindings stores.
func findingFromRow(r models.ScanFinding) finding {
	return finding{
		Domain: r.Domain, Kind: r.Kind, Target: r.Target, VulnID: r.VulnID, Pkg: r.Pkg,
		Line: r.Line, Version: r.Version, Fixed: r.Fixed, Severity: r.Severity, Title: r.Title, CWE: r.CWE,
	}
}

// findingsFromReport flattens a Trivy report into rows. Misconfigurations that
// passed are not findings. Secrets carry the rule and the line, never the
// matched text: the report is the one place a leaked key must not be copied
// to.
func findingsFromReport(report TrivyReport, domain string) []finding {
	var out []finding
	for _, target := range report.Results {
		for _, v := range target.Vulnerabilities {
			out = append(out, finding{
				Domain: domain, Kind: FindingVulnerability, Target: target.Target,
				VulnID: v.VulnerabilityID, Pkg: v.PkgName, Version: v.InstalledVersion,
				Fixed: v.FixedVersion, Severity: normalizeSeverity(v.Severity), Title: v.Title,
			})
		}
		if domain != FindingDomainCode {
			continue
		}
		for _, m := range target.Misconfigurations {
			if m.Status == "PASS" {
				continue
			}
			out = append(out, finding{
				Domain: domain, Kind: FindingMisconfiguration, Target: target.Target,
				VulnID: m.ID, Pkg: m.Type, Severity: normalizeSeverity(m.Severity), Title: m.Title,
			})
		}
		for _, s := range target.Secrets {
			out = append(out, finding{
				Domain: domain, Kind: FindingSecret, Target: target.Target,
				VulnID: s.RuleID, Pkg: s.Category, Line: s.StartLine,
				Severity: normalizeSeverity(s.Severity), Title: s.Title,
			})
		}
	}
	return out
}

func normalizeSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return "UNKNOWN"
	}
	return s
}

// countFindings tallies by severity, leaving out what was suppressed. It
// always returns the four keys the columns expect, so a caller can index it
// without a nil check.
func countFindings(rows []finding) map[string]int {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, f := range rows {
		if f.Suppressed {
			continue
		}
		counts[f.Severity]++
	}
	return counts
}

func countKind(rows []finding, kind string) int {
	n := 0
	for _, f := range rows {
		if f.Kind == kind && !f.Suppressed {
			n++
		}
	}
	return n
}

func countSuppressed(rows []finding) int {
	n := 0
	for _, f := range rows {
		if f.Suppressed {
			n++
		}
	}
	return n
}

// activeSuppressions returns the decisions that apply to one repository right
// now: its own and the global ones, minus any that expired. An expired
// suppression is not deleted -- the record of the decision stays -- it simply
// stops applying, and the finding comes back on the next scan.
func activeSuppressions(repoName string) []models.ScanSuppression {
	var all []models.ScanSuppression
	db.DB.Where("repo_name = ? OR repo_name = ''", repoName).Find(&all)
	now := time.Now()
	out := all[:0]
	for _, s := range all {
		if s.ExpiresAt != nil && s.ExpiresAt.Before(now) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// applySuppressions marks the rows a decision covers. A repository-specific
// suppression wins over a global one for the same CVE, and a package-specific
// one over a package-agnostic one, so the most deliberate decision is the one
// shown.
func applySuppressions(rows []finding, sups []models.ScanSuppression) []finding {
	if len(sups) == 0 {
		return rows
	}
	byVuln := map[string][]models.ScanSuppression{}
	for _, s := range sups {
		byVuln[s.VulnID] = append(byVuln[s.VulnID], s)
	}
	for i := range rows {
		var best *models.ScanSuppression
		bestScore := -1
		for j := range byVuln[rows[i].VulnID] {
			s := &byVuln[rows[i].VulnID][j]
			if s.Pkg != "" && s.Pkg != rows[i].Pkg {
				continue
			}
			score := 0
			if s.RepoName != "" {
				score += 2
			}
			if s.Pkg != "" {
				score++
			}
			if score > bestScore {
				best, bestScore = s, score
			}
		}
		if best != nil {
			rows[i].Suppressed = true
			rows[i].Suppression = best
		}
	}
	return rows
}

// reconcileFindings brings the stored rows of one repository and domain in
// step with what a scan just reported. A finding already open keeps its
// first-seen date; one that disappeared is closed, not deleted; one that
// comes back after being closed is opened again as of now, because a CVE
// that returns is a new problem, not the old one resumed.
//
// It returns how many of the rows are being seen for the first time -- the
// "new since the last scan" number that a report should lead with.
//
// notScanned names kinds this pass did not look for -- static analysis that
// failed to run, say. Their open rows are left exactly as they are: closing
// them would report as fixed what nobody checked.
func reconcileFindings(repoName, domain string, rows []finding, at time.Time, notScanned ...string) (newCount int, err error) {
	skip := make(map[string]bool, len(notScanned))
	for _, k := range notScanned {
		skip[k] = true
	}
	// One read of every row this repository and domain ever had, then bulk
	// writes. A row at a time was two queries per finding: an image with two
	// thousand CVEs across a few hundred repositories is millions of queries,
	// and the startup backfill did all of them before the API could listen.
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		var existing []models.ScanFinding
		if err := tx.Where("repo_name = ? AND domain = ?", repoName, domain).Find(&existing).Error; err != nil {
			return err
		}
		byID := make(map[identity]*models.ScanFinding, len(existing))
		for i := range existing {
			byID[findingFromRow(existing[i]).identity()] = &existing[i]
		}

		var touched []uint // still open, nothing but last_seen moves
		var created []models.ScanFinding
		seen := make(map[identity]bool, len(rows))
		for _, r := range rows {
			id := r.identity()
			if seen[id] {
				continue // the same finding twice in one report is one finding
			}
			seen[id] = true

			cur, ok := byID[id]
			switch {
			case !ok:
				created = append(created, models.ScanFinding{
					RepoName: repoName, Domain: r.Domain, Kind: r.Kind, Target: r.Target,
					VulnID: r.VulnID, Pkg: r.Pkg, Line: r.Line, Version: r.Version,
					Fixed: r.Fixed, Severity: r.Severity, Title: r.Title, CWE: r.CWE,
					FirstSeen: at, LastSeen: at,
				})
				newCount++
			case cur.ResolvedAt != nil:
				// It came back: a new problem, not the old one resumed. The
				// row is reopened in place so the unique index holds.
				if err := tx.Model(&models.ScanFinding{}).Where("id = ?", cur.ID).Updates(map[string]any{
					"resolved_at": nil, "first_seen": at, "last_seen": at, "line": r.Line,
					"severity": r.Severity, "fixed": r.Fixed, "version": r.Version, "title": r.Title, "cwe": r.CWE,
				}).Error; err != nil {
					return err
				}
				newCount++
			case cur.Severity != r.Severity || cur.Fixed != r.Fixed || cur.Version != r.Version || cur.Title != r.Title ||
				cur.Line != r.Line || cur.CWE != r.CWE:
				// Severity and the fixed version move as the database learns
				// more, and a weakness's line as the code around it is
				// edited; the identity does not.
				if err := tx.Model(&models.ScanFinding{}).Where("id = ?", cur.ID).Updates(map[string]any{
					"last_seen": at, "line": r.Line, "severity": r.Severity, "fixed": r.Fixed, "version": r.Version,
					"title": r.Title, "cwe": r.CWE,
				}).Error; err != nil {
					return err
				}
			default:
				touched = append(touched, cur.ID)
			}
		}

		var gone []uint
		for id, f := range byID {
			if f.ResolvedAt == nil && !seen[id] && !skip[f.Kind] {
				gone = append(gone, f.ID)
			}
		}

		for _, ids := range chunkIDs(touched, 500) {
			if err := tx.Model(&models.ScanFinding{}).Where("id IN ?", ids).Update("last_seen", at).Error; err != nil {
				return err
			}
		}
		for _, ids := range chunkIDs(gone, 500) {
			if err := tx.Model(&models.ScanFinding{}).Where("id IN ?", ids).Update("resolved_at", at).Error; err != nil {
				return err
			}
		}
		if len(created) > 0 {
			if err := tx.CreateInBatches(&created, 200).Error; err != nil {
				return err
			}
		}
		return nil
	})
	return newCount, err
}

// chunkIDs keeps an IN list under SQLite's bound-parameter limit.
func chunkIDs(ids []uint, size int) [][]uint {
	var out [][]uint
	for len(ids) > size {
		out = append(out, ids[:size])
		ids = ids[size:]
	}
	if len(ids) > 0 {
		out = append(out, ids)
	}
	return out
}

// openFindings reads the current findings of one repository and domain, with
// the suppressions applied, in the order a person should read them: worst
// first, then by package so the same library's CVEs sit together.
func openFindings(repoName, domain string) []finding {
	var rows []models.ScanFinding
	db.DB.Where("repo_name = ? AND domain = ? AND resolved_at IS NULL", repoName, domain).Find(&rows)
	out := make([]finding, 0, len(rows))
	for _, r := range rows {
		out = append(out, findingFromRow(r))
	}
	out = applySuppressions(out, activeSuppressions(repoName))
	sortFindings(out)
	return out
}

var severityRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

func sortFindings(rows []finding) {
	rank := func(s string) int {
		if r, ok := severityRank[s]; ok {
			return r
		}
		return 4
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Suppressed != b.Suppressed {
			return !a.Suppressed // the ones that still count come first
		}
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) < rank(b.Severity)
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Pkg != b.Pkg {
			return a.Pkg < b.Pkg
		}
		return a.VulnID < b.VulnID
	})
}

// detailFinding is what the API hands the page for one open finding: the
// row plus the two things only the table knows -- when it arrived, and
// whether anyone has already dealt with it.
type detailFinding struct {
	finding
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// IsNew: seen by exactly one scan, the latest. The first scan of a
	// repository marks everything new, which is the truth.
	IsNew bool `json:"is_new"`
}

func detailFindings(repoName, domain string) []detailFinding {
	var rows []models.ScanFinding
	db.DB.Where("repo_name = ? AND domain = ? AND resolved_at IS NULL", repoName, domain).Find(&rows)
	plain := make([]finding, 0, len(rows))
	byID := make(map[identity]models.ScanFinding, len(rows))
	for _, r := range rows {
		f := findingFromRow(r)
		plain = append(plain, f)
		byID[f.identity()] = r
	}
	plain = applySuppressions(plain, activeSuppressions(repoName))
	sortFindings(plain)
	out := make([]detailFinding, 0, len(plain))
	for _, f := range plain {
		r := byID[f.identity()]
		out = append(out, detailFinding{
			finding: f, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
			IsNew: r.FirstSeen.Equal(r.LastSeen),
		})
	}
	return out
}

// recountRepo recomputes a repository's stored counts from its open findings,
// without a scan. A suppression changes what counts the moment it is made;
// waiting a day for the rescan to notice would make the button look broken.
// The history gets a point too, because the dashboard total moved and the
// trend has to say so.
func recountRepo(repoName string) {
	var result models.ScanResult
	if db.DB.Where("repo_name = ?", repoName).First(&result).Error != nil {
		return
	}
	code := openFindings(repoName, FindingDomainCode)
	image := openFindings(repoName, FindingDomainImage)
	c, i := countFindings(code), countFindings(image)
	updates := map[string]any{
		"critical": c["CRITICAL"], "high": c["HIGH"], "medium": c["MEDIUM"], "low": c["LOW"],
		"image_critical": i["CRITICAL"], "image_high": i["HIGH"], "image_medium": i["MEDIUM"], "image_low": i["LOW"],
		"secrets":    countKind(code, FindingSecret),
		"weaknesses": countKind(code, FindingWeakness),
		"suppressed": countSuppressed(code) + countSuppressed(image),
	}
	// Not Save: that would move UpdatedAt, which the dashboards read as
	// "last scanned", and nothing was scanned.
	db.DB.Model(&models.ScanResult{}).Where("id = ?", result.ID).UpdateColumns(updates)
	if result.Critical != c["CRITICAL"] || result.High != c["HIGH"] || result.Medium != c["MEDIUM"] || result.Low != c["LOW"] ||
		result.ImageCritical != i["CRITICAL"] || result.ImageHigh != i["HIGH"] || result.ImageMedium != i["MEDIUM"] || result.ImageLow != i["LOW"] {
		recordScanHistory(models.ScanResult{
			RepoName: repoName,
			Critical: c["CRITICAL"], High: c["HIGH"], Medium: c["MEDIUM"], Low: c["LOW"],
			ImageCritical: i["CRITICAL"], ImageHigh: i["HIGH"], ImageMedium: i["MEDIUM"], ImageLow: i["LOW"],
		})
	}
}

// BackfillScanFindings gives every repository scanned before findings had
// rows a set of them, read from the report it already stored, dated to that
// scan. Safe on every start: a repository with rows is left alone. It also
// rewrites those stored reports through the current struct, which drops the
// matched text of any secret an older version kept.
//
// It runs in the background after the API is listening, and reads one
// repository's reports at a time. The first version loaded every stored
// report at once before the server started -- megabytes of Trivy JSON per
// repository -- which on a large estate ran the pod out of memory before it
// ever answered, and the gateway in front could only say 502.
func BackfillScanFindings() {
	var done []string
	db.DB.Model(&models.ScanFinding{}).Distinct().Pluck("repo_name", &done)
	have := make(map[string]bool, len(done))
	for _, r := range done {
		have[r] = true
	}
	var todo []models.ScanResult
	db.DB.Select("id", "repo_name", "updated_at").Find(&todo)

	n := 0
	for _, t := range todo {
		if have[t.RepoName] {
			continue
		}
		// The scan workers run alongside: a repository scanned since the list
		// was read already has rows from a newer report, and must be left to it.
		var rowsNow int64
		db.DB.Model(&models.ScanFinding{}).Where("repo_name = ?", t.RepoName).Count(&rowsNow)
		if rowsNow > 0 {
			continue
		}
		var r models.ScanResult
		if db.DB.Select("id", "repo_name", "updated_at", "report", "image_report").First(&r, t.ID).Error != nil {
			continue
		}
		var code, image TrivyReport
		_ = unmarshalReport(r.Report, &code)
		_ = unmarshalReport(r.ImageReport, &image)
		r.Report, r.ImageReport = "", ""
		if _, err := reconcileFindings(r.RepoName, FindingDomainCode, findingsFromReport(code, FindingDomainCode), r.UpdatedAt); err != nil {
			fmt.Printf("findings backfill failed for %s: %v\n", r.RepoName, err)
			continue
		}
		if _, err := reconcileFindings(r.RepoName, FindingDomainImage, findingsFromReport(image, FindingDomainImage), r.UpdatedAt); err != nil {
			fmt.Printf("findings backfill failed for %s: %v\n", r.RepoName, err)
			continue
		}
		// UpdateColumns, not Save: the scan date stays the scan's.
		// Only if no scan rewrote the row meanwhile.
		db.DB.Model(&models.ScanResult{}).Where("id = ? AND updated_at = ?", r.ID, r.UpdatedAt).UpdateColumns(map[string]any{
			"report":       marshalReport(code),
			"image_report": marshalReport(image),
		})
		recountRepo(r.RepoName)
		n++
		if n%50 == 0 {
			fmt.Printf("scan findings backfill: %d repositories so far\n", n)
		}
	}
	if n > 0 {
		fmt.Printf("scan findings backfilled for %d repositories\n", n)
	}
}

// ---- suppressions API --------------------------------------------------

var suppressionReasons = map[string]bool{
	"false_positive": true, "not_affected": true, "accepted_risk": true, "fix_planned": true,
}

// ListScanSuppressions returns the decisions that apply to a repository (its
// own and the global ones), or every decision when no repository is given.
func ListScanSuppressions(c *fiber.Ctx) error {
	repo := c.Query("repo")
	var sups []models.ScanSuppression
	q := db.DB.Order("created_at desc")
	if repo != "" {
		q = q.Where("repo_name = ? OR repo_name = ''", repo)
	}
	q.Find(&sups)
	if sups == nil {
		sups = []models.ScanSuppression{}
	}
	return c.JSON(sups)
}

func CreateScanSuppression(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	var req struct {
		RepoName  string `json:"repo_name"`
		VulnID    string `json:"vuln_id"`
		Pkg       string `json:"pkg"`
		Reason    string `json:"reason"`
		Note      string `json:"note"`
		ExpiresAt string `json:"expires_at"` // RFC 3339 or YYYY-MM-DD, optional
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	req.VulnID = strings.TrimSpace(req.VulnID)
	req.Pkg = strings.TrimSpace(req.Pkg)
	req.RepoName = strings.TrimSpace(req.RepoName)
	req.Note = strings.TrimSpace(req.Note)
	if req.VulnID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "vuln_id is required"})
	}
	if !suppressionReasons[req.Reason] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "reason must be one of false_positive, not_affected, accepted_risk, fix_planned"})
	}
	// Accepting a risk without saying why is the one thing an auditor will
	// ask about; a false positive is self-explanatory.
	if req.Reason != "false_positive" && req.Note == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "a note is required for this reason"})
	}
	if req.RepoName != "" {
		var n int64
		db.DB.Model(&models.Repository{}).Where("name = ?", req.RepoName).Count(&n)
		if n == 0 {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
		}
	}
	var expires *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			t, err = time.Parse("2006-01-02", req.ExpiresAt)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "expires_at must be a date"})
			}
			t = t.Add(24*time.Hour - time.Second) // through the end of that day
		}
		if t.Before(time.Now()) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "expires_at is in the past"})
		}
		expires = &t
	}

	var user models.User
	db.DB.Select("email").First(&user, userID)

	// One decision per (repo, cve, pkg): a second one replaces the first
	// rather than leaving two that disagree.
	var existing models.ScanSuppression
	if db.DB.Where("repo_name = ? AND vuln_id = ? AND pkg = ?", req.RepoName, req.VulnID, req.Pkg).First(&existing).Error == nil {
		db.DB.Delete(&existing)
	}
	sup := models.ScanSuppression{
		RepoName: req.RepoName, VulnID: req.VulnID, Pkg: req.Pkg,
		Reason: req.Reason, Note: req.Note, CreatedBy: userID, CreatedByEmail: user.Email,
		ExpiresAt: expires,
	}
	if err := db.DB.Create(&sup).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	db.LogAudit(userID, "suppress_finding", "repository", req.RepoName,
		fmt.Sprintf(`{"vuln_id":%q,"pkg":%q,"reason":%q}`, req.VulnID, req.Pkg, req.Reason), c.IP())

	recountAffected(sup)
	return c.Status(fiber.StatusCreated).JSON(sup)
}

func DeleteScanSuppression(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	var sup models.ScanSuppression
	if err := db.DB.First(&sup, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "suppression not found"})
	}
	db.DB.Delete(&sup)
	db.LogAudit(userID, "unsuppress_finding", "repository", sup.RepoName,
		fmt.Sprintf(`{"vuln_id":%q,"pkg":%q}`, sup.VulnID, sup.Pkg), c.IP())
	recountAffected(sup)
	return c.JSON(fiber.Map{"message": "suppression removed"})
}

// recountAffected refreshes the counts of every repository a decision
// touches: one, or -- for a global suppression -- every repository that has
// that CVE open.
func recountAffected(sup models.ScanSuppression) {
	if sup.RepoName != "" {
		recountRepo(sup.RepoName)
		return
	}
	var repos []string
	db.DB.Model(&models.ScanFinding{}).Where("vuln_id = ? AND resolved_at IS NULL", sup.VulnID).
		Distinct().Pluck("repo_name", &repos)
	for _, r := range repos {
		recountRepo(r)
	}
}
