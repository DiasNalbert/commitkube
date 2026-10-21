package handlers

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
	"gorm.io/gorm"
)

// Cloudflare zone monitoring. A zone is registered with its zone ID, the
// account it belongs to and an API token; from then on the analytics are read
// from Cloudflare on demand (cloudflare_analytics.go) and a poller checks each
// zone every few minutes against its alert thresholds (cloudflare_poller.go).
//
// The token needs Zone > Zone: Read and Zone > Analytics: Read. Two more are
// optional: Zone > DNS: Read enables the exposure check
// (cloudflare_exposure.go), and Account > Notifications: Read adds
// Cloudflare's own alert history to the zone's log.

// Defaults for a new zone, over a five-minute window.
const (
	defaultCFThreatThreshold    = 1000
	defaultCFDDoSThreshold      = 1
	defaultCFErrorRateThreshold = 5.0
	defaultCFSpikeFactor        = 3.0
)

type cloudflareZoneView struct {
	models.CloudflareZone
	OpenAlerts int64 `json:"open_alerts"`
	Alerts24h  int64 `json:"alerts_24h"`
}

func ListCloudflareZones(c *fiber.Ctx) error {
	var zones []models.CloudflareZone
	db.DB.Order("label").Find(&zones)

	type countRow struct {
		ZoneRefID uint
		N         int64
	}
	var open, recent []countRow
	db.DB.Model(&models.CloudflareAlert{}).Select("zone_ref_id, count(*) as n").
		Where("resolved_at IS NULL AND source = ?", "commitkube").Group("zone_ref_id").Scan(&open)
	db.DB.Model(&models.CloudflareAlert{}).Select("zone_ref_id, count(*) as n").
		Where("started_at >= ?", time.Now().Add(-24*time.Hour)).Group("zone_ref_id").Scan(&recent)
	openBy := map[uint]int64{}
	for _, r := range open {
		openBy[r.ZoneRefID] = r.N
	}
	recentBy := map[uint]int64{}
	for _, r := range recent {
		recentBy[r.ZoneRefID] = r.N
	}

	out := make([]cloudflareZoneView, 0, len(zones))
	for _, z := range zones {
		out = append(out, cloudflareZoneView{CloudflareZone: z, OpenAlerts: openBy[z.ID], Alerts24h: recentBy[z.ID]})
	}
	return c.JSON(out)
}

func GetCloudflareZone(c *fiber.Ctx) error {
	zone, err := cloudflareZoneParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "zone not found"})
	}
	var open int64
	db.DB.Model(&models.CloudflareAlert{}).
		Where("zone_ref_id = ? AND resolved_at IS NULL AND source = ?", zone.ID, "commitkube").Count(&open)
	return c.JSON(cloudflareZoneView{CloudflareZone: *zone, OpenAlerts: open})
}

func cloudflareZoneParam(c *fiber.Ctx) (*models.CloudflareZone, error) {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return nil, err
	}
	var zone models.CloudflareZone
	if err := db.DB.First(&zone, id).Error; err != nil {
		return nil, err
	}
	return &zone, nil
}

func cloudflareToken(z *models.CloudflareZone) string {
	return crypto.DecryptField(crypto.MasterKey(), z.APIToken)
}

// verifyCloudflareZone proves the three values belong together before they
// are saved: the token is live, it can see the zone, the zone is in the
// account given, and it can read analytics. Notification history is only a
// warning -- the zone is monitorable without it.
func verifyCloudflareZone(ctx context.Context, zoneID, accountID, token string) (*services.CloudflareZoneInfo, []string, error) {
	if !services.ValidCloudflareID(zoneID) {
		return nil, nil, errors.New("zone ID must be the 32-character hex ID shown on the zone's Overview page")
	}
	if !services.ValidCloudflareID(accountID) {
		return nil, nil, errors.New("account ID must be the 32-character hex ID shown on the zone's Overview page")
	}
	if strings.TrimSpace(token) == "" {
		return nil, nil, errors.New("API token is required")
	}
	cf := services.NewCloudflareClient(token)
	if err := cf.VerifyToken(ctx, accountID); err != nil {
		return nil, nil, fmt.Errorf("the token was refused: %v", err)
	}
	info, err := cf.GetZone(ctx, zoneID)
	if err != nil {
		return nil, nil, fmt.Errorf("the token cannot read this zone (it needs Zone > Zone: Read): %v", err)
	}
	if info.Account.ID != "" && info.Account.ID != accountID {
		return nil, nil, fmt.Errorf("zone %s belongs to account %s, not %s", info.Name, info.Account.ID, accountID)
	}
	if _, err := fetchCloudflareLimits(ctx, cf, zoneID); err != nil {
		return nil, nil, fmt.Errorf("the token cannot read this zone's analytics (it needs Zone > Analytics: Read): %v", err)
	}
	var warnings []string
	if _, err := cf.ListDNSRecords(ctx, zoneID); err != nil {
		warnings = append(warnings, "The exposure check (origin IPs, open ports, dangling records) needs Zone > DNS: Read ("+err.Error()+")")
	}
	if _, err := cf.AlertHistory(ctx, accountID, time.Now().Add(-time.Hour)); err != nil {
		warnings = append(warnings, "Cloudflare's own alert history will not be shown: the token needs Account > Notifications: Read ("+err.Error()+")")
	}
	return info, warnings, nil
}

type cloudflareZoneRequest struct {
	Label              *string  `json:"label"`
	ZoneID             *string  `json:"zone_id"`
	AccountID          *string  `json:"account_id"`
	APIToken           *string  `json:"api_token"`
	Enabled            *bool    `json:"enabled"`
	ThreatThreshold    *int64   `json:"threat_threshold"`
	DDoSThreshold      *int64   `json:"ddos_threshold"`
	ErrorRateThreshold *float64 `json:"error_rate_threshold"`
	SpikeFactor        *float64 `json:"spike_factor"`
}

func trimmed(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

func (r *cloudflareZoneRequest) applyThresholds(z *models.CloudflareZone) error {
	if r.ThreatThreshold != nil {
		if *r.ThreatThreshold < 0 {
			return errors.New("threat threshold cannot be negative")
		}
		z.ThreatThreshold = *r.ThreatThreshold
	}
	if r.DDoSThreshold != nil {
		if *r.DDoSThreshold < 0 {
			return errors.New("DDoS threshold cannot be negative")
		}
		z.DDoSThreshold = *r.DDoSThreshold
	}
	if r.ErrorRateThreshold != nil {
		if *r.ErrorRateThreshold < 0 || *r.ErrorRateThreshold > 100 {
			return errors.New("error rate threshold is a percentage between 0 and 100")
		}
		z.ErrorRateThreshold = *r.ErrorRateThreshold
	}
	if r.SpikeFactor != nil {
		if *r.SpikeFactor < 0 {
			return errors.New("spike factor cannot be negative")
		}
		z.SpikeFactor = *r.SpikeFactor
	}
	return nil
}

// VerifyCloudflareZone checks credentials without saving them, for the form's
// Test button. Given an existing zone's id and no token, it re-checks the
// stored one.
func VerifyCloudflareZone(c *fiber.Ctx) error {
	var req struct {
		cloudflareZoneRequest
		ID uint `json:"id"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	zoneID, accountID, token := trimmed(req.ZoneID), trimmed(req.AccountID), trimmed(req.APIToken)
	if req.ID != 0 {
		var z models.CloudflareZone
		if err := db.DB.First(&z, req.ID).Error; err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "zone not found"})
		}
		if zoneID == "" {
			zoneID = z.ZoneID
		}
		if accountID == "" {
			accountID = z.AccountID
		}
		if token == "" {
			token = cloudflareToken(&z)
		}
	}
	ctx, cancel := context.WithTimeout(c.Context(), 45*time.Second)
	defer cancel()
	info, warnings, err := verifyCloudflareZone(ctx, zoneID, accountID, token)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{
		"zone_name": info.Name, "account_name": info.Account.Name,
		"plan": info.Plan.Name, "status": info.Status, "warnings": warnings,
	})
}

func CreateCloudflareZone(c *fiber.Ctx) error {
	var req cloudflareZoneRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	zoneID, accountID, token := strings.ToLower(trimmed(req.ZoneID)), strings.ToLower(trimmed(req.AccountID)), trimmed(req.APIToken)

	var existing int64
	db.DB.Model(&models.CloudflareZone{}).Where("zone_id = ?", zoneID).Count(&existing)
	if existing > 0 {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "this zone is already being monitored"})
	}

	ctx, cancel := context.WithTimeout(c.Context(), 45*time.Second)
	defer cancel()
	info, warnings, err := verifyCloudflareZone(ctx, zoneID, accountID, token)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	zone := models.CloudflareZone{
		CreatedBy:          currentUserID(c),
		Label:              trimmed(req.Label),
		ZoneID:             zoneID,
		AccountID:          accountID,
		APIToken:           crypto.EncryptField(crypto.MasterKey(), token),
		ZoneName:           info.Name,
		AccountName:        info.Account.Name,
		Plan:               info.Plan.Name,
		Status:             info.Status,
		Enabled:            true,
		ThreatThreshold:    defaultCFThreatThreshold,
		DDoSThreshold:      defaultCFDDoSThreshold,
		ErrorRateThreshold: defaultCFErrorRateThreshold,
		SpikeFactor:        defaultCFSpikeFactor,
	}
	if zone.Label == "" {
		zone.Label = info.Name
	}
	if req.Enabled != nil {
		zone.Enabled = *req.Enabled
	}
	if err := req.applyThresholds(&zone); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := db.DB.Create(&zone).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	db.LogAudit(currentUserID(c), "create_cloudflare_zone", "cloudflare_zone", zone.ZoneName,
		fmt.Sprintf("zone %s, account %s", zone.ZoneID, zone.AccountID), c.IP())

	// The first measurement now rather than at the next tick, so the new
	// card does not sit empty for up to five minutes.
	go pollCloudflareZone(zone.ID)
	go func(z models.CloudflareZone) {
		cfExposureMu.Lock()
		defer cfExposureMu.Unlock()
		scanCloudflareExposure(&z)
	}(zone)

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": zone.ID, "warnings": warnings})
}

func UpdateCloudflareZone(c *fiber.Ctx) error {
	zone, err := cloudflareZoneParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "zone not found"})
	}
	var req cloudflareZoneRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.ZoneID != nil && strings.ToLower(trimmed(req.ZoneID)) != zone.ZoneID {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "the zone ID cannot change; add the other zone separately"})
	}

	// New credentials are verified before they replace the ones that work.
	newAccount := strings.ToLower(trimmed(req.AccountID))
	newToken := trimmed(req.APIToken)
	changedCreds := (newAccount != "" && newAccount != zone.AccountID) || newToken != ""
	var warnings []string
	if changedCreds {
		account := zone.AccountID
		if newAccount != "" {
			account = newAccount
		}
		token := cloudflareToken(zone)
		if newToken != "" {
			token = newToken
		}
		ctx, cancel := context.WithTimeout(c.Context(), 45*time.Second)
		defer cancel()
		info, w, err := verifyCloudflareZone(ctx, zone.ZoneID, account, token)
		if err != nil {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
		}
		warnings = w
		zone.AccountID = account
		zone.APIToken = crypto.EncryptField(crypto.MasterKey(), token)
		zone.ZoneName, zone.AccountName, zone.Plan, zone.Status = info.Name, info.Account.Name, info.Plan.Name, info.Status
		zone.LastError, zone.HistoryError = "", ""
	}

	if l := trimmed(req.Label); l != "" {
		zone.Label = l
	}
	if req.Enabled != nil {
		zone.Enabled = *req.Enabled
	}
	if err := req.applyThresholds(zone); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := db.DB.Save(zone).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	invalidateCloudflareCache(zone.ZoneID)
	details := "settings"
	if changedCreds {
		details = "settings and credentials"
	}
	db.LogAudit(currentUserID(c), "update_cloudflare_zone", "cloudflare_zone", zone.ZoneName, details, c.IP())
	return c.JSON(fiber.Map{"ok": true, "warnings": warnings})
}

func DeleteCloudflareZone(c *fiber.Ctx) error {
	zone, err := cloudflareZoneParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "zone not found"})
	}
	db.DB.Where("zone_ref_id = ?", zone.ID).Delete(&models.CloudflareAlert{})
	db.DB.Where("zone_ref_id = ?", zone.ID).Delete(&models.CloudflareExposure{})
	db.DB.Delete(zone)
	invalidateCloudflareCache(zone.ZoneID)
	db.LogAudit(currentUserID(c), "delete_cloudflare_zone", "cloudflare_zone", zone.ZoneName, zone.ZoneID, c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

// PollCloudflareZoneNow runs the alert checks for one zone immediately and
// returns the zone as it stands afterwards.
func PollCloudflareZoneNow(c *fiber.Ctx) error {
	zone, err := cloudflareZoneParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "zone not found"})
	}
	pollCloudflareZone(zone.ID)
	db.DB.First(zone, zone.ID)
	return c.JSON(zone)
}

// ListCloudflareAlerts serves the alert log, for one zone (:id) or for all of
// them. Filters: status (open, resolved), source, severity, q, days.
func ListCloudflareAlerts(c *fiber.Ctx) error {
	q := db.DB.Model(&models.CloudflareAlert{})
	if c.Params("id") != "" {
		zone, err := cloudflareZoneParam(c)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "zone not found"})
		}
		q = q.Where("zone_ref_id = ?", zone.ID)
	}
	days := c.QueryInt("days", 30)
	if days < 1 || days > 365 {
		days = 30
	}
	q = q.Where("started_at >= ?", time.Now().AddDate(0, 0, -days))

	// Counts are taken before the status/source/severity filters, so the
	// filter chips can show what each choice would return.
	type facet struct {
		K string
		N int64
	}
	var bySeverity, bySource []facet
	q.Session(&gorm.Session{}).Select("severity as k, count(*) as n").Group("severity").Scan(&bySeverity)
	q.Session(&gorm.Session{}).Select("source as k, count(*) as n").Group("source").Scan(&bySource)
	var openCount int64
	q.Session(&gorm.Session{}).Where("resolved_at IS NULL AND source = ?", "commitkube").Count(&openCount)

	switch c.Query("status") {
	case "open":
		q = q.Where("resolved_at IS NULL AND source = ?", "commitkube")
	case "resolved":
		q = q.Where("resolved_at IS NOT NULL OR source <> ?", "commitkube")
	}
	if s := c.Query("source"); s != "" {
		q = q.Where("source = ?", s)
	}
	if s := c.Query("severity"); s != "" {
		q = q.Where("severity = ?", s)
	}
	if s := strings.TrimSpace(c.Query("q")); s != "" {
		like := "%" + strings.ToLower(s) + "%"
		q = q.Where("lower(title) LIKE ? OR lower(message) LIKE ? OR lower(alert_type) LIKE ?", like, like, like)
	}
	limit := c.QueryInt("limit", 200)
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	var alerts []models.CloudflareAlert
	q.Order("started_at DESC, id DESC").Limit(limit).Find(&alerts)

	toMap := func(rows []facet) map[string]int64 {
		m := map[string]int64{}
		for _, r := range rows {
			m[r.K] = r.N
		}
		return m
	}
	return c.JSON(fiber.Map{
		"alerts":      alerts,
		"open":        openCount,
		"by_severity": toMap(bySeverity),
		"by_source":   toMap(bySource),
	})
}
