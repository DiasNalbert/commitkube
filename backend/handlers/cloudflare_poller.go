package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

// The Cloudflare poller does two things for each enabled zone, every pass:
//
//  1. Measures the last five minutes and evaluates the zone's threshold rules.
//     A rule that breaches opens one alert, which stays the same row while
//     the breach continues and resolves on the first window that is clean,
//     so a ten-minute attack is one entry with a peak, not two.
//  2. Copies the account's Cloudflare notification history -- the alerts
//     Cloudflare itself sent -- into the same log, once each.

const cfWindow = 5 * time.Minute

var cfPollMu sync.Mutex

func PollCloudflare() {
	if !cfPollMu.TryLock() {
		return // a slow pass is still running; skipping is better than piling up
	}
	defer cfPollMu.Unlock()

	var zones []models.CloudflareZone
	db.DB.Where("enabled = ?", true).Find(&zones)
	for _, z := range zones {
		pollCloudflareZoneLocked(&z)
	}
	syncCloudflareHistory(zones)
	pruneCloudflareAlerts()
}

// pollCloudflareZone is the single-zone pass, for a newly added zone and for
// the Check now button.
func pollCloudflareZone(id uint) {
	cfPollMu.Lock()
	defer cfPollMu.Unlock()
	var z models.CloudflareZone
	if err := db.DB.First(&z, id).Error; err != nil {
		return
	}
	pollCloudflareZoneLocked(&z)
	syncCloudflareHistory([]models.CloudflareZone{z})
}

type cfWindowStats struct {
	Requests  int64
	Errors5xx int64
	Baseline  int64 // requests in the hour before the window
	Mitigated int64
	DDoS      int64
	BySource  map[string]int64
}

func measureCloudflareWindow(ctx context.Context, cf *services.CloudflareClient, zoneID string, until time.Time) (*cfWindowStats, error) {
	since := until.Add(-cfWindow)
	win := func(extra map[string]interface{}) map[string]interface{} {
		f := map[string]interface{}{"datetime_geq": since, "datetime_lt": until, "requestSource": "eyeball"}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	httpRes, err := runCloudflareGroups(ctx, cf, zoneID, map[string]cfGroupQuery{
		"total":    {Dataset: "httpRequestsAdaptiveGroups", Filter: win(nil), Limit: 1},
		"errors":   {Dataset: "httpRequestsAdaptiveGroups", Filter: win(map[string]interface{}{"edgeResponseStatus_geq": 500}), Limit: 1},
		"baseline": {Dataset: "httpRequestsAdaptiveGroups", Filter: map[string]interface{}{"datetime_geq": since.Add(-time.Hour), "datetime_lt": since, "requestSource": "eyeball"}, Limit: 1},
	})
	if err != nil {
		return nil, fmt.Errorf("traffic: %w", err)
	}
	first := func(rows []cfGroup) int64 {
		if len(rows) == 0 {
			return 0
		}
		return rows[0].Count
	}
	s := &cfWindowStats{
		Requests:  first(httpRes["total"]),
		Errors5xx: first(httpRes["errors"]),
		Baseline:  first(httpRes["baseline"]),
		BySource:  map[string]int64{},
	}

	fw, err := runCloudflareGroup(ctx, cf, zoneID, cfGroupQuery{
		Dataset: "firewallEventsAdaptiveGroups",
		Filter:  map[string]interface{}{"datetime_geq": since, "datetime_lt": until},
		Dims:    []string{"action", "source"}, OrderBy: "count_DESC", Limit: 500,
	})
	if err != nil {
		return s, fmt.Errorf("security events: %w", err)
	}
	for _, r := range fw {
		if !cloudflareMitigating(r.dim("action")) {
			continue
		}
		src := r.dim("source")
		s.Mitigated += r.Count
		s.BySource[src] += r.Count
		if strings.Contains(strings.ToLower(src), "ddos") {
			s.DDoS += r.Count
		}
	}
	return s, nil
}

func pollCloudflareZoneLocked(z *models.CloudflareZone) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cf := services.NewCloudflareClient(cloudflareToken(z))

	// The zone's name and plan are read on every pass: one cheap call, and a
	// plan upgrade changes what the analytics can show.
	updates := map[string]interface{}{}
	if info, err := cf.GetZone(ctx, z.ZoneID); err == nil {
		z.ZoneName, z.AccountName, z.Plan, z.Status = info.Name, info.Account.Name, info.Plan.Name, info.Status
		updates["zone_name"], updates["account_name"], updates["plan"], updates["status"] = z.ZoneName, z.AccountName, z.Plan, z.Status
	}

	// One minute back and on a whole minute, as the analytics page does: the
	// adaptive datasets lag the edge, and a window ending "now" would always
	// look quieter than it was.
	until := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	stats, err := measureCloudflareWindow(ctx, cf, z.ZoneID, until)
	updates["last_polled_at"] = time.Now()
	updates["last_error"] = ""
	if err != nil {
		updates["last_error"] = err.Error()
	}
	if stats != nil {
		updates["last_requests"], updates["last_errors_5xx"], updates["last_threats"] = stats.Requests, stats.Errors5xx, stats.Mitigated
	}
	// Only the columns the poller owns: a whole-row save would put back
	// thresholds someone changed while this pass was running.
	db.DB.Model(&models.CloudflareZone{}).Where("id = ?", z.ID).Updates(updates)

	// A failed measurement says nothing about whether the zone is under
	// attack, so it neither opens nor resolves anything.
	if stats == nil {
		return
	}
	name := z.ZoneName
	if name == "" {
		name = z.Label
	}
	breakdown, _ := json.Marshal(map[string]interface{}{
		"window_start": until.Add(-cfWindow), "window_end": until,
		"requests": stats.Requests, "errors_5xx": stats.Errors5xx, "mitigated": stats.Mitigated,
		"mitigated_by_source": stats.BySource, "baseline_requests_per_5m": float64(stats.Baseline) / 12,
	})

	fwOK := err == nil // the security half failed if err is set but stats exist

	if fwOK {
		evaluateCloudflareRule(z, cfRule{
			Type: "ddos_l7", Severity: "critical", Title: "L7 DDoS attack detected",
			Enabled: z.DDoSThreshold > 0, Value: float64(stats.DDoS), Threshold: float64(z.DDoSThreshold),
			Message: fmt.Sprintf("Zone %s had %s requests mitigated by HTTP DDoS protection in the last 5 minutes (threshold: %s).",
				name, thousands(stats.DDoS), thousands(z.DDoSThreshold)),
		}, string(breakdown))
		evaluateCloudflareRule(z, cfRule{
			Type: "threat_spike", Severity: "high", Title: "Threats above threshold",
			Enabled: z.ThreatThreshold > 0, Value: float64(stats.Mitigated), Threshold: float64(z.ThreatThreshold),
			Message: fmt.Sprintf("Zone %s received %s requests classified as threats in the last 5 minutes (threshold: %s).",
				name, thousands(stats.Mitigated), thousands(z.ThreatThreshold)),
		}, string(breakdown))
	}

	// A rate needs a denominator worth dividing by: two 502s out of ten
	// requests at 4 a.m. is not an outage.
	const minRequestsForRate = 100
	rate := 0.0
	if stats.Requests > 0 {
		rate = float64(stats.Errors5xx) / float64(stats.Requests) * 100
	}
	evaluateCloudflareRule(z, cfRule{
		Type: "origin_errors", Severity: "high", Title: "Server errors (5xx) above threshold",
		Enabled: z.ErrorRateThreshold > 0 && stats.Requests >= minRequestsForRate,
		Value:   rate, Threshold: z.ErrorRateThreshold,
		Message: fmt.Sprintf("Zone %s answered %.1f%% of requests with a 5xx in the last 5 minutes (%s of %s; threshold: %.1f%%).",
			name, rate, thousands(stats.Errors5xx), thousands(stats.Requests), z.ErrorRateThreshold),
	}, string(breakdown))

	const minRequestsForSpike = 500
	avg := float64(stats.Baseline) / 12
	factor := 0.0
	if avg > 0 {
		factor = float64(stats.Requests) / avg
	}
	evaluateCloudflareRule(z, cfRule{
		Type: "traffic_spike", Severity: "medium", Title: "Traffic spike",
		Enabled: z.SpikeFactor > 0 && stats.Requests >= minRequestsForSpike && avg > 0,
		Value:   factor, Threshold: z.SpikeFactor,
		Message: fmt.Sprintf("Zone %s received %s requests in the last 5 minutes, %.1fx the previous hour's average of %s (threshold: %.1fx).",
			name, thousands(stats.Requests), factor, thousands(int64(avg)), z.SpikeFactor),
	}, string(breakdown))
}

type cfRule struct {
	Type, Severity, Title, Message string
	Enabled                        bool
	Value, Threshold               float64
}

func evaluateCloudflareRule(z *models.CloudflareZone, r cfRule, details string) {
	breached := r.Enabled && r.Value >= r.Threshold
	// Find rather than First: no open alert is the normal case, and First
	// would log it as an error on every pass.
	var found []models.CloudflareAlert
	db.DB.Where("zone_ref_id = ? AND alert_type = ? AND external_id = ? AND source = ? AND resolved_at IS NULL",
		z.ID, r.Type, "", "commitkube").Limit(1).Find(&found)
	hasOpen := len(found) > 0
	var open models.CloudflareAlert
	if hasOpen {
		open = found[0]
	}
	now := time.Now()

	switch {
	case breached && !hasOpen:
		a := models.CloudflareAlert{
			ZoneRefID: z.ID, Source: "commitkube", AlertType: r.Type, Severity: r.Severity,
			Title: r.Title, Message: r.Message, Value: r.Value, Peak: r.Value, Threshold: r.Threshold,
			StartedAt: now, LastSeenAt: now, Details: details,
		}
		if err := db.DB.Create(&a).Error; err != nil {
			log.Printf("[cloudflare] could not open %s alert for %s: %v", r.Type, z.ZoneName, err)
			return
		}
		notifyCloudflareAlert(z, &a)
	case breached && hasOpen:
		open.Value, open.LastSeenAt, open.Message, open.Details = r.Value, now, r.Message, details
		if r.Value > open.Peak {
			open.Peak = r.Value
		}
		db.DB.Save(&open)
	case !breached && hasOpen:
		open.ResolvedAt = &now
		db.DB.Save(&open)
	}
}

func notifyCloudflareAlert(z *models.CloudflareZone, a *models.CloudflareAlert) {
	event := "cloudflare." + a.AlertType
	if a.Source == "cloudflare" {
		event = "cloudflare.native_alert"
	}
	name := z.ZoneName
	if name == "" {
		name = z.Label
	}
	go SendNotifications(event, "Cloudflare: "+a.Title, a.Message, name, "system")
	go DispatchWebhook(services.WebhookEvent{
		Event: "cloudflare.alert",
		Payload: map[string]interface{}{
			"zone": name, "zone_id": z.ZoneID, "account_id": z.AccountID,
			"alert_type": a.AlertType, "source": a.Source, "severity": a.Severity,
			"title": a.Title, "message": a.Message, "value": a.Value, "threshold": a.Threshold,
			"started_at": a.StartedAt,
		},
	})
}

// syncCloudflareHistory reads each account's notification history once,
// with the first token that is allowed to, and files every alert under the
// zones it names. An alert that names none of the account's zones -- a
// billing or account-wide notice -- is filed under all of them, since each
// is affected by it.
func syncCloudflareHistory(zones []models.CloudflareZone) {
	byAccount := map[string][]models.CloudflareZone{}
	for _, z := range zones {
		byAccount[z.AccountID] = append(byAccount[z.AccountID], z)
	}
	for accountID, accZones := range byAccount {
		since := time.Now().Add(-7 * 24 * time.Hour)
		for _, z := range accZones {
			if z.HistorySyncedAt != nil && z.HistorySyncedAt.Add(-10*time.Minute).After(since) {
				since = z.HistorySyncedAt.Add(-10 * time.Minute)
			}
		}
		firstSync := true
		for _, z := range accZones {
			if z.HistorySyncedAt != nil {
				firstSync = false
			}
		}

		var items []services.CloudflareAlertHistory
		var lastErr error
		fetched := false
		for _, z := range accZones {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			got, err := services.NewCloudflareClient(cloudflareToken(&z)).AlertHistory(ctx, accountID, since)
			cancel()
			if err == nil {
				items, fetched = got, true
				break
			}
			lastErr = err
		}
		now := time.Now()
		ids := make([]uint, 0, len(accZones))
		for _, z := range accZones {
			ids = append(ids, z.ID)
		}
		if !fetched {
			msg := "could not read the account's alert history"
			var cfErr *services.CloudflareError
			if errors.As(lastErr, &cfErr) && (cfErr.Status == 401 || cfErr.Status == 403) {
				msg = "the token needs Account > Notifications: Read to show Cloudflare's own alerts"
			} else if lastErr != nil {
				msg = lastErr.Error()
			}
			db.DB.Model(&models.CloudflareZone{}).Where("id IN ?", ids).Update("history_error", msg)
			continue
		}
		db.DB.Model(&models.CloudflareZone{}).Where("id IN ?", ids).
			Updates(map[string]interface{}{"history_error": "", "history_synced_at": now})

		for _, it := range items {
			targets := cloudflareAlertTargets(it, accZones)
			for _, z := range targets {
				storeCloudflareHistoryItem(&z, it, !firstSync)
			}
		}
	}
}

func cloudflareAlertTargets(it services.CloudflareAlertHistory, zones []models.CloudflareZone) []models.CloudflareZone {
	text := strings.ToLower(it.AlertBody + " " + it.Name + " " + it.Description)
	var matched []models.CloudflareZone
	for _, z := range zones {
		if (z.ZoneName != "" && strings.Contains(text, strings.ToLower(z.ZoneName))) || strings.Contains(text, z.ZoneID) {
			matched = append(matched, z)
		}
	}
	if len(matched) == 0 {
		return zones
	}
	return matched
}

func cloudflareNativeSeverity(alertType string) string {
	t := strings.ToLower(alertType)
	switch {
	case strings.Contains(t, "ddos"):
		return "critical"
	case strings.Contains(t, "origin"), strings.Contains(t, "health"), strings.Contains(t, "error"),
		strings.Contains(t, "waf"), strings.Contains(t, "firewall"), strings.Contains(t, "security"):
		return "high"
	case strings.Contains(t, "ssl"), strings.Contains(t, "cert"), strings.Contains(t, "expir"), strings.Contains(t, "tunnel"):
		return "medium"
	default:
		return "info"
	}
}

func storeCloudflareHistoryItem(z *models.CloudflareZone, it services.CloudflareAlertHistory, notify bool) {
	var exists int64
	db.DB.Model(&models.CloudflareAlert{}).
		Where("zone_ref_id = ? AND source = ? AND external_id = ?", z.ID, "cloudflare", it.ID).Count(&exists)
	if exists > 0 {
		return
	}
	sent, err := time.Parse(time.RFC3339, it.Sent)
	if err != nil {
		sent = time.Now()
	}
	title := it.Name
	if title == "" {
		title = it.Description
	}
	if title == "" {
		title = it.AlertType
	}
	details, _ := json.Marshal(map[string]string{
		"alert_type": it.AlertType, "description": it.Description, "mechanism": it.Mechanism,
		"mechanism_type": it.MechanismType, "policy_id": it.PolicyID, "account_id": z.AccountID,
	})
	a := models.CloudflareAlert{
		ZoneRefID: z.ID, Source: "cloudflare", AlertType: it.AlertType, ExternalID: it.ID,
		Severity: cloudflareNativeSeverity(it.AlertType), Title: title, Message: it.AlertBody,
		StartedAt: sent, LastSeenAt: sent, Details: string(details),
	}
	if err := db.DB.Create(&a).Error; err != nil {
		return // the unique index caught a concurrent copy
	}
	// The first sync backfills a week; announcing all of it again would
	// flood every channel with alerts people already received.
	if notify {
		notifyCloudflareAlert(z, &a)
	}
}

func pruneCloudflareAlerts() {
	days := 90
	if v := os.Getenv("CLOUDFLARE_ALERT_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	db.DB.Where("started_at < ? AND (resolved_at IS NOT NULL OR source <> ?)", time.Now().AddDate(0, 0, -days), "commitkube").
		Delete(&models.CloudflareAlert{})
}

func thousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}
