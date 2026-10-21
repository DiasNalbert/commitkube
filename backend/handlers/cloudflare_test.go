package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	testZoneID    = "0123456789abcdef0123456789abcdef"
	testAccountID = "fedcba9876543210fedcba9876543210"
)

// fakeCloudflare answers the handful of REST and GraphQL calls the module
// makes. Group queries are answered per alias from the scenario; anything
// else gets one row with placeholder dimensions, which is enough to prove a
// section was asked for and decoded.
type fakeCloudflare struct {
	mu        sync.Mutex
	total     int64
	errors5xx int64
	baseline  int64
	fwRows    []map[string]interface{}
	history   []services.CloudflareAlertHistory
	dns       []services.CloudflareDNSRecord
	refuse    *regexp.Regexp // GraphQL queries matching this get an error
	queries   []string
	maxDurSec int64
}

var (
	cfNodeRe = regexp.MustCompile(`(\w+): (\w+)\(limit: \d+, filter: \{[^}]*\}(?:, orderBy: \[[^\]]*\])?\) \{ count(?: dimensions \{ ([^}]*) \})?`)
)

func (f *fakeCloudflare) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/user/tokens/verify":
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "result": map[string]string{"status": "active"}})
		case r.URL.Path == "/zones/"+testZoneID:
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "result": map[string]interface{}{
				"id": testZoneID, "name": "example.com", "status": "active",
				"plan":    map[string]string{"name": "Free Website"},
				"account": map[string]string{"id": testAccountID, "name": "Example Corp"},
			}})
		case r.URL.Path == "/zones/"+testZoneID+"/dns_records":
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "result": f.dns,
				"result_info": map[string]int{"page": 1, "total_pages": 1}})
		case strings.HasSuffix(r.URL.Path, "/alerting/v3/history"):
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "result": f.history})
		case r.URL.Path == "/graphql":
			var body struct {
				Query string `json:"query"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			f.queries = append(f.queries, body.Query)
			if f.refuse != nil && f.refuse.MatchString(body.Query) {
				json.NewEncoder(w).Encode(map[string]interface{}{"data": nil, "errors": []map[string]string{{"message": "zone does not have access to the field"}}})
				return
			}
			zone := map[string]interface{}{}
			if strings.Contains(body.Query, "settings {") {
				zone["settings"] = map[string]interface{}{
					"httpRequestsAdaptiveGroups":   map[string]int64{"maxDuration": f.maxDurSec, "maxPageSize": 10000, "notOlderThan": 2678400},
					"firewallEventsAdaptiveGroups": map[string]int64{"maxDuration": f.maxDurSec, "maxPageSize": 10000, "notOlderThan": 2678400},
					"firewallEventsAdaptive":       map[string]int64{"maxDuration": f.maxDurSec, "maxPageSize": 10000, "notOlderThan": 2678400},
				}
			}
			if strings.Contains(body.Query, "firewallEventsAdaptive(") {
				zone["firewallEventsAdaptive"] = []map[string]interface{}{
					{"action": "block", "source": "waf", "clientIP": "203.0.113.9", "clientRequestPath": "/.env", "datetime": "2026-10-21T10:00:00Z"},
				}
			}
			for _, m := range cfNodeRe.FindAllStringSubmatch(body.Query, -1) {
				alias, dataset, dims := m[1], m[2], strings.Fields(m[3])
				switch {
				case alias == "total":
					zone[alias] = []map[string]int64{{"count": f.total}}
				case alias == "errors":
					zone[alias] = []map[string]int64{{"count": f.errors5xx}}
				case alias == "baseline":
					zone[alias] = []map[string]int64{{"count": f.baseline}}
				case dataset == "firewallEventsAdaptiveGroups" && strings.Join(dims, " ") == "action source":
					zone[alias] = f.fwRows
				default:
					d := map[string]string{}
					for _, name := range dims {
						if strings.HasPrefix(name, "datetime") {
							d[name] = time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Minute).Format(time.RFC3339)
						} else {
							d[name] = "x"
						}
					}
					zone[alias] = []map[string]interface{}{{"count": 7, "dimensions": d, "sum": map[string]float64{"edgeResponseBytes": 100, "visits": 3}}}
				}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"viewer": map[string]interface{}{"zones": []interface{}{zone}}}})
		default:
			t.Errorf("unexpected Cloudflare call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func setupCloudflareTest(t *testing.T) (*fakeCloudflare, *models.CloudflareZone) {
	t.Helper()
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "cloudflare.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(&models.CloudflareZone{}, &models.CloudflareAlert{}, &models.CloudflareExposure{},
		&models.NotificationConfig{}, &models.WebhookConfig{}); err != nil {
		t.Fatal(err)
	}
	db.DB = gdb

	fake := &fakeCloudflare{maxDurSec: 86400}
	srv := httptest.NewServer(fake.handler(t))
	t.Cleanup(srv.Close)
	prevAPI := services.CloudflareAPI
	services.CloudflareAPI = srv.URL
	t.Cleanup(func() { services.CloudflareAPI = prevAPI })
	cfLimitsMu.Lock()
	cfLimitsCache = map[string]struct {
		at     time.Time
		limits cloudflareLimits
	}{}
	cfLimitsMu.Unlock()

	z := &models.CloudflareZone{
		Label: "Example", ZoneID: testZoneID, AccountID: testAccountID, APIToken: "tok",
		ZoneName: "example.com", Enabled: true,
		ThreatThreshold: 1000, DDoSThreshold: 1, ErrorRateThreshold: 5, SpikeFactor: 3,
	}
	if err := gdb.Create(z).Error; err != nil {
		t.Fatal(err)
	}
	return fake, z
}

func openAlerts(t *testing.T, zoneID uint) map[string]models.CloudflareAlert {
	t.Helper()
	var rows []models.CloudflareAlert
	db.DB.Where("zone_ref_id = ? AND source = ? AND resolved_at IS NULL", zoneID, "commitkube").Find(&rows)
	out := map[string]models.CloudflareAlert{}
	for _, r := range rows {
		out[r.AlertType] = r
	}
	return out
}

func TestCloudflareAlertLifecycle(t *testing.T) {
	fake, z := setupCloudflareTest(t)

	// An attack: 1,500 requests dropped by the DDoS ruleset, 500 blocked by
	// the WAF, 300 only logged. Traffic at ten times the hour before it.
	fake.total, fake.errors5xx, fake.baseline = 10000, 100, 12000
	fake.fwRows = []map[string]interface{}{
		{"count": 1500, "dimensions": map[string]string{"action": "block", "source": "l7ddos"}},
		{"count": 500, "dimensions": map[string]string{"action": "managed_challenge", "source": "waf"}},
		{"count": 300, "dimensions": map[string]string{"action": "log", "source": "firewallManaged"}},
	}
	pollCloudflareZone(z.ID)

	open := openAlerts(t, z.ID)
	for _, typ := range []string{"ddos_l7", "threat_spike", "traffic_spike"} {
		if _, ok := open[typ]; !ok {
			t.Errorf("expected an open %s alert, have %v", typ, keys(open))
		}
	}
	if _, ok := open["origin_errors"]; ok {
		t.Errorf("1%% of requests failing is under the 5%% threshold, but origin_errors opened")
	}
	if got := open["threat_spike"].Value; got != 2000 {
		t.Errorf("threats counted %v, want 2000 (logged events are not mitigated)", got)
	}
	if msg := open["threat_spike"].Message; !strings.Contains(msg, "2,000 requests classified as threats") || !strings.Contains(msg, "threshold: 1,000") {
		t.Errorf("message does not say what happened: %q", msg)
	}

	var zone models.CloudflareZone
	db.DB.First(&zone, z.ID)
	if zone.LastRequests != 10000 || zone.LastThreats != 2000 || zone.LastErrors5xx != 100 || zone.LastPolledAt == nil {
		t.Errorf("zone pulse not recorded: %+v", zone)
	}

	// The attack goes on and grows: still one row per rule, with the peak.
	fake.fwRows[0]["count"] = 4812
	pollCloudflareZone(z.ID)
	var n int64
	db.DB.Model(&models.CloudflareAlert{}).Where("alert_type = ?", "ddos_l7").Count(&n)
	if n != 1 {
		t.Fatalf("a continuing attack opened %d ddos_l7 rows, want 1", n)
	}
	if got := openAlerts(t, z.ID)["ddos_l7"].Peak; got != 4812 {
		t.Errorf("peak = %v, want 4812", got)
	}

	// Quiet again: everything resolves, and nothing is reopened.
	fake.total, fake.errors5xx, fake.baseline, fake.fwRows = 1000, 0, 12000, nil
	pollCloudflareZone(z.ID)
	if open := openAlerts(t, z.ID); len(open) != 0 {
		t.Errorf("alerts still open after a clean window: %v", keys(open))
	}
}

func TestCloudflareFailedMeasurementLeavesAlertsAlone(t *testing.T) {
	fake, z := setupCloudflareTest(t)
	fake.total, fake.baseline = 10000, 12000
	fake.fwRows = []map[string]interface{}{{"count": 5000, "dimensions": map[string]string{"action": "block", "source": "waf"}}}
	pollCloudflareZone(z.ID)
	if _, ok := openAlerts(t, z.ID)["threat_spike"]; !ok {
		t.Fatal("setup: threat_spike did not open")
	}

	// The security dataset fails: that says nothing about the attack, so
	// the alert must neither resolve nor be touched.
	fake.refuse = regexp.MustCompile(`firewallEventsAdaptiveGroups`)
	pollCloudflareZone(z.ID)
	if _, ok := openAlerts(t, z.ID)["threat_spike"]; !ok {
		t.Error("a failed measurement resolved the threat alert")
	}
	var zone models.CloudflareZone
	db.DB.First(&zone, z.ID)
	if !strings.Contains(zone.LastError, "security events") {
		t.Errorf("last_error = %q, want the security events failure", zone.LastError)
	}
}

func TestCloudflareHistoryCopiedOnce(t *testing.T) {
	fake, z := setupCloudflareTest(t)
	fake.history = []services.CloudflareAlertHistory{
		{ID: "h1", Name: "Cloudflare alert: L7 DDoS attack detected", AlertType: "advanced_ddos_attack_l7_alert",
			AlertBody: "Zone example.com is under attack", Mechanism: "soc@example.com", MechanismType: "email",
			Sent: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)},
		{ID: "h2", Name: "Other zone", AlertType: "health_check_status_notification",
			AlertBody: "Zone other.org origin unhealthy", Sent: time.Now().UTC().Format(time.RFC3339)},
	}
	other := models.CloudflareZone{Label: "Other", ZoneID: strings.Repeat("a", 32), AccountID: testAccountID,
		APIToken: "tok", ZoneName: "other.org", Enabled: true}
	db.DB.Create(&other)

	zones := []models.CloudflareZone{*z, other}
	syncCloudflareHistory(zones)
	syncCloudflareHistory(zones)

	var rows []models.CloudflareAlert
	db.DB.Where("source = ?", "cloudflare").Order("zone_ref_id, external_id").Find(&rows)
	if len(rows) != 2 {
		t.Fatalf("want each alert filed once under the zone it names, got %d rows: %+v", len(rows), rows)
	}
	if rows[0].ZoneRefID != z.ID || rows[0].ExternalID != "h1" || rows[0].Severity != "critical" {
		t.Errorf("DDoS alert misfiled: %+v", rows[0])
	}
	if rows[1].ZoneRefID != other.ID || rows[1].ExternalID != "h2" {
		t.Errorf("health alert misfiled: %+v", rows[1])
	}
}

func TestCloudflareAnalyticsDegradesPerSection(t *testing.T) {
	fake, _ := setupCloudflareTest(t)
	// A Free plan: no bot scores, and one query may cover a day at most.
	fake.refuse = regexp.MustCompile(`botScore`)
	body, err := buildCloudflareAnalytics(context.Background(), testZoneID, "tok", 72*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sections := body["sections"].(map[string]*cfSection)
	if s := sections["bot_scores"]; s == nil || s.Error == "" {
		t.Errorf("bot_scores should carry the plan's refusal, got %+v", s)
	}
	for _, name := range []string{"traffic", "mitigation", "paths", "probes", "fw_ips", "events", "user_agents", "status"} {
		if s := sections[name]; s == nil || s.Error != "" || s.Data == nil {
			t.Errorf("section %s should have rendered, got %+v", name, s)
		}
	}
	// Three days at one day per query: the series is read in three windows
	// (four when the range starts mid-hour and is aligned back to the hour),
	// and the top lists are cut to the day the plan allows.
	var seriesQueries int
	for _, q := range fake.queries {
		if strings.Contains(q, "httpRequestsAdaptiveGroups") && strings.Contains(q, "datetimeHour") {
			seriesQueries++
		}
	}
	if seriesQueries < 3 || seriesQueries > 4 {
		t.Errorf("series read in %d queries, want 3 or 4", seriesQueries)
	}
	if notices := body["notices"].([]string); len(notices) == 0 {
		t.Error("the page should be told the top lists cover less than the range")
	}
	if pts := sections["traffic"].Data.([]cfPoint); len(pts) < 72 {
		t.Errorf("series has %d points, want a bucket per hour with the gaps filled", len(pts))
	}
}

func TestCloudflareVerifyRejectsWrongAccount(t *testing.T) {
	setupCloudflareTest(t)
	_, _, err := verifyCloudflareZone(context.Background(), testZoneID, strings.Repeat("b", 32), "tok")
	if err == nil || !strings.Contains(err.Error(), "belongs to account") {
		t.Errorf("a zone in another account was accepted: %v", err)
	}
	if _, _, err := verifyCloudflareZone(context.Background(), "../../user", testAccountID, "tok"); err == nil {
		t.Error("a malformed zone ID reached the API")
	}
}

func TestCloudflareHelpers(t *testing.T) {
	f := gqlFilter(map[string]interface{}{
		"requestSource": `eye"ball`, "edgeResponseStatus_geq": 500,
		"datetime_geq": time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC),
	})
	if want := `{datetime_geq: "2026-10-21T10:00:00Z", edgeResponseStatus_geq: 500, requestSource: "eye\"ball"}`; f != want {
		t.Errorf("gqlFilter = %s, want %s", f, want)
	}
	for ua, want := range map[string]string{
		"":                      "empty",
		"Mozilla/5.0 zgrab/0.x": "scanner",
		"curl/8.4.0":            "automated",
		"Googlebot/2.1 (+http://www.google.com/bot.html)":                                         "automated",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36": "browser",
	} {
		if got := cloudflareUAClass(ua); got != want {
			t.Errorf("cloudflareUAClass(%q) = %s, want %s", ua, got, want)
		}
	}
	for path, want := range map[string]bool{
		"/.env": true, "/wp-login.php": true, "/.git/config": true, "/api/v1/users": false, "/": false,
	} {
		if got := cloudflareProbeReason(path) != ""; got != want {
			t.Errorf("probe(%q) = %v, want %v", path, got, want)
		}
	}
	if got := thousands(4812); got != "4,812" {
		t.Errorf("thousands = %s", got)
	}
	if !cloudflareMitigating("managed_challenge") || cloudflareMitigating("log") || cloudflareMitigating("skip") {
		t.Error("mitigating actions misclassified")
	}
}

func keys(m map[string]models.CloudflareAlert) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
