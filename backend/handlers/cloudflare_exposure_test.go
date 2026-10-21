package handlers

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

// fakeInternetDB answers per IP from a map; an IP missing from it is "never
// seen" (404), and one in fail answers 500.
type fakeInternetDB struct {
	mu    sync.Mutex
	hosts map[string]services.InternetDBHost
	fail  map[string]bool
	asked []string
}

func (f *fakeInternetDB) start(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		ip := strings.TrimPrefix(r.URL.Path, "/")
		f.asked = append(f.asked, ip)
		if f.fail[ip] {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		h, ok := f.hosts[ip]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"detail":"No information available"}`))
			return
		}
		json.NewEncoder(w).Encode(h)
	}))
	t.Cleanup(srv.Close)
	prev := services.InternetDBURL
	services.InternetDBURL = srv.URL
	t.Cleanup(func() { services.InternetDBURL = prev })
}

func setupExposureTest(t *testing.T) (*fakeCloudflare, *fakeInternetDB, *models.CloudflareZone) {
	fake, z := setupCloudflareTest(t)
	db.DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_cfa_open_key ON cloudflare_alerts (zone_ref_id, alert_type, external_id) WHERE resolved_at IS NULL AND source = 'commitkube'")
	idb := &fakeInternetDB{hosts: map[string]services.InternetDBHost{}, fail: map[string]bool{}}
	idb.start(t)

	prevLookup := cfLookupHost
	cfLookupHost = func(ctx context.Context, host string) ([]string, error) {
		if strings.Contains(host, "gone") {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []string{"192.0.2.1"}, nil
	}
	t.Cleanup(func() { cfLookupHost = prevLookup })

	fake.dns = []services.CloudflareDNSRecord{
		{Type: "A", Name: "example.com", Content: "198.51.100.10", Proxied: true},
		{Type: "A", Name: "www.example.com", Content: "198.51.100.10", Proxied: true},
		{Type: "A", Name: "legacy.example.com", Content: "203.0.113.5", Proxied: false},
		{Type: "A", Name: "mail.example.com", Content: "203.0.113.25", Proxied: false},
		{Type: "A", Name: "intranet.example.com", Content: "10.1.2.3", Proxied: false},
		{Type: "CNAME", Name: "docs.example.com", Content: "old-docs.gone.herokuapp.com", Proxied: true},
		{Type: "CNAME", Name: "blog.example.com", Content: "example.github.io", Proxied: true},
		{Type: "CNAME", Name: "app.example.com", Content: "missing.example.com", Proxied: true},
		{Type: "MX", Name: "example.com", Content: "mail.example.com"},
		{Type: "TXT", Name: "example.com", Content: `"v=spf1 include:_spf.example.net ~all"`},
	}
	// The origin answers 443 to anyone, and runs a Redis on the side.
	idb.hosts["198.51.100.10"] = services.InternetDBHost{IP: "198.51.100.10", Ports: []int{443, 6379, 80},
		Vulns: []string{"CVE-2023-0001"}, CPEs: []string{"cpe:/a:nginx:nginx:1.18.0"}}
	idb.hosts["203.0.113.5"] = services.InternetDBHost{IP: "203.0.113.5", Ports: []int{22, 443, 31080}}
	return fake, idb, z
}

func findingsByType(res *cfExposureResult) map[string][]cfExposureFinding {
	out := map[string][]cfExposureFinding{}
	for _, f := range res.Findings {
		out[f.Type] = append(out[f.Type], f)
	}
	return out
}

func TestCloudflareExposureFindings(t *testing.T) {
	_, idb, z := setupExposureTest(t)
	res, err := buildCloudflareExposure(context.Background(), z)
	if err != nil {
		t.Fatal(err)
	}
	by := findingsByType(res)

	if f := by["origin_exposed"]; len(f) != 1 || f[0].Key != "198.51.100.10" || !strings.Contains(f[0].Detail, "80, 443") {
		t.Errorf("origin exposure: %+v", f)
	}
	ports := map[string]string{}
	for _, f := range by["exposed_port"] {
		ports[f.Key] = f.Severity
	}
	want := map[string]string{"198.51.100.10:6379": "critical", "203.0.113.5:22": "medium", "203.0.113.5:31080": "high"}
	for k, sev := range want {
		if ports[k] != sev {
			t.Errorf("port %s: severity %q, want %q (all: %v)", k, ports[k], sev, ports)
		}
	}
	if _, ok := ports["203.0.113.5:443"]; ok {
		t.Error("443 on a DNS-only host is expected and should not be a finding")
	}
	if len(by["known_vulns"]) != 1 {
		t.Errorf("known_vulns: %+v", by["known_vulns"])
	}

	dangling := map[string]string{}
	for _, f := range by["dangling_cname"] {
		dangling[f.Key] = f.Severity
	}
	if dangling["docs.example.com"] != "critical" {
		t.Errorf("a dead Heroku CNAME is a takeover risk, got %v", dangling)
	}
	if dangling["app.example.com"] != "high" {
		t.Errorf("a CNAME to a missing name in the zone is dangling, got %v", dangling)
	}
	if _, ok := dangling["blog.example.com"]; ok {
		t.Error("a CNAME that resolves was reported dangling")
	}

	dnsOnly := map[string]bool{}
	for _, f := range by["dns_only_record"] {
		dnsOnly[f.Key] = true
	}
	if !dnsOnly["legacy.example.com"] || dnsOnly["mail.example.com"] || dnsOnly["intranet.example.com"] {
		t.Errorf("DNS-only findings: %v (mail is expected DNS-only; the private IP is reported on its own)", dnsOnly)
	}
	if len(by["private_ip_in_dns"]) != 1 {
		t.Errorf("private IP: %+v", by["private_ip_in_dns"])
	}
	for _, ip := range idb.asked {
		if ip == "10.1.2.3" {
			t.Error("a private IP was sent to InternetDB")
		}
	}

	var spf, dmarc bool
	for _, f := range by["email_auth"] {
		spf = spf || f.Key == "spf"
		dmarc = dmarc || f.Key == "dmarc"
	}
	if spf || !dmarc {
		t.Errorf("email auth: SPF is present (no finding), DMARC is missing (finding); got spf=%v dmarc=%v", spf, dmarc)
	}
	if res.Findings[0].Severity != "critical" {
		t.Errorf("findings not sorted by severity: first is %s", res.Findings[0].Severity)
	}
}

func TestCloudflareExposureAlertLifecycle(t *testing.T) {
	_, idb, z := setupExposureTest(t)
	scanCloudflareExposure(z)

	openKeys := func() map[string]bool {
		var rows []models.CloudflareAlert
		db.DB.Where("zone_ref_id = ? AND resolved_at IS NULL AND source = ?", z.ID, "commitkube").Find(&rows)
		out := map[string]bool{}
		for _, r := range rows {
			out[r.AlertType+"|"+r.ExternalID] = true
		}
		return out
	}
	open := openKeys()
	for _, k := range []string{"origin_exposed|198.51.100.10", "exposed_port|198.51.100.10:6379", "exposed_port|203.0.113.5:22",
		"exposed_port|203.0.113.5:31080", "known_vulns|198.51.100.10", "dangling_cname|docs.example.com"} {
		if !open[k] {
			t.Errorf("expected open alert %s; open: %v", k, open)
		}
	}
	if open["dns_only_record|legacy.example.com"] {
		t.Error("posture findings must not page anyone")
	}

	// Same picture again: nothing new is opened.
	var before, after int64
	db.DB.Model(&models.CloudflareAlert{}).Count(&before)
	scanCloudflareExposure(z)
	db.DB.Model(&models.CloudflareAlert{}).Count(&after)
	if before != after {
		t.Errorf("an unchanged zone opened %d more alerts", after-before)
	}

	// Redis is firewalled off; the DNS-only host cannot be looked up this
	// time. The Redis alert resolves; the other host's alerts are left as
	// they were, since nobody looked.
	h := idb.hosts["198.51.100.10"]
	h.Ports = []int{443, 80}
	idb.hosts["198.51.100.10"] = h
	idb.fail["203.0.113.5"] = true
	scanCloudflareExposure(z)
	open = openKeys()
	if open["exposed_port|198.51.100.10:6379"] {
		t.Error("the closed Redis port is still open as an alert")
	}
	if !open["exposed_port|203.0.113.5:22"] || !open["exposed_port|203.0.113.5:31080"] {
		t.Error("a failed lookup resolved alerts it could not re-check")
	}

	var row models.CloudflareExposure
	db.DB.Where("zone_ref_id = ?", z.ID).First(&row)
	if row.Error != "" || row.Result == "" {
		t.Errorf("exposure row not stored: error=%q", row.Error)
	}
}

func TestCloudflareExposureKeepsLastResultOnFailure(t *testing.T) {
	fake, _, z := setupExposureTest(t)
	scanCloudflareExposure(z)
	fake.dns = nil
	// A token that lost DNS read: the check fails, the last result stays.
	prev := services.CloudflareAPI
	services.CloudflareAPI = "http://127.0.0.1:1" // nothing listens
	defer func() { services.CloudflareAPI = prev }()
	scanCloudflareExposure(z)
	var row models.CloudflareExposure
	db.DB.Where("zone_ref_id = ?", z.ID).First(&row)
	if row.Error == "" || !strings.Contains(row.Result, "198.51.100.10") {
		t.Errorf("want the error and the previous result, got error=%q result=%d bytes", row.Error, len(row.Result))
	}
}
