package handlers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

func TestCloudflareDimensionsByIntrospection(t *testing.T) {
	setupCloudflareTest(t)
	cfSchemaMu.Lock()
	cfSchemaCache = map[string]struct {
		at   time.Time
		dims []string
	}{}
	cfSchemaMu.Unlock()
	dims, err := cloudflareDimensions(context.Background(), services.NewCloudflareClient("tok"), "httpRequestsAdaptiveGroups")
	if err != nil {
		t.Fatal(err)
	}
	if got := pickGeoDimension(dims, `region|subdivision|state|province`); got != "clientRegionCode" {
		t.Errorf("region dimension = %q, want clientRegionCode (never the edge's region)", got)
	}
	if got := pickGeoDimension(dims, `city`); got != "clientCityName" {
		t.Errorf("city dimension = %q, want clientCityName (never coloCity)", got)
	}
	if got := pickGeoDimension([]string{"clientCountryName", "coloCity"}, `city`); got != "" {
		t.Errorf("with only the edge's city available, nothing should be picked; got %q", got)
	}
}

func enabled(b bool) *bool { return &b }

func suggestionsByID(s []cfSuggestion) map[string]cfSuggestion {
	out := map[string]cfSuggestion{}
	for _, x := range s {
		out[x.ID] = x
	}
	return out
}

func TestCloudflareSuggestions(t *testing.T) {
	zone := &models.CloudflareZone{Plan: "Pro Website"}
	var in cfSuggestInput
	in.Paths = []cfKeyCount{{"/api/v1/orders", 50000}, {"/api/v1/login", 9000}, {"/", 8000}}
	in.Countries = []cfKeyCount{{"BR", 90000}, {"US", 3000}, {"CN", 150}}
	in.Probes = append(in.Probes,
		struct {
			Path  string `json:"path"`
			Count int64  `json:"count"`
		}{"/.env", 120},
		struct {
			Path  string `json:"path"`
			Count int64  `json:"count"`
		}{"/.git/config", 40},
		struct {
			Path  string `json:"path"`
			Count int64  `json:"count"`
		}{"/icecoder/lib/file-control.php", 30},
	)
	in.UserAgents = append(in.UserAgents,
		struct {
			UA    string `json:"ua"`
			Class string `json:"class"`
			Count int64  `json:"count"`
		}{"Mozilla/5.0 zgrab/0.x", "scanner", 300},
		struct {
			UA    string `json:"ua"`
			Class string `json:"class"`
			Count int64  `json:"count"`
		}{"", "empty", 400},
	)
	in.FwIPs = append(in.FwIPs,
		struct {
			IP      string `json:"ip"`
			Country string `json:"country"`
			ASN     string `json:"asn"`
			Count   int64  `json:"count"`
		}{"198.51.100.77", "US", "396982", 286},
		struct {
			IP      string `json:"ip"`
			Country string `json:"country"`
			ASN     string `json:"asn"`
			Count   int64  `json:"count"`
		}{"not-an-ip\" or true", "US", "1", 999},
	)
	in.FwCountries = []cfKeyCount{{"CN", 140}, {"BR", 200}}
	in.PostPaths = []cfKeyCount{{"/api/v1/login", 4000}, {"/api/v1/orders", 9000}, {"/api/v1/validate/code\" or true", 5000}}
	in.AuthFails = map[string]int64{"/api/v1/login": 700}

	rules := map[string]*services.CloudflareRuleset{
		"custom": {Rules: []services.CloudflareRule{
			{ID: "r1", Description: "Block git", Action: "block", Expression: `http.request.uri.path contains "/.git"`, Enabled: enabled(true)},
			{ID: "r2", Description: "Old rule", Action: "block", Expression: `ip.src eq 1.1.1.1`, Enabled: enabled(false)},
		}},
		"ratelimit": {Rules: nil},
		"managed":   {Rules: nil},
	}
	got := suggestionsByID(buildCloudflareSuggestions(zone, in, rules, map[string]string{}, 24*time.Hour))

	secrets, ok := got["block_secret_files"]
	if !ok {
		t.Fatal("no suggestion for the .env probes")
	}
	if !strings.Contains(secrets.Expression, `"/.env"`) || strings.Contains(secrets.Expression, `"/.git"`) {
		t.Errorf("/.git is covered by an existing rule and must be left out: %s", secrets.Expression)
	}
	if len(secrets.CoveredBy) == 0 || !strings.Contains(secrets.CoveredBy[0], "Block git") {
		t.Errorf("the covering rule should be named: %v", secrets.CoveredBy)
	}
	if !strings.Contains(got["block_webshells"].Expression, `"icecoder"`) {
		t.Errorf("icecoder probe not turned into a rule: %+v", got["block_webshells"])
	}
	if !strings.Contains(got["block_scanner_ua"].Expression, `lower(http.user_agent) contains "zgrab"`) {
		t.Errorf("scanner UA rule: %+v", got["block_scanner_ua"])
	}
	if _, ok := got["challenge_empty_ua"]; !ok {
		t.Error("400 empty user agents should suggest a challenge")
	}
	ips := got["block_offending_ips"].Expression
	if ips != "ip.src in {198.51.100.77}" {
		t.Errorf("only parsed IPs may reach an expression; got %q", ips)
	}
	if !strings.Contains(got["challenge_hosting_asns"].Expression, "396982") {
		t.Errorf("Google Cloud ASN challenge: %+v", got["challenge_hosting_asns"])
	}
	cn := got["challenge_countries"]
	if !strings.Contains(cn.Expression, `"CN"`) || strings.Contains(cn.Expression, `"BR"`) {
		t.Errorf("only the country sending mostly attacks should be challenged: %q", cn.Expression)
	}

	login, ok := got["ratelimit_api_v1_login"]
	if !ok {
		t.Fatalf("no rate limit for the login endpoint; got %v", keysOf(got))
	}
	if login.Ratelimit == nil || login.Ratelimit.Period != 60 || !contains(login.Ratelimit.Characteristics, "cf.colo.id") {
		t.Errorf("rate limit spec: %+v", login.Ratelimit)
	}
	if !strings.Contains(strings.Join(login.Evidence, " "), "700 of them answered 401/403") {
		t.Errorf("auth failures missing from the evidence: %v", login.Evidence)
	}
	for id, s := range got {
		if strings.Contains(s.Expression, `" or true`) {
			t.Errorf("%s: an attacker-supplied value escaped into an expression: %s", id, s.Expression)
		}
	}
	if _, ok := got["ratelimit_api_v1_orders"]; ok {
		t.Error("/api/v1/orders does not take credentials and should not get a login-style limit")
	}
	if _, ok := got["ratelimit_baseline"]; !ok {
		t.Error("a zone with no rate limiting should get a baseline suggestion")
	}
	if _, ok := got["deploy_managed_ruleset"]; !ok {
		t.Error("a Pro zone without the managed ruleset should be told to deploy it")
	}
	if r := got["review_disabled"]; len(r.Evidence) != 1 || r.Evidence[0] != "Old rule" {
		t.Errorf("disabled rule review: %+v", r)
	}
	all := buildCloudflareSuggestions(zone, in, rules, map[string]string{}, 24*time.Hour)
	for i := 1; i < len(all); i++ {
		if map[string]int{"high": 0, "medium": 1, "low": 2}[all[i-1].Priority] > map[string]int{"high": 0, "medium": 1, "low": 2}[all[i].Priority] {
			t.Errorf("not sorted by priority at %d: %s before %s", i, all[i-1].Priority, all[i].Priority)
		}
	}

	// Free plan: rate limits count over ten seconds, and there is no managed
	// ruleset to deploy.
	free := suggestionsByID(buildCloudflareSuggestions(&models.CloudflareZone{Plan: "Free Website"}, in, rules, map[string]string{}, 24*time.Hour))
	if free["ratelimit_api_v1_login"].Ratelimit.Period != 10 {
		t.Error("Free plans only count over 10 seconds")
	}
	if _, ok := free["deploy_managed_ruleset"]; ok {
		t.Error("the Free plan has no Cloudflare Managed Ruleset to deploy")
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func keysOf(m map[string]cfSuggestion) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}
