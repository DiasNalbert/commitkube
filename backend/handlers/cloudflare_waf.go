package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

// The WAF tab: the rules the zone has, how often each one fired, and rules
// worth adding, worked out from the traffic the zone is actually getting.
//
// Suggestions are copy-and-paste: an expression in Cloudflare's rules
// language, the action, and the evidence behind it. Nothing is written to
// Cloudflare from here -- a rule that blocks the wrong thing takes a site
// down, and that decision stays with a person looking at the dashboard.
//
// Every value placed into a suggested expression is one this file controls:
// fixed tokens, IPs parsed by netip, ASNs as integers, two-letter country
// codes, and request paths only when they match a plain path pattern. A path
// an attacker sent can never break out of the quoted string it lands in.

var cfPhases = map[string]string{
	"custom":    "http_request_firewall_custom",
	"ratelimit": "http_ratelimit",
	"managed":   "http_request_firewall_managed",
}

var cfManagedRulesets = map[string]string{
	"efb7b8c949ac4650a09736fc376e9aee": "Cloudflare Managed Ruleset",
	"4814384a9e5d4991b9815dcfc25d2f1f": "Cloudflare OWASP Core Ruleset",
	"c2e184081120413c86c3ab7e14069605": "Cloudflare Exposed Credentials Check",
	"77454fe2d30c4220b5701f6fdfb893ba": "Cloudflare Free Managed Ruleset",
	"aaede80b4d414dc89c443cea61680354": "Cloudflare Leaked Credentials Detection",
}

// Networks of cloud and hosting providers: where scanners rent their
// machines, and where real visitors almost never browse from.
var cfHostingASNs = map[int]string{
	14061: "DigitalOcean", 16509: "Amazon AWS", 14618: "Amazon AWS", 396982: "Google Cloud", 15169: "Google",
	8075: "Microsoft Azure", 24940: "Hetzner", 213230: "Hetzner", 16276: "OVH", 63949: "Akamai Linode",
	20473: "Vultr (Choopa)", 45102: "Alibaba Cloud", 132203: "Tencent Cloud", 31898: "Oracle Cloud",
	51167: "Contabo", 9009: "M247", 200019: "AlexHost", 211252: "Delis", 202425: "IP Volume", 49981: "WorldStream",
}

type cfRateSpec struct {
	Characteristics   []string `json:"characteristics"`
	Period            int      `json:"period"`
	RequestsPerPeriod int      `json:"requests_per_period"`
	MitigationTimeout int      `json:"mitigation_timeout"`
}

type cfSuggestion struct {
	ID         string      `json:"id"`
	Priority   string      `json:"priority"` // high, medium, low
	Title      string      `json:"title"`
	Why        string      `json:"why"`
	Evidence   []string    `json:"evidence"`
	Phase      string      `json:"phase"` // custom, ratelimit, managed
	Action     string      `json:"action,omitempty"`
	Expression string      `json:"expression,omitempty"`
	Ratelimit  *cfRateSpec `json:"ratelimit,omitempty"`
	Caveat     string      `json:"caveat,omitempty"`
	CoveredBy  []string    `json:"covered_by,omitempty"`
	weight     int64
}

// cfSuggestInput is the part of the analytics payload the suggestions read.
type cfSuggestInput struct {
	Paths     []cfKeyCount `json:"paths"`
	Countries []cfKeyCount `json:"countries"`
	Probes    []struct {
		Path  string `json:"path"`
		Count int64  `json:"count"`
	} `json:"probes"`
	UserAgents []struct {
		UA    string `json:"ua"`
		Class string `json:"class"`
		Count int64  `json:"count"`
	} `json:"user_agents"`
	IPs []struct {
		IP    string `json:"ip"`
		Count int64  `json:"count"`
	} `json:"ips"`
	FwPaths []struct {
		Path  string `json:"path"`
		Count int64  `json:"count"`
	} `json:"fw_paths"`
	FwCountries []cfKeyCount `json:"fw_countries"`
	FwIPs       []struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
		ASN     string `json:"asn"`
		Count   int64  `json:"count"`
	} `json:"fw_ips"`
	Events []map[string]interface{} `json:"events"`
	// From the WAF endpoint's own queries.
	PostPaths []cfKeyCount
	AuthFails map[string]int64
}

func decodeSuggestInput(sections map[string]*cfSection) cfSuggestInput {
	in := map[string]interface{}{}
	for name, s := range sections {
		if s != nil && s.Error == "" && s.Data != nil {
			in[name] = s.Data
		}
	}
	raw, _ := json.Marshal(in)
	var out cfSuggestInput
	json.Unmarshal(raw, &out)
	return out
}

// Probe tokens, grouped by the rule they would go into. A token is only
// suggested once something in the zone's traffic has asked for it.
var cfProbeGroups = []struct {
	id, title, why string
	tokens         []string
}{
	{"block_secret_files", "Block requests for secrets and source-control files",
		"Scanners are asking this zone for credentials and repository metadata. No legitimate visitor requests these paths, so blocking them costs nothing and stops the reconnaissance at the edge.",
		[]string{"/.env", "/.git", "/.svn", "/.hg", "/.aws", "/.ssh", "/.docker", "/.npmrc", "/.htpasswd", "/.htaccess", "/.kube",
			"/.terraform", ".tfstate", "serviceaccountkey.json", "credentials.json", "/.ds_store", "/.vscode", "/.idea", "id_rsa", "/etc/passwd"}},
	{"block_webshells", "Block web shell and exploit probes",
		"These paths belong to known exploits, web shells and file managers that attackers look for to take over a server.",
		[]string{"icecoder", "elfinder", "filemanager", "terminal-xhr", "eval-stdin.php", "/vendor/phpunit", "/cgi-bin/", "/boaform",
			"/hnap1", "/goform", "/actuator", "/jolokia", "/_ignition", "/shell", "/cmd.php", "/wso.php", "/c99", "/r57", "/alfa"}},
	{"block_backups", "Block backup and dump downloads",
		"Requests for database dumps and backup files are scanners hoping someone left one in the web root.",
		[]string{".sql", ".bak", ".backup", ".old", ".swp", "/backup", "/dump"}},
	{"block_wordpress", "Block WordPress probes",
		"Something is probing for WordPress, and those requests end in 4xx, so the site is not WordPress. Blocking the paths ends the noise and the brute force against xmlrpc.php and wp-login.php.",
		[]string{"/wp-login.php", "/wp-admin", "/xmlrpc.php", "/wp-content", "/wp-includes", "wlwmanifest.xml", "/wp-json"}},
}

var cfSafePath = regexp.MustCompile(`^/[A-Za-z0-9/_\-.]{1,200}$`)
var cfAuthPath = regexp.MustCompile(`(?i)login|signin|sign-in|/auth|token|session|password|passwd|/otp|2fa|mfa|validate|verify|/code`)

func quoteExpr(s string) string { return strconv.Quote(s) }

func buildCloudflareSuggestions(zone *models.CloudflareZone, in cfSuggestInput, rules map[string]*services.CloudflareRuleset,
	ruleErr map[string]string, span time.Duration) []cfSuggestion {

	var out []cfSuggestion
	custom := rules["custom"]
	rate := rules["ratelimit"]
	managed := rules["managed"]

	// What the zone already stops: the expressions of enabled rules whose
	// action actually mitigates. Coverage is read as substring presence --
	// rough, but it errs on the side of suggesting, never of hiding.
	var active []services.CloudflareRule
	if custom != nil {
		for _, r := range custom.Rules {
			if r.IsEnabled() && cloudflareMitigating(r.Action) {
				active = append(active, r)
			}
		}
	}
	coveredBy := func(token string) string {
		t := strings.ToLower(token)
		for _, r := range active {
			if strings.Contains(strings.ToLower(r.Expression), t) {
				if r.Description != "" {
					return r.Description
				}
				return r.ID
			}
		}
		return ""
	}

	// -- probe paths, from every place a path shows up
	pathCounts := map[string]int64{}
	for _, p := range in.Probes {
		pathCounts[strings.ToLower(p.Path)] += p.Count
	}
	for _, p := range in.FwPaths {
		pathCounts[strings.ToLower(p.Path)] += p.Count
	}
	for _, e := range in.Events {
		if p, ok := e["clientRequestPath"].(string); ok {
			pathCounts[strings.ToLower(p)]++
		}
	}
	for _, g := range cfProbeGroups {
		var tokens []string
		var covered []string
		var total int64
		var evidence []string
		for _, tok := range g.tokens {
			var n int64
			var example string
			for p, c := range pathCounts {
				if strings.Contains(p, tok) {
					n += c
					if example == "" || c > pathCounts[example] {
						example = p
					}
				}
			}
			if n == 0 {
				continue
			}
			if by := coveredBy(tok); by != "" {
				covered = append(covered, fmt.Sprintf("%s (rule %q)", tok, by))
				continue
			}
			tokens = append(tokens, tok)
			total += n
			evidence = append(evidence, fmt.Sprintf("%s requests matching %s, e.g. %s", thousands(n), tok, example))
		}
		if len(tokens) == 0 {
			continue
		}
		parts := make([]string, len(tokens))
		for i, t := range tokens {
			parts[i] = fmt.Sprintf("(http.request.uri.path contains %s)", quoteExpr(t))
		}
		s := cfSuggestion{
			ID: g.id, Title: g.title, Why: g.why, Evidence: evidence, Phase: "custom", Action: "block",
			Expression: strings.Join(parts, " or "), CoveredBy: covered, weight: total,
			Priority: "medium",
		}
		if total >= 50 || g.id == "block_secret_files" {
			s.Priority = "high"
		}
		if g.id == "block_wordpress" {
			s.Caveat = "Skip this one if any part of the site runs WordPress."
		}
		if g.id == "block_backups" {
			s.Caveat = "If the site serves files with these extensions on purpose, narrow the rule to the paths you saw."
		}
		out = append(out, s)
	}

	// -- PHP, when the site serves none
	var phpProbes, phpServed int64
	probeSet := map[string]bool{}
	for _, p := range in.Probes {
		probeSet[strings.ToLower(p.Path)] = true
		if strings.HasSuffix(strings.ToLower(p.Path), ".php") {
			phpProbes += p.Count
		}
	}
	for _, p := range in.Paths {
		lp := strings.ToLower(p.Key)
		if strings.HasSuffix(lp, ".php") && !probeSet[lp] && cloudflareProbeReason(lp) == "" {
			phpServed += p.Count
		}
	}
	if phpProbes >= 20 && phpServed == 0 && coveredBy(`"php"`) == "" && coveredBy(".php") == "" {
		out = append(out, cfSuggestion{
			ID: "block_php", Priority: "high", Phase: "custom", Action: "block",
			Title:      "Block every .php request",
			Why:        "The site serves no PHP that we can see, yet " + thousands(phpProbes) + " requests for .php files came in and were answered 4xx. Most exploit kits target PHP, so one rule removes the whole class.",
			Evidence:   []string{thousands(phpProbes) + " requests for .php paths answered 4xx", "No .php path among the most requested ones"},
			Expression: `http.request.uri.path.extension eq "php"`,
			Caveat:     "Check with the team that nothing behind this zone is PHP, including admin tools on other hostnames of the zone.",
			weight:     phpProbes,
		})
	}

	// -- scanner and empty user agents
	scanners := map[string]int64{}
	var emptyUA int64
	for _, u := range in.UserAgents {
		switch u.Class {
		case "scanner":
			if name := strings.ToLower(cfScannerUA.FindString(u.UA)); name != "" && coveredBy(name) == "" {
				scanners[name] += u.Count
			}
		case "empty":
			emptyUA += u.Count
		}
	}
	if len(scanners) > 0 {
		names := make([]string, 0, len(scanners))
		var total int64
		for n, c := range scanners {
			names = append(names, n)
			total += c
		}
		sort.Strings(names)
		parts := make([]string, len(names))
		ev := make([]string, len(names))
		for i, n := range names {
			parts[i] = fmt.Sprintf("(lower(http.user_agent) contains %s)", quoteExpr(n))
			ev[i] = fmt.Sprintf("%s requests from %s", thousands(scanners[n]), n)
		}
		out = append(out, cfSuggestion{
			ID: "block_scanner_ua", Priority: "high", Phase: "custom", Action: "block",
			Title:      "Block vulnerability scanners by user agent",
			Why:        "These clients announce themselves as vulnerability scanners. Nothing legitimate visits with them.",
			Evidence:   ev,
			Expression: strings.Join(parts, " or "),
			Caveat:     "Scanners can change their user agent; this catches the lazy ones. Keep it alongside the path rules.",
			weight:     total,
		})
	}
	if emptyUA >= 50 && coveredBy(`http.user_agent eq ""`) == "" {
		out = append(out, cfSuggestion{
			ID: "challenge_empty_ua", Priority: "medium", Phase: "custom", Action: "managed_challenge",
			Title:      "Challenge requests without a user agent",
			Why:        "Browsers always send a user agent. Requests without one are scripts, and they were " + thousands(emptyUA) + " in this window.",
			Evidence:   []string{thousands(emptyUA) + " requests with an empty User-Agent"},
			Expression: `(http.user_agent eq "") and not cf.client.bot`,
			Caveat:     "API clients of your own may send no user agent; exclude their paths or hosts first. A challenge blocks any non-browser client.",
			weight:     emptyUA,
		})
	}

	// -- offending IPs and the networks they come from
	var badIPs []string
	var badEvidence []string
	asnEvents := map[int]int64{}
	for _, ip := range in.FwIPs {
		if n, err := strconv.Atoi(ip.ASN); err == nil {
			if _, hosting := cfHostingASNs[n]; hosting {
				asnEvents[n] += ip.Count
			}
		}
		addr, err := netip.ParseAddr(ip.IP)
		if err != nil || ip.Count < 50 || len(badIPs) >= 10 || coveredBy(ip.IP) != "" {
			continue
		}
		badIPs = append(badIPs, addr.String())
		badEvidence = append(badEvidence, fmt.Sprintf("%s (%s, AS%s): %s security events", addr, ip.Country, ip.ASN, thousands(ip.Count)))
	}
	if len(badIPs) > 0 {
		out = append(out, cfSuggestion{
			ID: "block_offending_ips", Priority: "medium", Phase: "custom", Action: "block",
			Title:      "Block the most persistent attacking IPs",
			Why:        "These addresses keep triggering security rules. Blocking them outright saves evaluating every request they send against everything else.",
			Evidence:   badEvidence,
			Expression: "ip.src in {" + strings.Join(badIPs, " ") + "}",
			Caveat:     "Attackers rotate addresses, so this ages quickly. A Cloudflare IP list you add to over time works better than editing the rule each time.",
			weight:     int64(len(badIPs)),
		})
	}
	if len(asnEvents) > 0 {
		var total int64
		var asns []int
		for n, c := range asnEvents {
			if coveredBy(strconv.Itoa(n)) == "" {
				asns = append(asns, n)
				total += c
			}
		}
		sort.Ints(asns)
		if total >= 100 {
			nums := make([]string, len(asns))
			ev := make([]string, len(asns))
			for i, n := range asns {
				nums[i] = strconv.Itoa(n)
				ev[i] = fmt.Sprintf("AS%d %s: %s security events", n, cfHostingASNs[n], thousands(asnEvents[n]))
			}
			out = append(out, cfSuggestion{
				ID: "challenge_hosting_asns", Priority: "medium", Phase: "custom", Action: "managed_challenge",
				Title:      "Challenge traffic from cloud hosting networks",
				Why:        "Most of the attack traffic comes from rented cloud servers. People browse from home and mobile networks, so a challenge here rarely reaches a real visitor.",
				Evidence:   ev,
				Expression: "(ip.src.asnum in {" + strings.Join(nums, " ") + "}) and not cf.client.bot",
				Caveat:     "Your own integrations, monitors and partners may run on these clouds. Check the Traffic tab for API clients from them and exclude their paths before deploying.",
				weight:     total,
			})
		}
	}

	// -- countries that send mostly attacks
	reqByCountry := map[string]int64{}
	var totalReq int64
	for _, c := range in.Countries {
		reqByCountry[c.Key] = c.Count
		totalReq += c.Count
	}
	var hot []string
	var hotEv []string
	var hotTotal int64
	for _, c := range in.FwCountries {
		if !cfCountryCode.MatchString(c.Key) || c.Count < 100 || coveredBy(quoteExpr(c.Key)) != "" {
			continue
		}
		req := reqByCountry[c.Key]
		share := 0.0
		if totalReq > 0 {
			share = float64(req) / float64(totalReq)
		}
		if share >= 0.02 || (req > 0 && float64(c.Count)/float64(req) < 0.3) {
			continue
		}
		hot = append(hot, quoteExpr(c.Key))
		hotEv = append(hotEv, fmt.Sprintf("%s: %s security events against %s requests (%.1f%% of the zone's traffic)", c.Key, thousands(c.Count), thousands(req), share*100))
		hotTotal += c.Count
	}
	if len(hot) > 0 {
		out = append(out, cfSuggestion{
			ID: "challenge_countries", Priority: "low", Phase: "custom", Action: "managed_challenge",
			Title:      "Challenge countries that send mostly attacks",
			Why:        "From these countries, security events are a large part of all requests while real traffic is almost nil.",
			Evidence:   hotEv,
			Expression: "(ip.src.country in {" + strings.Join(hot, " ") + "}) and not cf.client.bot",
			Caveat:     "A challenge, not a block: a real customer abroad can still pass it.",
			weight:     hotTotal,
		})
	}

	// -- rate limiting
	freePlan := strings.Contains(strings.ToLower(zone.Plan), "free")
	period, perPeriod := 60, 10
	if freePlan {
		period, perPeriod = 10, 5 // Free plans count over ten seconds only
	}
	rateCovers := func(path string) bool {
		if rate == nil {
			return false
		}
		for _, r := range rate.Rules {
			if r.IsEnabled() && strings.Contains(r.Expression, path) {
				return true
			}
		}
		return false
	}
	added := 0
	for _, p := range in.PostPaths {
		if added >= 3 || p.Count < 100 || !cfAuthPath.MatchString(p.Key) || !cfSafePath.MatchString(p.Key) || rateCovers(p.Key) {
			continue
		}
		ev := []string{fmt.Sprintf("%s POST requests to %s in the last %s", thousands(p.Count), p.Key, humanDuration(span))}
		if f := in.AuthFails[p.Key]; f > 0 {
			ev = append(ev, fmt.Sprintf("%s of them answered 401/403", thousands(f)))
		}
		out = append(out, cfSuggestion{
			ID: "ratelimit_" + strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(p.Key), "_"), "_"), Priority: "high",
			Phase: "ratelimit", Action: "block",
			Title:      "Rate limit " + p.Key,
			Why:        "It takes credentials or codes, which is what brute force and credential stuffing go after. A per-IP limit leaves people alone and stops scripts.",
			Evidence:   ev,
			Expression: fmt.Sprintf(`(http.request.method eq "POST") and (http.request.uri.path eq %s)`, quoteExpr(p.Key)),
			Ratelimit:  &cfRateSpec{Characteristics: []string{"ip.src", "cf.colo.id"}, Period: period, RequestsPerPeriod: perPeriod, MitigationTimeout: 600},
			Caveat:     "Users behind one office or carrier NAT share an IP. Raise the limit if the Security events tab shows real people being blocked.",
			weight:     p.Count,
		})
		added++
	}
	if rate != nil && len(rate.Rules) == 0 && ruleErr["ratelimit"] == "" {
		// A ceiling well above the busiest client seen, so nobody legitimate
		// meets it: three times the busiest IP's average rate, at least 100 a
		// minute.
		var busiest int64
		for _, ip := range in.IPs {
			if ip.Count > busiest {
				busiest = ip.Count
			}
		}
		minutes := math.Max(1, span.Minutes())
		perMin := math.Max(100, math.Ceil(3*float64(busiest)/minutes/10)*10)
		limit, per := int(perMin), 60
		if freePlan {
			limit, per = int(math.Ceil(perMin/6)), 10
		}
		expr := "true"
		apiShare := int64(0)
		var total int64
		for _, p := range in.Paths {
			total += p.Count
			if strings.HasPrefix(p.Key, "/api/") {
				apiShare += p.Count
			}
		}
		if total > 0 && float64(apiShare)/float64(total) > 0.5 {
			expr = `starts_with(http.request.uri.path, "/api/")`
		}
		out = append(out, cfSuggestion{
			ID: "ratelimit_baseline", Priority: "medium", Phase: "ratelimit", Action: "block",
			Title:      "Add a baseline rate limit",
			Why:        "The zone has no rate limiting at all, so a single client can send as much as it likes. A high per-IP ceiling stops floods and scraping without touching normal use.",
			Evidence:   []string{fmt.Sprintf("Busiest single IP: %s requests in %s (about %.0f a minute)", thousands(busiest), humanDuration(span), float64(busiest)/minutes)},
			Expression: expr,
			Ratelimit:  &cfRateSpec{Characteristics: []string{"ip.src", "cf.colo.id"}, Period: per, RequestsPerPeriod: limit, MitigationTimeout: 60},
			Caveat:     "Set from the traffic in the selected range; a longer range gives a safer number.",
			weight:     busiest,
		})
	}

	// -- managed rulesets
	if managed != nil && ruleErr["managed"] == "" && !freePlan {
		deployed := map[string]bool{}
		for _, r := range managed.Rules {
			if r.Action != "execute" || !r.IsEnabled() {
				continue
			}
			var p struct {
				ID string `json:"id"`
			}
			json.Unmarshal(r.ActionParameters, &p)
			deployed[p.ID] = true
		}
		if !deployed["efb7b8c949ac4650a09736fc376e9aee"] {
			out = append(out, cfSuggestion{
				ID: "deploy_managed_ruleset", Priority: "high", Phase: "managed",
				Title:    "Turn on the Cloudflare Managed Ruleset",
				Why:      "The plan includes Cloudflare's own WAF rules -- SQL injection, XSS, known CVEs, maintained by Cloudflare -- and they are not deployed on this zone.",
				Evidence: []string{"No rule in the managed phase executes the Cloudflare Managed Ruleset"},
				Caveat:   "Deploy it from Security › WAF › Managed rules. Its default actions are tuned to avoid false positives.",
				weight:   1 << 40,
			})
		}
		if !deployed["4814384a9e5d4991b9815dcfc25d2f1f"] {
			out = append(out, cfSuggestion{
				ID: "deploy_owasp", Priority: "low", Phase: "managed",
				Title:    "Consider the OWASP Core Ruleset",
				Why:      "It scores every request against the OWASP ModSecurity rules and catches attack patterns the managed ruleset does not.",
				Evidence: []string{"Not deployed on this zone"},
				Caveat:   "It is noisier. Deploy it with the action set to Log first and raise the paranoia level only after reading what it would block.",
			})
		}
	}

	// -- hygiene of the rules that exist
	if custom != nil {
		var disabled, logOnly []string
		for _, r := range custom.Rules {
			name := r.Description
			if name == "" {
				name = r.ID
			}
			if !r.IsEnabled() {
				disabled = append(disabled, name)
			} else if r.Action == "log" {
				logOnly = append(logOnly, name)
			}
		}
		if len(disabled) > 0 {
			out = append(out, cfSuggestion{ID: "review_disabled", Priority: "low", Phase: "custom",
				Title: "Review disabled rules", Why: "Disabled rules protect nothing. Re-enable the ones still needed and delete the rest, so the list says what is really in force.",
				Evidence: disabled})
		}
		if len(logOnly) > 0 {
			out = append(out, cfSuggestion{ID: "review_log_only", Priority: "low", Phase: "custom",
				Title: "Rules still only logging", Why: "A rule set to Log records matches and lets them through. If what it logs is what you meant to stop, switch it to a mitigating action.",
				Evidence: logOnly})
		}
	}

	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Priority] != rank[out[j].Priority] {
			return rank[out[i].Priority] < rank[out[j].Priority]
		}
		return out[i].weight > out[j].weight
	})
	return out
}

type cfRuleView struct {
	services.CloudflareRule
	Enabled bool   `json:"enabled"`
	Hits    int64  `json:"hits"`
	Ruleset string `json:"ruleset_name,omitempty"` // for managed deployments
}

func GetCloudflareWAF(c *fiber.Ctx) error {
	zone, err := cloudflareZoneParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "zone not found"})
	}
	rangeKey := c.Query("range", "24h")
	span, ok := cloudflareRanges[rangeKey]
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "range must be one of 30m, 1h, 6h, 24h, 3d, 7d"})
	}
	ctx, cancel := context.WithTimeout(c.Context(), 90*time.Second)
	defer cancel()
	cf := services.NewCloudflareClient(cloudflareToken(zone))

	analytics, _, aerr := cachedCloudflareAnalytics(ctx, zone, rangeKey, span)
	limits, _ := fetchCloudflareLimits(ctx, cf, zone.ZoneID)
	until := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	httpSince, _ := limits.clamp("httpRequestsAdaptiveGroups", until.Add(-span), until)
	fwSince, _ := limits.clamp("firewallEventsAdaptiveGroups", until.Add(-span), until)

	rulesets := map[string]*services.CloudflareRuleset{}
	ruleErr := map[string]string{}
	var hits map[string]int64
	var hitsErr string
	var postPaths []cfKeyCount
	authFails := map[string]int64{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for key, phase := range cfPhases {
		wg.Add(1)
		go func(key, phase string) {
			defer wg.Done()
			rs, err := cf.PhaseEntrypoint(ctx, zone.ZoneID, phase)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				msg := err.Error()
				if ce, ok := err.(*services.CloudflareError); ok && (ce.Status == 401 || ce.Status == 403) {
					msg = "the token needs Zone > WAF: Read to list these rules (" + msg + ")"
				}
				ruleErr[key] = msg
				return
			}
			rulesets[key] = rs
		}(key, phase)
	}
	wg.Add(3)
	go func() {
		defer wg.Done()
		rows, err := runCloudflareGroup(ctx, cf, zone.ZoneID, cfGroupQuery{
			Dataset: "firewallEventsAdaptiveGroups", Filter: map[string]interface{}{"datetime_geq": fwSince, "datetime_lt": until},
			Dims: []string{"ruleId"}, OrderBy: "count_DESC", Limit: 1000,
		})
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			hitsErr = err.Error()
			return
		}
		hits = map[string]int64{}
		for _, r := range rows {
			hits[r.dim("ruleId")] += r.Count
		}
	}()
	go func() {
		defer wg.Done()
		rows, err := runCloudflareGroup(ctx, cf, zone.ZoneID, cfGroupQuery{
			Dataset: "httpRequestsAdaptiveGroups",
			Filter:  map[string]interface{}{"datetime_geq": httpSince, "datetime_lt": until, "requestSource": "eyeball", "clientRequestHTTPMethodName": "POST"},
			Dims:    []string{"clientRequestPath"}, OrderBy: "count_DESC", Limit: 40,
		})
		if err == nil {
			mu.Lock()
			postPaths = keyCounts(rows, "clientRequestPath")
			mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		rows, err := runCloudflareGroup(ctx, cf, zone.ZoneID, cfGroupQuery{
			Dataset: "httpRequestsAdaptiveGroups",
			Filter: map[string]interface{}{"datetime_geq": httpSince, "datetime_lt": until, "requestSource": "eyeball",
				"edgeResponseStatus_geq": 401, "edgeResponseStatus_leq": 403},
			Dims: []string{"clientRequestPath", "edgeResponseStatus"}, OrderBy: "count_DESC", Limit: 100,
		})
		if err == nil {
			mu.Lock()
			for _, r := range rows {
				if s := r.dim("edgeResponseStatus"); s == "401" || s == "403" {
					authFails[r.dim("clientRequestPath")] += r.Count
				}
			}
			mu.Unlock()
		}
	}()
	wg.Wait()

	phases := fiber.Map{}
	for key := range cfPhases {
		entry := fiber.Map{}
		if e := ruleErr[key]; e != "" {
			entry["error"] = e
		}
		if rs := rulesets[key]; rs != nil {
			views := make([]cfRuleView, 0, len(rs.Rules))
			for _, r := range rs.Rules {
				v := cfRuleView{CloudflareRule: r, Enabled: r.IsEnabled(), Hits: hits[r.ID]}
				if key == "managed" {
					var p struct {
						ID string `json:"id"`
					}
					json.Unmarshal(r.ActionParameters, &p)
					v.Ruleset = cfManagedRulesets[p.ID]
					if v.Ruleset == "" {
						v.Ruleset = p.ID
					}
				}
				views = append(views, v)
			}
			entry["rules"] = views
			entry["ruleset_id"] = rs.ID
		}
		phases[key] = entry
	}

	body := fiber.Map{"phases": phases, "since": fwSince, "until": until, "hits_error": hitsErr, "plan": zone.Plan}
	if aerr != nil {
		body["suggestions_error"] = "the zone's analytics could not be read, so there is no traffic to base suggestions on: " + aerr.Error()
		body["suggestions"] = []cfSuggestion{}
	} else {
		sections, _ := analytics["sections"].(map[string]*cfSection)
		in := decodeSuggestInput(sections)
		in.PostPaths, in.AuthFails = postPaths, authFails
		body["suggestions"] = buildCloudflareSuggestions(zone, in, rulesets, ruleErr, span)
	}
	return c.JSON(body)
}
