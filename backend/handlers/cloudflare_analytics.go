package handlers

import (
	"context"
	"fmt"
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

// The analytics page asks Cloudflare's GraphQL Analytics API, section by
// section. Each section is its own query on purpose: what a zone may query
// depends on its plan (bot scores are Enterprise, some fields are Pro and up),
// and GraphQL rejects a whole document over one field it does not allow. One
// query per section means a missing feature blanks that card and says why,
// and everything else still renders.
//
// Two datasets carry everything:
//   - httpRequestsAdaptiveGroups: every request the edge answered.
//   - firewallEventsAdaptiveGroups / firewallEventsAdaptive: every request a
//     security feature acted on -- WAF, custom rules, rate limiting, bot
//     fight, the L7 DDoS ruleset -- with what it did.

var cloudflareRanges = map[string]time.Duration{
	"30m": 30 * time.Minute,
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"3d":  72 * time.Hour,
	"7d":  7 * 24 * time.Hour,
}

// Buckets small enough to see an attack's shape, few enough to draw: about
// 60 to 170 points whatever the range.
func cloudflareBucket(d time.Duration) (string, time.Duration) {
	switch {
	case d <= time.Hour:
		return "datetimeMinute", time.Minute
	case d <= 6*time.Hour:
		return "datetimeFiveMinutes", 5 * time.Minute
	case d <= 24*time.Hour:
		return "datetimeFifteenMinutes", 15 * time.Minute
	default:
		return "datetimeHour", time.Hour
	}
}

// Actions that stopped or challenged the request. "log", "skip", "allow" and
// a solved challenge are recorded as events too, but nothing was mitigated.
func cloudflareMitigating(action string) bool {
	a := strings.ReplaceAll(strings.ToLower(action), "_", "")
	switch a {
	case "block", "drop", "challenge", "jschallenge", "managedchallenge",
		"connectionclose", "forceconnectionclose", "challengefailed", "jschallengefailed", "managedchallengefailed":
		return true
	}
	return false
}

// ---- dataset limits --------------------------------------------------------

// cloudflareLimits is how far one query may reach for a dataset, as the zone's
// plan allows. Zero means unknown, and the request is sent as asked.
type cloudflareLimit struct {
	MaxDuration  time.Duration
	NotOlderThan time.Duration
	MaxPageSize  int
}

type cloudflareLimits map[string]cloudflareLimit

var (
	cfLimitsMu    sync.Mutex
	cfLimitsCache = map[string]struct {
		at     time.Time
		limits cloudflareLimits
	}{}
)

func fetchCloudflareLimits(ctx context.Context, cf *services.CloudflareClient, zoneID string) (cloudflareLimits, error) {
	cfLimitsMu.Lock()
	if hit, ok := cfLimitsCache[zoneID]; ok && time.Since(hit.at) < time.Hour {
		cfLimitsMu.Unlock()
		return hit.limits, nil
	}
	cfLimitsMu.Unlock()

	datasets := []string{"httpRequestsAdaptiveGroups", "firewallEventsAdaptiveGroups", "firewallEventsAdaptive"}
	var b strings.Builder
	for _, d := range datasets {
		fmt.Fprintf(&b, "%s { maxDuration maxPageSize notOlderThan } ", d)
	}
	query := `query($zoneTag: string) { viewer { zones(filter: {zoneTag: $zoneTag}) { settings { ` + b.String() + `} } } }`
	var out struct {
		Viewer struct {
			Zones []struct {
				Settings map[string]*struct {
					MaxDuration  int64 `json:"maxDuration"`
					MaxPageSize  int   `json:"maxPageSize"`
					NotOlderThan int64 `json:"notOlderThan"`
				} `json:"settings"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	if err := cf.GraphQL(ctx, query, map[string]interface{}{"zoneTag": zoneID}, &out); err != nil {
		return nil, err
	}
	if len(out.Viewer.Zones) == 0 {
		return nil, fmt.Errorf("the token cannot see zone %s in the analytics API", zoneID)
	}
	limits := cloudflareLimits{}
	for name, s := range out.Viewer.Zones[0].Settings {
		if s == nil {
			continue
		}
		limits[name] = cloudflareLimit{
			MaxDuration:  time.Duration(s.MaxDuration) * time.Second,
			NotOlderThan: time.Duration(s.NotOlderThan) * time.Second,
			MaxPageSize:  s.MaxPageSize,
		}
	}
	cfLimitsMu.Lock()
	cfLimitsCache[zoneID] = struct {
		at     time.Time
		limits cloudflareLimits
	}{time.Now(), limits}
	cfLimitsMu.Unlock()
	return limits, nil
}

// clamp narrows [since, until) to what the dataset allows in one query.
func (l cloudflareLimits) clamp(dataset string, since, until time.Time) (time.Time, bool) {
	lim, ok := l[dataset]
	if !ok {
		return since, false
	}
	clamped := false
	if lim.MaxDuration > 0 && until.Sub(since) > lim.MaxDuration {
		since, clamped = until.Add(-lim.MaxDuration), true
	}
	if lim.NotOlderThan > 0 {
		// A minute of margin: the boundary moves while the query is in flight.
		oldest := time.Now().Add(-lim.NotOlderThan + time.Minute)
		if since.Before(oldest) {
			since, clamped = oldest, true
		}
	}
	return since, clamped
}

// ---- query building ---------------------------------------------------------

// gqlFilter writes a filter as a GraphQL literal. Every value comes from this
// file -- timestamps, numbers, fixed strings -- never from the request, and
// strings go through strconv.Quote, so nothing can break out of it.
func gqlFilter(f map[string]interface{}) string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		var v string
		switch x := f[k].(type) {
		case string:
			v = strconv.Quote(x)
		case time.Time:
			v = strconv.Quote(x.UTC().Format(time.RFC3339))
		case int:
			v = strconv.Itoa(x)
		case int64:
			v = strconv.FormatInt(x, 10)
		case []string:
			q := make([]string, len(x))
			for i, s := range x {
				q[i] = strconv.Quote(s)
			}
			v = "[" + strings.Join(q, ", ") + "]"
		}
		parts = append(parts, k+": "+v)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

type cfGroup struct {
	Count      int64                  `json:"count"`
	Sum        map[string]float64     `json:"sum"`
	Dimensions map[string]interface{} `json:"dimensions"`
}

func (g cfGroup) dim(name string) string {
	switch v := g.Dimensions[name].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

type cfGroupQuery struct {
	Dataset string
	Filter  map[string]interface{}
	Dims    []string
	Sums    []string
	OrderBy string
	Limit   int
}

func (q cfGroupQuery) node(alias string) string {
	var fields []string
	fields = append(fields, "count")
	if len(q.Dims) > 0 {
		fields = append(fields, "dimensions { "+strings.Join(q.Dims, " ")+" }")
	}
	if len(q.Sums) > 0 {
		fields = append(fields, "sum { "+strings.Join(q.Sums, " ")+" }")
	}
	args := fmt.Sprintf("limit: %d, filter: %s", q.Limit, gqlFilter(q.Filter))
	if q.OrderBy != "" {
		args += ", orderBy: [" + q.OrderBy + "]"
	}
	return fmt.Sprintf("%s: %s(%s) { %s }", alias, q.Dataset, args, strings.Join(fields, " "))
}

// runCloudflareGroups sends one or more group queries as a single document
// and returns each alias's rows.
func runCloudflareGroups(ctx context.Context, cf *services.CloudflareClient, zoneID string, queries map[string]cfGroupQuery) (map[string][]cfGroup, error) {
	aliases := make([]string, 0, len(queries))
	for a := range queries {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	var b strings.Builder
	for _, a := range aliases {
		b.WriteString(queries[a].node(a))
		b.WriteString(" ")
	}
	query := `query($zoneTag: string) { viewer { zones(filter: {zoneTag: $zoneTag}) { ` + b.String() + `} } }`
	var out struct {
		Viewer struct {
			Zones []map[string][]cfGroup `json:"zones"`
		} `json:"viewer"`
	}
	if err := cf.GraphQL(ctx, query, map[string]interface{}{"zoneTag": zoneID}, &out); err != nil {
		return nil, err
	}
	if len(out.Viewer.Zones) == 0 {
		return nil, fmt.Errorf("zone not visible to this token")
	}
	return out.Viewer.Zones[0], nil
}

func runCloudflareGroup(ctx context.Context, cf *services.CloudflareClient, zoneID string, q cfGroupQuery) ([]cfGroup, error) {
	res, err := runCloudflareGroups(ctx, cf, zoneID, map[string]cfGroupQuery{"rows": q})
	if err != nil {
		return nil, err
	}
	return res["rows"], nil
}

// ---- heuristics -------------------------------------------------------------

// Paths nobody asks for by accident: the scanners walk the internet asking
// every host for the same handful of files. A hit on one does not prove an
// attack, but a list of them answered 404 is what reconnaissance looks like.
var cfProbePatterns = []struct {
	re     *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`(?i)/\.env|/\.aws|/\.ssh|/\.docker|/\.npmrc|/\.htpasswd|/\.htaccess`), "secrets file"},
	{regexp.MustCompile(`(?i)/\.git|/\.svn|/\.hg|/\.ds_store`), "source control metadata"},
	{regexp.MustCompile(`(?i)wp-login|wp-admin|xmlrpc\.php|wp-content|wp-includes|wlwmanifest`), "WordPress probe"},
	{regexp.MustCompile(`(?i)phpmyadmin|/pma/|adminer|/mysql/`), "database admin probe"},
	{regexp.MustCompile(`(?i)\.\./|%2e%2e|/etc/passwd|/proc/self|win\.ini`), "path traversal"},
	{regexp.MustCompile(`(?i)serviceaccountkey\.json|credentials\.json|/\.terraform|\.tfstate|/\.kube/|/\.gcloud|/\.azure|/\.boto|application_default_credentials`), "cloud credentials"},
	{regexp.MustCompile(`(?i)icecoder|elfinder|filemanager|file-manager|/terminal|terminal-xhr|webshell|/c99|/r57|/wso\.php|/alfa|/shell\.php|/cmd\.php|/up\.php|/adminer`), "web shell / file manager"},
	{regexp.MustCompile(`(?i)/cgi-bin/|/boaform|/hnap1|/gponform|/setup\.cgi|/shell|/cmd\.|/eval-stdin`), "device / RCE exploit"},
	{regexp.MustCompile(`(?i)/vendor/phpunit|/actuator|/jolokia|/solr/|/console/|/manager/html|/jmx-console|/_ignition`), "framework exploit"},
	{regexp.MustCompile(`(?i)\.(sql|bak|old|backup|swp|zip|tar|tgz|gz|7z)$`), "backup / dump file"},
	{regexp.MustCompile(`(?i)/server-status|/config\.(json|php|yml|yaml)|/phpinfo|/info\.php|/debug`), "configuration disclosure"},
	{regexp.MustCompile(`(?i)/owa/|/autodiscover|/ecp/|/remote/login|/global-protect|/vpn/`), "edge appliance probe"},
}

func cloudflareProbeReason(path string) string {
	for _, p := range cfProbePatterns {
		if p.re.MatchString(path) {
			return p.reason
		}
	}
	return ""
}

var (
	cfScannerUA = regexp.MustCompile(`(?i)zgrab|masscan|nmap|nikto|sqlmap|nuclei|wpscan|\w*buster|ffuf|acunetix|nessus|openvas|netsparker|qualys|censys|shodan|expanse|l9explore|httpx|fuzz`)
	cfBotUA     = regexp.MustCompile(`(?i)bot\b|bot/|crawl|spider|slurp|curl/|wget/|python|go-http-client|java/|okhttp|libwww|httpclient|axios|node-fetch|undici|scrapy|headless|phantomjs|puppeteer|playwright|postman|insomnia|monitor|uptime|pingdom|feedfetcher|facebookexternalhit|preview|ruby|perl|php/|guzzle|dart/|reqwest`)
	cfBrowserUA = regexp.MustCompile(`(?i)mozilla/5\.0.*(chrome|safari|firefox|edg|opr)/`)
)

// cloudflareUAClass sorts a user agent into the four groups the Bots tab
// shows. It is a reading of the header, which the client chooses -- the
// honest name for it is "declared", and the bot score is what to trust where
// the plan has one.
func cloudflareUAClass(ua string) string {
	switch {
	case strings.TrimSpace(ua) == "":
		return "empty"
	case cfScannerUA.MatchString(ua):
		return "scanner"
	case cfBotUA.MatchString(ua):
		return "automated"
	case cfBrowserUA.MatchString(ua):
		return "browser"
	default:
		return "other"
	}
}

// ---- the endpoint -----------------------------------------------------------

type cfSection struct {
	Data  interface{} `json:"data,omitempty"`
	Error string      `json:"error,omitempty"`
}

type cfKeyCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

func keyCounts(rows []cfGroup, dim string) []cfKeyCount {
	out := make([]cfKeyCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, cfKeyCount{Key: r.dim(dim), Count: r.Count})
	}
	return out
}

var (
	cfAnalyticsMu    sync.Mutex
	cfAnalyticsCache = map[string]struct {
		at   time.Time
		body fiber.Map
	}{}
)

// Cloudflare allows 300 GraphQL queries per five minutes, shared by every
// zone a token can see, and one page load costs about twenty. A minute of
// cache keeps a few people on the same page from spending that quota.
const cfAnalyticsTTL = time.Minute

func invalidateCloudflareCache(zoneID string) {
	cfAnalyticsMu.Lock()
	for k := range cfAnalyticsCache {
		if strings.HasPrefix(k, zoneID+"|") {
			delete(cfAnalyticsCache, k)
		}
	}
	cfAnalyticsMu.Unlock()
	cfLimitsMu.Lock()
	delete(cfLimitsCache, zoneID)
	cfLimitsMu.Unlock()
}

func GetCloudflareAnalytics(c *fiber.Ctx) error {
	zone, err := cloudflareZoneParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "zone not found"})
	}
	rangeKey := c.Query("range", "24h")
	span, ok := cloudflareRanges[rangeKey]
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "range must be one of 30m, 1h, 6h, 24h, 3d, 7d"})
	}

	ctx, cancel := context.WithTimeout(c.Context(), 60*time.Second)
	defer cancel()
	body, at, err := cachedCloudflareAnalytics(ctx, zone, rangeKey, span)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(withCachedAt(body, at))
}

// cachedCloudflareAnalytics is the analytics payload for a zone and range,
// from the cache when it is fresh. The WAF suggestions read the same payload,
// so opening that tab after the overview costs no further queries.
func cachedCloudflareAnalytics(ctx context.Context, zone *models.CloudflareZone, rangeKey string, span time.Duration) (fiber.Map, time.Time, error) {
	cacheKey := zone.ZoneID + "|" + rangeKey
	cfAnalyticsMu.Lock()
	hit, cached := cfAnalyticsCache[cacheKey]
	cfAnalyticsMu.Unlock()
	if cached && time.Since(hit.at) < cfAnalyticsTTL {
		return hit.body, hit.at, nil
	}
	body, err := buildCloudflareAnalytics(ctx, zone.ZoneID, cloudflareToken(zone), span)
	if err != nil {
		return nil, time.Time{}, err
	}
	body["range"] = rangeKey
	now := time.Now()
	cfAnalyticsMu.Lock()
	cfAnalyticsCache[cacheKey] = struct {
		at   time.Time
		body fiber.Map
	}{now, body}
	cfAnalyticsMu.Unlock()
	return body, now, nil
}

// withCachedAt answers with a copy: the cached map is shared by every request
// that hits it, and is never written to after it is stored.
func withCachedAt(body fiber.Map, at time.Time) fiber.Map {
	out := fiber.Map{"cached_at": at}
	for k, v := range body {
		out[k] = v
	}
	return out
}

func buildCloudflareAnalytics(ctx context.Context, zoneID, token string, span time.Duration) (fiber.Map, error) {
	cf := services.NewCloudflareClient(token)
	limits, err := fetchCloudflareLimits(ctx, cf, zoneID)
	if err != nil {
		return nil, err
	}

	// Cloudflare's adaptive datasets lag the edge by a minute or two; ending
	// the window on a whole minute, one back, keeps the last point from
	// always reading as a drop.
	until := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	since := until.Add(-span)
	bucketDim, step := cloudflareBucket(span)
	since = since.Truncate(step)

	var notices []string
	httpSince, httpClamped := limits.clamp("httpRequestsAdaptiveGroups", since, until)
	fwSince, fwClamped := limits.clamp("firewallEventsAdaptiveGroups", since, until)
	if httpClamped {
		notices = append(notices, fmt.Sprintf("Top lists for traffic cover the last %s: this zone's plan allows one query to reach that far.", humanDuration(until.Sub(httpSince))))
	}
	if fwClamped {
		notices = append(notices, fmt.Sprintf("Top lists for security events cover the last %s: this zone's plan allows one query to reach that far.", humanDuration(until.Sub(fwSince))))
	}

	httpWin := func(extra map[string]interface{}) map[string]interface{} {
		f := map[string]interface{}{"datetime_geq": httpSince, "datetime_lt": until, "requestSource": "eyeball"}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	fwWin := map[string]interface{}{"datetime_geq": fwSince, "datetime_lt": until}

	sections := map[string]*cfSection{}
	var mu sync.Mutex
	set := func(name string, data interface{}, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			sections[name] = &cfSection{Error: err.Error()}
			return
		}
		sections[name] = &cfSection{Data: data}
	}

	// Five at a time: fast enough for a page, and gentle on the per-token
	// rate limit when several zones share one.
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn()
		}()
	}

	top := func(name, dataset string, filter map[string]interface{}, dims []string, limit int, shape func([]cfGroup) interface{}) {
		run(func() {
			rows, err := runCloudflareGroup(ctx, cf, zoneID, cfGroupQuery{
				Dataset: dataset, Filter: filter, Dims: dims, OrderBy: "count_DESC", Limit: limit,
			})
			if err != nil {
				set(name, nil, err)
				return
			}
			set(name, shape(rows), nil)
		})
	}
	byKey := func(dim string) func([]cfGroup) interface{} {
		return func(rows []cfGroup) interface{} { return keyCounts(rows, dim) }
	}

	// -- time series: the full range, split into as many queries as the plan
	// needs. These are the two numbers worth seeing over the whole week even
	// where the top lists cannot reach that far.
	run(func() {
		series, note, err := cloudflareSeries(ctx, cf, zoneID, limits, "httpRequestsAdaptiveGroups",
			map[string]interface{}{"requestSource": "eyeball"}, bucketDim, step, since, until,
			[]string{"edgeResponseBytes", "visits"}, nil)
		if note != "" {
			mu.Lock()
			notices = append(notices, note)
			mu.Unlock()
		}
		set("traffic", series, err)
	})
	run(func() {
		series, _, err := cloudflareSeries(ctx, cf, zoneID, limits, "firewallEventsAdaptiveGroups",
			map[string]interface{}{}, bucketDim, step, since, until, nil, []string{"action"})
		set("mitigation", series, err)
	})

	// -- traffic
	top("status", "httpRequestsAdaptiveGroups", httpWin(nil), []string{"edgeResponseStatus"}, 60, byKey("edgeResponseStatus"))
	top("paths", "httpRequestsAdaptiveGroups", httpWin(nil), []string{"clientRequestPath"}, 20, byKey("clientRequestPath"))
	top("hosts", "httpRequestsAdaptiveGroups", httpWin(nil), []string{"clientRequestHTTPHost"}, 15, byKey("clientRequestHTTPHost"))
	top("countries", "httpRequestsAdaptiveGroups", httpWin(nil), []string{"clientCountryName"}, 20, byKey("clientCountryName"))
	top("methods", "httpRequestsAdaptiveGroups", httpWin(nil), []string{"clientRequestHTTPMethodName"}, 12, byKey("clientRequestHTTPMethodName"))
	top("cache", "httpRequestsAdaptiveGroups", httpWin(nil), []string{"cacheStatus"}, 20, byKey("cacheStatus"))
	top("ips", "httpRequestsAdaptiveGroups", httpWin(nil), []string{"clientIP", "clientCountryName"}, 20, func(rows []cfGroup) interface{} {
		type ip struct {
			IP      string `json:"ip"`
			Country string `json:"country"`
			Count   int64  `json:"count"`
		}
		out := make([]ip, 0, len(rows))
		for _, r := range rows {
			out = append(out, ip{r.dim("clientIP"), r.dim("clientCountryName"), r.Count})
		}
		return out
	})
	top("probes", "httpRequestsAdaptiveGroups", httpWin(map[string]interface{}{"edgeResponseStatus_geq": 400, "edgeResponseStatus_lt": 500}),
		[]string{"clientRequestPath"}, 25, func(rows []cfGroup) interface{} {
			type probe struct {
				Path   string `json:"path"`
				Count  int64  `json:"count"`
				Reason string `json:"reason,omitempty"`
			}
			out := make([]probe, 0, len(rows))
			for _, r := range rows {
				p := r.dim("clientRequestPath")
				out = append(out, probe{p, r.Count, cloudflareProbeReason(p)})
			}
			return out
		})
	top("user_agents", "httpRequestsAdaptiveGroups", httpWin(nil), []string{"userAgent"}, 100, func(rows []cfGroup) interface{} {
		type ua struct {
			UA    string `json:"ua"`
			Class string `json:"class"`
			Count int64  `json:"count"`
		}
		out := make([]ua, 0, len(rows))
		for _, r := range rows {
			v := r.dim("userAgent")
			out = append(out, ua{v, cloudflareUAClass(v), r.Count})
		}
		return out
	})

	// -- bots. Bot scores exist only with Bot Management; the section says so
	// when the plan refuses it, and the page falls back to user agents.
	top("bot_scores", "httpRequestsAdaptiveGroups", httpWin(nil), []string{"botScore"}, 100, func(rows []cfGroup) interface{} {
		buckets := map[string]int64{"automated": 0, "likely_automated": 0, "likely_human": 0, "not_scored": 0}
		for _, r := range rows {
			s, err := strconv.Atoi(r.dim("botScore"))
			switch {
			case err != nil || s <= 0:
				buckets["not_scored"] += r.Count
			case s == 1:
				buckets["automated"] += r.Count
			case s < 30:
				buckets["likely_automated"] += r.Count
			default:
				buckets["likely_human"] += r.Count
			}
		}
		return buckets
	})
	top("verified_bots", "httpRequestsAdaptiveGroups", httpWin(nil), []string{"verifiedBotCategory"}, 20, byKey("verifiedBotCategory"))

	// -- security events
	top("fw_actions", "firewallEventsAdaptiveGroups", fwWin, []string{"action"}, 30, func(rows []cfGroup) interface{} {
		type act struct {
			Action    string `json:"action"`
			Count     int64  `json:"count"`
			Mitigated bool   `json:"mitigated"`
		}
		out := make([]act, 0, len(rows))
		for _, r := range rows {
			a := r.dim("action")
			out = append(out, act{a, r.Count, cloudflareMitigating(a)})
		}
		return out
	})
	top("fw_sources", "firewallEventsAdaptiveGroups", fwWin, []string{"source"}, 30, byKey("source"))
	top("fw_paths", "firewallEventsAdaptiveGroups", fwWin, []string{"clientRequestPath"}, 20, func(rows []cfGroup) interface{} {
		type p struct {
			Path   string `json:"path"`
			Count  int64  `json:"count"`
			Reason string `json:"reason,omitempty"`
		}
		out := make([]p, 0, len(rows))
		for _, r := range rows {
			v := r.dim("clientRequestPath")
			out = append(out, p{v, r.Count, cloudflareProbeReason(v)})
		}
		return out
	})
	top("fw_countries", "firewallEventsAdaptiveGroups", fwWin, []string{"clientCountryName"}, 20, byKey("clientCountryName"))
	top("fw_ips", "firewallEventsAdaptiveGroups", fwWin, []string{"clientIP", "clientCountryName", "clientAsn"}, 20, func(rows []cfGroup) interface{} {
		type ip struct {
			IP      string `json:"ip"`
			Country string `json:"country"`
			ASN     string `json:"asn"`
			Count   int64  `json:"count"`
		}
		out := make([]ip, 0, len(rows))
		for _, r := range rows {
			out = append(out, ip{r.dim("clientIP"), r.dim("clientCountryName"), r.dim("clientAsn"), r.Count})
		}
		return out
	})
	top("fw_rules", "firewallEventsAdaptiveGroups", fwWin, []string{"ruleId", "source", "description"}, 20, func(rows []cfGroup) interface{} {
		type rule struct {
			RuleID      string `json:"rule_id"`
			Source      string `json:"source"`
			Description string `json:"description"`
			Count       int64  `json:"count"`
		}
		out := make([]rule, 0, len(rows))
		for _, r := range rows {
			out = append(out, rule{r.dim("ruleId"), r.dim("source"), r.dim("description"), r.Count})
		}
		return out
	})

	run(func() {
		events, err := cloudflareRecentEvents(ctx, cf, zoneID, fwSince, until)
		set("events", events, err)
	})

	wg.Wait()

	return fiber.Map{
		"since":          since,
		"until":          until,
		"top_since":      httpSince,
		"fw_since":       fwSince,
		"bucket_seconds": int(step / time.Second),
		"notices":        notices,
		"sections":       sections,
	}, nil
}

type cfPoint struct {
	T         time.Time `json:"t"`
	Requests  int64     `json:"requests,omitempty"`
	Bytes     float64   `json:"bytes,omitempty"`
	Visits    float64   `json:"visits,omitempty"`
	Mitigated int64     `json:"mitigated,omitempty"`
	Other     int64     `json:"other,omitempty"`
}

// cloudflareSeries reads one dataset over the whole range in buckets, in as
// many windows as the plan's per-query limit makes necessary (up to eight),
// and fills the buckets nothing happened in with zero so the chart does not
// draw a line straight across an empty hour.
//
// For the firewall dataset, splitBy names the action dimension: each bucket
// is then divided into mitigated and other events.
func cloudflareSeries(ctx context.Context, cf *services.CloudflareClient, zoneID string, limits cloudflareLimits,
	dataset string, base map[string]interface{}, bucketDim string, step time.Duration, since, until time.Time,
	sums []string, splitBy []string) ([]cfPoint, string, error) {

	note := ""
	window := until.Sub(since)
	lim := limits[dataset]
	if lim.MaxDuration > 0 && lim.MaxDuration < window {
		window = lim.MaxDuration
	}
	if lim.NotOlderThan > 0 {
		oldest := time.Now().Add(-lim.NotOlderThan + time.Minute).Truncate(step).Add(step)
		if since.Before(oldest) {
			since = oldest
			note = fmt.Sprintf("Charts start %s ago: this zone's plan keeps no older data.", humanDuration(until.Sub(since)))
		}
	}
	const maxWindows = 8
	if until.Sub(since) > window*maxWindows {
		since = until.Add(-window * maxWindows).Truncate(step).Add(step)
		note = fmt.Sprintf("Charts cover the last %s: reaching further would take more queries than this zone's plan allows per page.", humanDuration(until.Sub(since)))
	}

	pageSize := 10000
	if lim.MaxPageSize > 0 && lim.MaxPageSize < pageSize {
		pageSize = lim.MaxPageSize
	}

	points := map[int64]*cfPoint{}
	point := func(t time.Time) *cfPoint {
		k := t.Truncate(step).Unix()
		p, ok := points[k]
		if !ok {
			p = &cfPoint{T: t.Truncate(step)}
			points[k] = p
		}
		return p
	}

	for start := since; start.Before(until); start = start.Add(window) {
		end := start.Add(window)
		if end.After(until) {
			end = until
		}
		f := map[string]interface{}{"datetime_geq": start, "datetime_lt": end}
		for k, v := range base {
			f[k] = v
		}
		rows, err := runCloudflareGroup(ctx, cf, zoneID, cfGroupQuery{
			Dataset: dataset, Filter: f, Dims: append([]string{bucketDim}, splitBy...), Sums: sums,
			OrderBy: bucketDim + "_ASC", Limit: pageSize,
		})
		if err != nil {
			return nil, note, err
		}
		for _, r := range rows {
			t, err := time.Parse(time.RFC3339, r.dim(bucketDim))
			if err != nil {
				continue
			}
			p := point(t)
			if len(splitBy) > 0 {
				if cloudflareMitigating(r.dim(splitBy[0])) {
					p.Mitigated += r.Count
				} else {
					p.Other += r.Count
				}
				continue
			}
			p.Requests += r.Count
			p.Bytes += r.Sum["edgeResponseBytes"]
			p.Visits += r.Sum["visits"]
		}
	}

	out := make([]cfPoint, 0, int(until.Sub(since)/step)+1)
	for t := since.Truncate(step); t.Before(until); t = t.Add(step) {
		if p, ok := points[t.Unix()]; ok {
			out = append(out, *p)
		} else {
			out = append(out, cfPoint{T: t})
		}
	}
	return out, note, nil
}

// cloudflareRecentEvents is the raw event log behind the security charts: the
// latest requests a security feature acted on, one row each. The extended
// field list is tried first; a plan that refuses one of its fields gets the
// fields every plan has.
func cloudflareRecentEvents(ctx context.Context, cf *services.CloudflareClient, zoneID string, since, until time.Time) ([]map[string]interface{}, error) {
	base := "action source datetime clientIP clientAsn clientCountryName clientRequestPath clientRequestQuery userAgent"
	extended := base + " rayName ruleId clientRequestHTTPHost clientRequestHTTPMethodName edgeResponseStatus description"
	filter := gqlFilter(map[string]interface{}{"datetime_geq": since, "datetime_lt": until})

	try := func(fields string) ([]map[string]interface{}, error) {
		query := `query($zoneTag: string) { viewer { zones(filter: {zoneTag: $zoneTag}) { ` +
			`firewallEventsAdaptive(limit: 100, filter: ` + filter + `, orderBy: [datetime_DESC]) { ` + fields + ` } } } }`
		var out struct {
			Viewer struct {
				Zones []struct {
					Events []map[string]interface{} `json:"firewallEventsAdaptive"`
				} `json:"zones"`
			} `json:"viewer"`
		}
		if err := cf.GraphQL(ctx, query, map[string]interface{}{"zoneTag": zoneID}, &out); err != nil {
			return nil, err
		}
		if len(out.Viewer.Zones) == 0 {
			return []map[string]interface{}{}, nil
		}
		return out.Viewer.Zones[0].Events, nil
	}
	events, err := try(extended)
	if err != nil {
		events, err = try(base)
	}
	if err != nil {
		return nil, err
	}
	for _, e := range events {
		if a, ok := e["action"].(string); ok {
			e["mitigated"] = cloudflareMitigating(a)
		}
		if p, ok := e["clientRequestPath"].(string); ok {
			if r := cloudflareProbeReason(p); r != "" {
				e["probe"] = r
			}
		}
	}
	return events, nil
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int((d+time.Hour)/(24*time.Hour)))
	case d >= time.Hour:
		return fmt.Sprintf("%d hours", int((d+time.Minute)/time.Hour))
	default:
		return fmt.Sprintf("%d minutes", int(d/time.Minute))
	}
}
