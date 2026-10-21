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
	"github.com/kubecommit/backend/services"
)

// Where requests come from: every country for the world map, and inside one
// country its regions and cities.
//
// Country is a documented dimension. Region and city are not documented
// anywhere this code could check, and guessing a field name would fail the
// whole query. So the dataset's dimensions are read from the live schema by
// introspection -- the same thing Cloudflare's own GraphQL explorer does --
// and the drill-down uses whatever region and city fields actually exist.

type cfTypeRef struct {
	Name   string     `json:"name"`
	Kind   string     `json:"kind"`
	OfType *cfTypeRef `json:"ofType"`
}

func (t *cfTypeRef) named() string {
	for t != nil {
		if t.Name != "" {
			return t.Name
		}
		t = t.OfType
	}
	return ""
}

var (
	cfSchemaMu    sync.Mutex
	cfSchemaCache = map[string]struct {
		at   time.Time
		dims []string
	}{}
)

func cfTypeFields(ctx context.Context, cf *services.CloudflareClient, typeName string) (map[string]string, error) {
	// The name goes in as a quoted literal: Cloudflare declares its own
	// scalars, and a variable typed String! is not guaranteed to match.
	query := `query { __type(name: ` + strconv.Quote(typeName) + `) { fields { name type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } } } }`
	var out struct {
		Type *struct {
			Fields []struct {
				Name string    `json:"name"`
				Type cfTypeRef `json:"type"`
			} `json:"fields"`
		} `json:"__type"`
	}
	if err := cf.GraphQL(ctx, query, nil, &out); err != nil {
		return nil, err
	}
	if out.Type == nil {
		return nil, fmt.Errorf("type %s not in the schema", typeName)
	}
	fields := map[string]string{}
	for _, f := range out.Type.Fields {
		fields[f.Name] = f.Type.named()
	}
	return fields, nil
}

// cloudflareDimensions lists the dimensions a zone dataset can group by,
// walking the schema from the root: viewer > zones > dataset > dimensions.
// The schema is the same for every zone, so the answer is kept for a day.
func cloudflareDimensions(ctx context.Context, cf *services.CloudflareClient, dataset string) ([]string, error) {
	cfSchemaMu.Lock()
	if hit, ok := cfSchemaCache[dataset]; ok && time.Since(hit.at) < 24*time.Hour {
		cfSchemaMu.Unlock()
		return hit.dims, nil
	}
	cfSchemaMu.Unlock()

	var root struct {
		Schema struct {
			QueryType struct {
				Name string `json:"name"`
			} `json:"queryType"`
		} `json:"__schema"`
	}
	if err := cf.GraphQL(ctx, `query { __schema { queryType { name } } }`, nil, &root); err != nil {
		return nil, err
	}
	typeName := root.Schema.QueryType.Name
	for _, field := range []string{"viewer", "zones", dataset, "dimensions"} {
		fields, err := cfTypeFields(ctx, cf, typeName)
		if err != nil {
			return nil, err
		}
		next, ok := fields[field]
		if !ok || next == "" {
			return nil, fmt.Errorf("the schema has no %s under %s", field, typeName)
		}
		typeName = next
	}
	fields, err := cfTypeFields(ctx, cf, typeName)
	if err != nil {
		return nil, err
	}
	dims := make([]string, 0, len(fields))
	for name := range fields {
		dims = append(dims, name)
	}
	sort.Strings(dims)

	cfSchemaMu.Lock()
	cfSchemaCache[dataset] = struct {
		at   time.Time
		dims []string
	}{time.Now(), dims}
	cfSchemaMu.Unlock()
	return dims, nil
}

// pickGeoDimension chooses the client-side region or city field among the
// dimensions: "client" and "name"/"code" preferred, the edge's own location
// (colo, edge) never -- that is where Cloudflare answered, not where the
// visitor is.
func pickGeoDimension(dims []string, kind string) string {
	re := regexp.MustCompile(`(?i)` + kind)
	best, bestScore := "", -1
	for _, d := range dims {
		l := strings.ToLower(d)
		if !re.MatchString(d) || strings.Contains(l, "colo") || strings.Contains(l, "edge") || strings.Contains(l, "origin") {
			continue
		}
		score := 0
		if strings.HasPrefix(l, "client") {
			score += 4
		}
		if strings.HasSuffix(l, "name") {
			score += 2
		}
		if strings.HasSuffix(l, "code") {
			score++
		}
		if score > bestScore {
			best, bestScore = d, score
		}
	}
	return best
}

var cfCountryCode = regexp.MustCompile(`^[A-Z]{2}$`)

func GetCloudflareGeo(c *fiber.Ctx) error {
	zone, err := cloudflareZoneParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "zone not found"})
	}
	rangeKey := c.Query("range", "24h")
	span, ok := cloudflareRanges[rangeKey]
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "range must be one of 30m, 1h, 6h, 24h, 3d, 7d"})
	}
	country := strings.ToUpper(c.Query("country"))
	if country != "" && !cfCountryCode.MatchString(country) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "country must be a two-letter ISO code"})
	}

	cacheKey := zone.ZoneID + "|geo|" + rangeKey + "|" + country
	cfAnalyticsMu.Lock()
	hit, cached := cfAnalyticsCache[cacheKey]
	cfAnalyticsMu.Unlock()
	if cached && time.Since(hit.at) < cfAnalyticsTTL {
		return c.JSON(withCachedAt(hit.body, hit.at))
	}

	ctx, cancel := context.WithTimeout(c.Context(), 60*time.Second)
	defer cancel()
	cf := services.NewCloudflareClient(cloudflareToken(zone))
	limits, err := fetchCloudflareLimits(ctx, cf, zone.ZoneID)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	until := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	httpSince, _ := limits.clamp("httpRequestsAdaptiveGroups", until.Add(-span), until)
	fwSince, _ := limits.clamp("firewallEventsAdaptiveGroups", until.Add(-span), until)
	httpFilter := map[string]interface{}{"datetime_geq": httpSince, "datetime_lt": until, "requestSource": "eyeball"}
	fwFilter := map[string]interface{}{"datetime_geq": fwSince, "datetime_lt": until}

	body := fiber.Map{"since": httpSince, "until": until, "country": country}
	sections := map[string]*cfSection{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	set := func(name string, data interface{}, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			sections[name] = &cfSection{Error: err.Error()}
		} else {
			sections[name] = &cfSection{Data: data}
		}
	}
	group := func(name, dataset string, filter map[string]interface{}, dim string, limit int) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows, err := runCloudflareGroup(ctx, cf, zone.ZoneID, cfGroupQuery{
				Dataset: dataset, Filter: filter, Dims: []string{dim}, OrderBy: "count_DESC", Limit: limit,
			})
			if err != nil {
				set(name, nil, err)
				return
			}
			set(name, keyCounts(rows, dim), nil)
		}()
	}

	if country == "" {
		group("countries", "httpRequestsAdaptiveGroups", httpFilter, "clientCountryName", 300)
		group("threats", "firewallEventsAdaptiveGroups", fwFilter, "clientCountryName", 300)
		wg.Wait()
	} else {
		dims, err := cloudflareDimensions(ctx, cf, "httpRequestsAdaptiveGroups")
		region, city := "", ""
		if err != nil {
			body["schema_error"] = err.Error()
		} else {
			region = pickGeoDimension(dims, `region|subdivision|state|province`)
			city = pickGeoDimension(dims, `city`)
		}
		body["region_dim"], body["city_dim"] = region, city
		inCountry := func(base map[string]interface{}) map[string]interface{} {
			f := map[string]interface{}{"clientCountryName": country}
			for k, v := range base {
				f[k] = v
			}
			return f
		}
		if region != "" {
			group("regions", "httpRequestsAdaptiveGroups", inCountry(httpFilter), region, 100)
		}
		if city != "" {
			group("cities", "httpRequestsAdaptiveGroups", inCountry(httpFilter), city, 30)
		}
		group("ips", "httpRequestsAdaptiveGroups", inCountry(httpFilter), "clientIP", 15)
		group("paths", "httpRequestsAdaptiveGroups", inCountry(httpFilter), "clientRequestPath", 15)
		group("threat_sources", "firewallEventsAdaptiveGroups", inCountry(fwFilter), "source", 15)
		wg.Wait()
	}
	body["sections"] = sections

	now := time.Now()
	cfAnalyticsMu.Lock()
	cfAnalyticsCache[cacheKey] = struct {
		at   time.Time
		body fiber.Map
	}{now, body}
	cfAnalyticsMu.Unlock()
	return c.JSON(withCachedAt(body, now))
}
