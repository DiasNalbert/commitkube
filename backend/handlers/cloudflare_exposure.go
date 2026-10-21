package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
	"gorm.io/gorm/clause"
)

// Exposure: what a zone shows the internet underneath Cloudflare.
//
// A proxied hostname resolves to Cloudflare, so scanning the domain only ever
// finds Cloudflare's ports. What matters is what sits behind it:
//
//   - the origin IPs. If an origin answers on 80/443 to anyone, an attacker
//     who learns the IP skips the WAF, the rate limits and the DDoS
//     protection altogether. The DNS API gives the origin IP even for
//     proxied records, which is how it is learned here -- and how it gets
//     learned by everyone else, through history and leaks.
//   - DNS-only records, whose IPs are public by definition.
//   - every port on those IPs, as the internet sees them.
//
// The internet's view comes from Shodan's InternetDB, not from a scan of our
// own. CommitKube runs inside the cluster it would be scanning, and a probe
// from there measures the cluster network -- it would report ports the
// internet cannot reach and miss the firewall that is the whole question.
//
// Checks run every few hours: InternetDB itself refreshes about weekly, so
// running more often would only re-read the same answer.

type cfExposureFinding struct {
	Severity string `json:"severity"` // critical, high, medium, info
	Type     string `json:"type"`
	Key      string `json:"key"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Target   string `json:"target"`
}

type cfExposurePort struct {
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Severity string `json:"severity"`
}

type cfExposureIP struct {
	IP        string           `json:"ip"`
	Records   []string         `json:"records"`
	Proxied   bool             `json:"proxied"`  // at least one proxied record points here: it is an origin
	DNSOnly   bool             `json:"dns_only"` // at least one DNS-only record points here: it is public
	Private   bool             `json:"private"`
	Checked   bool             `json:"checked"`
	Seen      bool             `json:"seen"` // InternetDB has data on it
	Ports     []cfExposurePort `json:"ports"`
	Vulns     []string         `json:"vulns"`
	CPEs      []string         `json:"cpes"`
	Tags      []string         `json:"tags"`
	Hostnames int              `json:"hostnames"`
	Error     string           `json:"error,omitempty"`
}

type cfExposureResult struct {
	Records  []services.CloudflareDNSRecord `json:"records"`
	IPs      []cfExposureIP                 `json:"ips"`
	Findings []cfExposureFinding            `json:"findings"`
	Summary  map[string]int                 `json:"summary"`
	Notes    []string                       `json:"notes"`
}

// Ports worth an alert on their own, with what usually listens there. The
// critical ones are the services that answer without authentication by
// default: open to the internet, they are usually an incident already.
var cfPortServices = map[int]struct {
	name     string
	severity string
}{
	21: {"FTP", "high"}, 22: {"SSH", "medium"}, 23: {"Telnet", "critical"}, 25: {"SMTP", "info"},
	53: {"DNS", "medium"}, 110: {"POP3", "medium"}, 111: {"rpcbind", "high"}, 135: {"MS RPC", "high"},
	139: {"NetBIOS", "high"}, 143: {"IMAP", "medium"}, 161: {"SNMP", "high"}, 445: {"SMB", "critical"},
	465: {"SMTPS", "info"}, 587: {"SMTP submission", "info"}, 993: {"IMAPS", "info"}, 995: {"POP3S", "info"},
	1433: {"Microsoft SQL Server", "high"}, 1521: {"Oracle DB", "high"}, 2049: {"NFS", "high"},
	2375: {"Docker API (no TLS)", "critical"}, 2376: {"Docker API", "high"}, 2379: {"etcd", "critical"},
	2380: {"etcd peer", "critical"}, 3000: {"Grafana / dev server", "medium"}, 3306: {"MySQL", "high"},
	3389: {"RDP", "high"}, 4194: {"cAdvisor", "high"}, 5000: {"Docker registry / dev server", "medium"},
	5432: {"PostgreSQL", "high"}, 5601: {"Kibana", "high"}, 5672: {"AMQP", "high"}, 5900: {"VNC", "high"},
	5984: {"CouchDB", "critical"}, 6379: {"Redis", "critical"}, 6443: {"Kubernetes API", "high"},
	8001: {"kubectl proxy", "critical"}, 8086: {"InfluxDB", "high"}, 8200: {"HashiCorp Vault", "medium"},
	8500: {"Consul", "high"}, 9000: {"MinIO / Portainer / SonarQube", "medium"}, 9090: {"Prometheus", "high"},
	9092: {"Kafka", "high"}, 9093: {"Alertmanager", "high"}, 9100: {"node_exporter", "high"},
	9200: {"Elasticsearch", "critical"}, 9300: {"Elasticsearch transport", "critical"},
	10250: {"kubelet", "critical"}, 10255: {"kubelet (read-only)", "critical"}, 11211: {"Memcached", "critical"},
	15672: {"RabbitMQ management", "high"}, 27017: {"MongoDB", "critical"}, 27018: {"MongoDB", "critical"},
}

var cfWebPorts = map[int]bool{80: true, 443: true, 8080: true, 8443: true}

func cfPortInfo(port int) cfExposurePort {
	if s, ok := cfPortServices[port]; ok {
		return cfExposurePort{port, s.name, s.severity}
	}
	switch {
	case cfWebPorts[port]:
		return cfExposurePort{port, "HTTP(S)", "info"}
	case port >= 30000 && port <= 32767:
		// The NodePort range: something in the cluster was published on
		// every node, usually by accident.
		return cfExposurePort{port, "Kubernetes NodePort", "high"}
	default:
		return cfExposurePort{port, "", "medium"}
	}
}

// Providers where a CNAME left pointing at a deleted resource can be claimed
// by anyone who creates a resource of the same name: the textbook subdomain
// takeover.
var cfTakeoverSuffixes = []string{
	".s3.amazonaws.com", ".s3-website", ".cloudfront.net", ".elasticbeanstalk.com", ".herokuapp.com",
	".herokudns.com", ".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net",
	".blob.core.windows.net", ".azureedge.net", ".github.io", ".netlify.app", ".netlify.com", ".vercel.app",
	".ghost.io", ".myshopify.com", ".surge.sh", ".bitbucket.io", ".wordpress.com", ".pantheonsite.io",
	".zendesk.com", ".readme.io", ".fly.dev", ".onrender.com", ".firebaseapp.com", ".web.app",
}

func cfTakeoverProne(target string) bool {
	t := strings.ToLower(target)
	for _, s := range cfTakeoverSuffixes {
		if strings.Contains(t, s) {
			return true
		}
	}
	return false
}

// Hostnames whose job is to be reached directly: mail and the like. A
// DNS-only record for one of them is expected, not a gap.
func cfExpectedDNSOnly(name string) bool {
	first := strings.ToLower(strings.SplitN(name, ".", 2)[0])
	for _, p := range []string{"mail", "smtp", "mx", "imap", "pop", "pop3", "autodiscover", "autoconfig", "webmail", "ftp", "vpn", "sip", "_"} {
		if first == p || strings.HasPrefix(first, p) && len(first) <= len(p)+2 {
			return true
		}
	}
	return false
}

func cfSeverityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	default:
		return 3
	}
}

var cfLookupHost = net.DefaultResolver.LookupHost

// buildCloudflareExposure runs the whole check for one zone. A failure to
// reach one IP's data is kept on that IP; only a failure to read the DNS
// records fails the check, since nothing else can be known without them.
func buildCloudflareExposure(ctx context.Context, z *models.CloudflareZone) (*cfExposureResult, error) {
	cf := services.NewCloudflareClient(cloudflareToken(z))
	records, err := cf.ListDNSRecords(ctx, z.ZoneID)
	if err != nil {
		var cfErr *services.CloudflareError
		if errors.As(err, &cfErr) && (cfErr.Status == 401 || cfErr.Status == 403) {
			return nil, fmt.Errorf("the token needs Zone > DNS: Read to check exposure (%v)", err)
		}
		return nil, err
	}
	res := &cfExposureResult{Records: records, Summary: map[string]int{}}
	add := func(f cfExposureFinding) { res.Findings = append(res.Findings, f) }

	zoneName := strings.ToLower(z.ZoneName)
	names := map[string]bool{}
	for _, r := range records {
		names[strings.ToLower(r.Name)] = true
	}

	// -- IPs, from A and AAAA records
	byIP := map[string]*cfExposureIP{}
	var order []string
	for _, r := range records {
		if r.Type != "A" && r.Type != "AAAA" {
			continue
		}
		addr, err := netip.ParseAddr(r.Content)
		if err != nil {
			continue
		}
		ip := byIP[r.Content]
		if ip == nil {
			ip = &cfExposureIP{IP: r.Content, Private: addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() ||
				(addr.Is4() && addr.As4()[0] == 100 && addr.As4()[1]&0xC0 == 64)} // 100.64/10, carrier-grade NAT
			byIP[r.Content] = ip
			order = append(order, r.Content)
		}
		ip.Records = append(ip.Records, r.Name)
		if r.Proxied {
			ip.Proxied = true
			res.Summary["proxied"]++
		} else {
			ip.DNSOnly = true
			res.Summary["dns_only"]++
		}
		res.Summary["address_records"]++

		if !r.Proxied && !ip.Private && !cfExpectedDNSOnly(r.Name) {
			add(cfExposureFinding{
				Severity: "medium", Type: "dns_only_record", Key: r.Name, Target: r.Name,
				Title:  "DNS-only record exposes its IP",
				Detail: fmt.Sprintf("%s points straight at %s with the proxy off: the IP is public and its traffic skips the WAF and DDoS protection.", r.Name, r.Content),
			})
		}
	}
	for _, ip := range byIP {
		if ip.Private {
			add(cfExposureFinding{
				Severity: "info", Type: "private_ip_in_dns", Key: ip.IP, Target: ip.IP,
				Title:  "Internal address published in public DNS",
				Detail: fmt.Sprintf("%s (%s) is a private address. It is unreachable from outside, but it tells anyone how the internal network is laid out.", ip.IP, strings.Join(ip.Records, ", ")),
			})
		}
	}

	// -- what the internet sees on each public IP. Capped, so a zone with a
	// thousand records cannot turn one check into a thousand lookups.
	const maxIPs = 256
	lookup := order
	if len(lookup) > maxIPs {
		lookup = lookup[:maxIPs]
		res.Notes = append(res.Notes, fmt.Sprintf("Only the first %d of %d addresses were looked up.", maxIPs, len(order)))
	}
	if os.Getenv("CLOUDFLARE_EXPOSURE_INTERNETDB") == "false" {
		res.Notes = append(res.Notes, "Port data is turned off (CLOUDFLARE_EXPOSURE_INTERNETDB=false).")
		lookup = nil
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, addr := range lookup {
		ip := byIP[addr]
		if ip.Private {
			continue // InternetDB answers for private ranges with noise pooled from every network
		}
		wg.Add(1)
		go func(ip *cfExposureIP) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			h, err := services.LookupInternetDB(ctx, ip.IP)
			if err != nil {
				ip.Error = err.Error()
				return
			}
			ip.Checked = true
			if h == nil {
				return
			}
			ip.Seen = true
			ip.Vulns, ip.CPEs, ip.Tags, ip.Hostnames = h.Vulns, h.CPEs, h.Tags, len(h.Hostnames)
			sort.Ints(h.Ports)
			for _, p := range h.Ports {
				ip.Ports = append(ip.Ports, cfPortInfo(p))
			}
		}(ip)
	}
	wg.Wait()

	for _, addr := range order {
		ip := byIP[addr]
		res.IPs = append(res.IPs, *ip)
		if !ip.Checked {
			continue
		}
		res.Summary["ips_checked"]++
		if len(ip.Ports) > 0 {
			res.Summary["ips_with_ports"]++
		}
		where := strings.Join(ip.Records, ", ")

		var web []string
		for _, p := range ip.Ports {
			if cfWebPorts[p.Port] {
				web = append(web, fmt.Sprint(p.Port))
			}
		}
		if ip.Proxied && len(web) > 0 {
			add(cfExposureFinding{
				Severity: "high", Type: "origin_exposed", Key: ip.IP, Target: ip.IP,
				Title: "Origin reachable without Cloudflare",
				Detail: fmt.Sprintf("%s is the origin of %s, and the internet reaches it directly on port %s. Anyone with the IP bypasses the WAF, rate limiting and DDoS protection. Allow only Cloudflare's IP ranges on the origin firewall, or use Cloudflare Tunnel.",
					ip.IP, where, strings.Join(web, ", ")),
			})
		}
		for _, p := range ip.Ports {
			if cfWebPorts[p.Port] || p.Severity == "info" {
				continue
			}
			svc := p.Service
			if svc == "" {
				svc = "an unidentified service"
			}
			add(cfExposureFinding{
				Severity: p.Severity, Type: "exposed_port", Key: fmt.Sprintf("%s:%d", ip.IP, p.Port), Target: fmt.Sprintf("%s:%d", ip.IP, p.Port),
				Title:  fmt.Sprintf("Port %d open to the internet (%s)", p.Port, svc),
				Detail: fmt.Sprintf("%s, behind %s, answers on port %d (%s).", ip.IP, where, p.Port, svc),
			})
		}
		if len(ip.Vulns) > 0 {
			sev := "high"
			list := ip.Vulns
			if len(list) > 12 {
				list = append(append([]string{}, list[:12]...), fmt.Sprintf("and %d more", len(ip.Vulns)-12))
			}
			add(cfExposureFinding{
				Severity: sev, Type: "known_vulns", Key: ip.IP, Target: ip.IP,
				Title:  fmt.Sprintf("%d known vulnerabilities in what %s exposes", len(ip.Vulns), ip.IP),
				Detail: fmt.Sprintf("The software visible on %s (%s) matches: %s. Matched by version, so confirm before acting.", ip.IP, where, strings.Join(list, ", ")),
			})
		}
		res.Summary["vulns"] += len(ip.Vulns)
	}

	// -- dangling CNAMEs
	type cname struct{ name, target string }
	var cnames []cname
	for _, r := range records {
		if r.Type == "CNAME" {
			cnames = append(cnames, cname{r.Name, strings.TrimSuffix(strings.ToLower(r.Content), ".")})
		}
	}
	var mu sync.Mutex
	for _, c := range cnames {
		wg.Add(1)
		go func(c cname) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			inZone := zoneName != "" && (c.target == zoneName || strings.HasSuffix(c.target, "."+zoneName))
			dangling := false
			if inZone {
				dangling = !names[c.target] && !strings.HasPrefix(c.target, "*.")
			} else {
				lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				_, err := cfLookupHost(lctx, c.target)
				cancel()
				var dnsErr *net.DNSError
				dangling = errors.As(err, &dnsErr) && dnsErr.IsNotFound
			}
			if !dangling {
				return
			}
			f := cfExposureFinding{
				Severity: "high", Type: "dangling_cname", Key: c.name, Target: c.name,
				Title:  "CNAME points at a name that does not exist",
				Detail: fmt.Sprintf("%s is a CNAME for %s, which does not resolve. Remove the record if the service is gone.", c.name, c.target),
			}
			if cfTakeoverProne(c.target) {
				f.Severity = "critical"
				f.Title = "Subdomain takeover risk"
				f.Detail = fmt.Sprintf("%s is a CNAME for %s, which no longer exists on a provider where anyone can claim that name — and with it, %s. Remove the record or recreate the resource.", c.name, c.target, c.name)
			}
			mu.Lock()
			add(f)
			mu.Unlock()
		}(c)
	}
	wg.Wait()

	// -- email authentication, read from the zone's own records
	apex := zoneName
	var hasMX bool
	var spf, dmarc string
	for _, r := range records {
		n := strings.ToLower(r.Name)
		switch {
		case r.Type == "MX" && n == apex:
			hasMX = true
		case r.Type == "TXT" && n == apex && strings.HasPrefix(strings.Trim(strings.ToLower(r.Content), `"`), "v=spf1"):
			spf = strings.Trim(strings.ToLower(r.Content), `"`)
		case r.Type == "TXT" && n == "_dmarc."+apex && strings.HasPrefix(strings.Trim(strings.ToLower(r.Content), `"`), "v=dmarc1"):
			dmarc = strings.Trim(strings.ToLower(r.Content), `"`)
		}
	}
	if apex != "" {
		switch {
		case spf == "" && hasMX:
			add(cfExposureFinding{Severity: "medium", Type: "email_auth", Key: "spf", Target: apex,
				Title: "No SPF record", Detail: apex + " receives mail but publishes no SPF policy, so anyone can send mail claiming to be from it."})
		case strings.Contains(spf, "+all"):
			add(cfExposureFinding{Severity: "high", Type: "email_auth", Key: "spf", Target: apex,
				Title: "SPF allows every sender", Detail: "The SPF record ends in +all, which authorises every server on the internet to send as " + apex + "."})
		}
		switch {
		case dmarc == "" && (hasMX || spf != ""):
			add(cfExposureFinding{Severity: "medium", Type: "email_auth", Key: "dmarc", Target: "_dmarc." + apex,
				Title: "No DMARC policy", Detail: "Without DMARC, receivers have no instruction for mail that fails SPF or DKIM, and spoofed mail from " + apex + " is usually delivered."})
		case strings.Contains(dmarc, "p=none"):
			add(cfExposureFinding{Severity: "info", Type: "email_auth", Key: "dmarc", Target: "_dmarc." + apex,
				Title: "DMARC only monitors", Detail: "The DMARC policy is p=none: failures are reported, but spoofed mail is still delivered. Move to quarantine or reject once the reports are clean."})
		}
	}

	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if cfSeverityRank(a.Severity) != cfSeverityRank(b.Severity) {
			return cfSeverityRank(a.Severity) < cfSeverityRank(b.Severity)
		}
		return a.Target < b.Target
	})
	res.Summary["records"] = len(records)
	res.Summary["ips"] = len(order)
	for _, f := range res.Findings {
		res.Summary["findings_"+f.Severity]++
	}
	return res, nil
}

// Exposure findings that become alerts, and what each takes to be re-checked.
// The rest -- DNS-only records, email policy, internal IPs -- are posture:
// they show on the tab without paging anyone.
var cfExposureAlertTypes = map[string]bool{
	"origin_exposed": true, "exposed_port": true, "known_vulns": true, "dangling_cname": true,
}

// reconcileExposureAlerts opens an alert for each new finding, keeps the ones
// still present open, and resolves those that are gone. Gone means one of two
// things: the IP was looked up again and the finding is not there, or no
// record in the zone points at the IP any more -- someone removed it, and the
// zone no longer exposes it whatever InternetDB still remembers. An IP that is
// still in DNS but could not be looked up this time keeps its alerts as they
// were: no answer is not the same as closed.
func reconcileExposureAlerts(z *models.CloudflareZone, res *cfExposureResult) {
	checkedIP := map[string]bool{}
	inDNS := map[string]bool{}
	for _, ip := range res.IPs {
		inDNS[ip.IP] = true
		if ip.Checked {
			checkedIP[ip.IP] = true
		}
	}
	current := map[string]cfExposureFinding{}
	for _, f := range res.Findings {
		if cfExposureAlertTypes[f.Type] && cfSeverityRank(f.Severity) <= cfSeverityRank("medium") {
			current[f.Type+"|"+f.Key] = f
		}
	}

	var open []models.CloudflareAlert
	types := make([]string, 0, len(cfExposureAlertTypes))
	for t := range cfExposureAlertTypes {
		types = append(types, t)
	}
	db.DB.Where("zone_ref_id = ? AND source = ? AND resolved_at IS NULL AND alert_type IN ?", z.ID, "commitkube", types).Find(&open)

	now := time.Now()
	seen := map[string]bool{}
	for _, a := range open {
		k := a.AlertType + "|" + a.ExternalID
		seen[k] = true
		if f, ok := current[k]; ok {
			db.DB.Model(&models.CloudflareAlert{}).Where("id = ?", a.ID).
				Updates(map[string]interface{}{"last_seen_at": now, "message": f.Detail, "severity": f.Severity, "title": f.Title})
			continue
		}
		ipOf := a.ExternalID
		if a.AlertType == "exposed_port" {
			if host, _, err := net.SplitHostPort(a.ExternalID); err == nil {
				ipOf = host
			}
		}
		if a.AlertType == "dangling_cname" || checkedIP[ipOf] || !inDNS[ipOf] {
			db.DB.Model(&models.CloudflareAlert{}).Where("id = ?", a.ID).Update("resolved_at", now)
		}
	}
	for k, f := range current {
		if seen[k] {
			continue
		}
		details, _ := json.Marshal(map[string]string{"target": f.Target, "source": "Shodan InternetDB and the zone's DNS records"})
		a := models.CloudflareAlert{
			ZoneRefID: z.ID, Source: "commitkube", AlertType: f.Type, ExternalID: f.Key, Severity: f.Severity,
			Title: f.Title, Message: f.Detail, StartedAt: now, LastSeenAt: now, Details: string(details),
		}
		if err := db.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&a).Error; err == nil && a.ID != 0 {
			notifyCloudflareAlert(z, &a)
		}
	}
}

func scanCloudflareExposure(z *models.CloudflareZone) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	row := models.CloudflareExposure{ZoneRefID: z.ID}
	db.DB.Where("zone_ref_id = ?", z.ID).Limit(1).Find(&row)
	row.ZoneRefID = z.ID
	row.ScannedAt = time.Now()

	res, err := buildCloudflareExposure(ctx, z)
	if err != nil {
		// The last good result stays; the error says why it is not newer.
		row.Error = err.Error()
	} else {
		row.Error = ""
		b, _ := json.Marshal(res)
		row.Result = string(b)
		reconcileExposureAlerts(z, res)
	}
	db.DB.Save(&row)
}

var cfExposureMu sync.Mutex

func PollCloudflareExposure() {
	if !cfExposureMu.TryLock() {
		return
	}
	defer cfExposureMu.Unlock()
	var zones []models.CloudflareZone
	db.DB.Where("enabled = ?", true).Find(&zones)
	for i := range zones {
		scanCloudflareExposure(&zones[i])
	}
}

func GetCloudflareExposure(c *fiber.Ctx) error {
	zone, err := cloudflareZoneParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "zone not found"})
	}
	var row models.CloudflareExposure
	db.DB.Where("zone_ref_id = ?", zone.ID).Limit(1).Find(&row)
	if row.ID == 0 {
		return c.JSON(fiber.Map{"scanned_at": nil, "error": "", "result": nil})
	}
	var res json.RawMessage
	if row.Result != "" {
		res = json.RawMessage(row.Result)
	}
	return c.JSON(fiber.Map{"scanned_at": row.ScannedAt, "error": row.Error, "result": res})
}

func ScanCloudflareExposureNow(c *fiber.Ctx) error {
	zone, err := cloudflareZoneParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "zone not found"})
	}
	cfExposureMu.Lock()
	scanCloudflareExposure(zone)
	cfExposureMu.Unlock()
	return GetCloudflareExposure(c)
}
