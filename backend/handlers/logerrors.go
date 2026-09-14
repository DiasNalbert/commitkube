package handlers

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
	"strings"
)

// Counting error lines says a workload is unhappy. It does not say what is
// wrong, and for a batch job or an RPA that is the whole question: the run
// failed, but did it fail because the site it drives was down, or because the
// automation broke? This file answers that from the log text alone.
//
// Two steps. First the message is reduced to a template, so lines that differ
// only in an order number collapse into one group -- a catalogue that lists
// every line individually is just the log again. Then the template is
// classified, because the failures that matter here announce themselves very
// precisely: a Chromium automation says net::ERR_NAME_NOT_RESOLVED, a Python
// client says ConnectionRefusedError, a JVM says UnknownHostException. Those
// are not ambiguous, and none of them require an agent to observe.

var (
	reTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?`)
	reClock     = regexp.MustCompile(`\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b`)
	reUUID      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reHex       = regexp.MustCompile(`(?i)\b(?:0x)?[0-9a-f]{8,}\b`)
	reIP        = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b`)
	reURL       = regexp.MustCompile(`(?i)\bhttps?://[^\s'"<>)\]]+`)
	rePath      = regexp.MustCompile(`(?:/[\w.-]+){2,}/?`)
	reQuoted    = regexp.MustCompile(`'[^']{1,120}'|"[^"]{1,120}"`)
	reNumber    = regexp.MustCompile(`\b\d+\b`)
	reSpace     = regexp.MustCompile(`\s+`)

	// Hosts are extracted before the URL is blanked, so the group keeps the
	// third party's name even though the rest of the URL is templated away.
	reHostInURL = regexp.MustCompile(`(?i)\bhttps?://([a-z0-9.-]+\.[a-z]{2,})`)
	reHostNamed = regexp.MustCompile(`(?i)(?:host|hostname|server|url|endpoint|domain)[=: '"]+([a-z0-9.-]+\.[a-z]{2,})`)
	reHostBare  = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\.[a-z]{2,})\b`)
)

// logTemplate reduces a message to its invariant shape. Order matters: the
// most specific patterns run first, so that a timestamp is not shredded into
// placeholder numbers before it is recognised as a timestamp.
func logTemplate(line string) string {
	s := strings.TrimSpace(line)
	s = reTimestamp.ReplaceAllString(s, "<ts>")
	s = reClock.ReplaceAllString(s, "<ts>")
	s = reUUID.ReplaceAllString(s, "<uuid>")
	s = reURL.ReplaceAllString(s, "<url>")
	s = reIP.ReplaceAllString(s, "<ip>")
	s = reHex.ReplaceAllString(s, "<hex>")
	s = rePath.ReplaceAllString(s, "<path>")
	s = reQuoted.ReplaceAllString(s, "<str>")
	s = reNumber.ReplaceAllString(s, "<n>")
	s = reSpace.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func fingerprint(template string) string {
	sum := sha1.Sum([]byte(template))
	return hex.EncodeToString(sum[:8])
}

// classRule maps the markers a runtime prints when a call fails to the reason
// it failed. The ordering of the slice is the precedence: a message naming a
// refused connection is unreachable even if it also mentions a timeout later.
type classRule struct {
	class   string
	markers []string
}

var classRules = []classRule{
	{"dependency_unreachable", []string{
		// Chromium, which is what most browser automation drives.
		"net::ERR_NAME_NOT_RESOLVED", "net::ERR_CONNECTION_REFUSED",
		"net::ERR_CONNECTION_CLOSED", "net::ERR_CONNECTION_RESET",
		"net::ERR_INTERNET_DISCONNECTED", "net::ERR_ADDRESS_UNREACHABLE",
		"net::ERR_SSL", "net::ERR_CERT",
		// Node, Python, Go, Java, .NET.
		"ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "ECONNRESET", "EHOSTUNREACH", "ENETUNREACH",
		"ConnectionRefusedError", "NewConnectionError", "NameResolutionError",
		"MaxRetryError", "requests.exceptions.ConnectionError",
		"connection refused", "connection reset by peer", "no such host",
		"temporary failure in name resolution", "name or service not known",
		"java.net.ConnectException", "java.net.UnknownHostException",
		"SocketException", "HttpRequestException",
		"getaddrinfo", "dial tcp",
		// Portuguese wrappers, for automations that catch the library error and
		// re-log it in their own words.
		"conexão recusada", "conexao recusada", "não foi possível conectar",
		"nao foi possivel conectar", "não foi possível acessar",
		"nao foi possivel acessar", "host desconhecido", "servidor não encontrado",
		"servidor nao encontrado", "fora do ar", "indisponível", "indisponivel",
	}},
	{"dependency_timeout", []string{
		"net::ERR_CONNECTION_TIMED_OUT", "net::ERR_TIMED_OUT",
		"ETIMEDOUT", "ESOCKETTIMEDOUT",
		"TimeoutError", "Navigation timeout", "navigation timeout",
		"Timeout exceeded", "timeout exceeded", "context deadline exceeded",
		"ReadTimeout", "ConnectTimeout", "read timeout", "connect timeout",
		"java.net.SocketTimeoutException", "TaskCanceledException",
		"i/o timeout", "request timed out", "Gateway Time-out", "gateway timeout",
		"tempo esgotado", "tempo limite", "tempo de espera", "expirou",
	}},
	{"dependency_http", []string{
		"502 Bad Gateway", "503 Service Unavailable", "504 Gateway",
		"Bad Gateway", "Service Unavailable", "Internal Server Error",
		"HTTP 502", "HTTP 503", "HTTP 504", "HTTP 500",
		"status code 502", "status code 503", "status code 504", "status code 500",
	}},
	{"app_exception", []string{
		"Traceback (most recent call last)", "panic:", "NullPointerException",
		"Unhandled exception", "UnhandledPromiseRejection", "AssertionError",
		"TypeError", "ValueError", "KeyError", "AttributeError", "IndexError",
		"NoSuchElementException", "ElementNotInteractableException",
		"StaleElementReferenceException", "waiting for selector",
		"segmentation fault", "OutOfMemoryError",
	}},
}

// classifyLogError decides why a line reports failure. Everything the rules do
// not recognise stays "unknown" rather than being forced into the nearest
// bucket -- a wrong class here would send someone to argue with the wrong team.
func classifyLogError(line string) string {
	lower := strings.ToLower(line)
	for _, rule := range classRules {
		for _, marker := range rule.markers {
			if strings.Contains(line, marker) || strings.Contains(lower, strings.ToLower(marker)) {
				return rule.class
			}
		}
	}
	return "unknown"
}

// isDependencyClass reports whether the class blames something outside the
// application. These are the groups that answer "the third party was down".
func isDependencyClass(class string) bool {
	return strings.HasPrefix(class, "dependency_")
}

// extractTarget pulls the host the failing message named. A selector failure
// inside a page mentions no host and correctly returns nothing: attributing a
// broken automation to whatever domain happened to appear in the line would
// manufacture a culprit.
func extractTarget(line string) string {
	if m := reHostInURL.FindStringSubmatch(line); len(m) == 2 {
		return normalizeHost(m[1])
	}
	if m := reHostNamed.FindStringSubmatch(line); len(m) == 2 && plausibleHost(m[1]) {
		return normalizeHost(m[1])
	}
	for _, m := range reHostBare.FindAllStringSubmatch(line, -1) {
		if !plausibleHost(m[1]) {
			continue
		}
		if host := normalizeHost(m[1]); host != "" {
			return host
		}
	}
	return ""
}

// plausibleHost rejects the dotted names that are not hosts. A JVM stack trace
// is full of them -- java.net.UnknownHostException reads as a domain to any
// regex -- and attributing an outage to one would name a culprit that does not
// exist. Two rules together are enough: a real hostname in a log is lowercase,
// where a class path is CamelCase, and its last label is a plausible TLD.
func plausibleHost(h string) bool {
	if h != strings.ToLower(h) {
		return false
	}
	i := strings.LastIndex(h, ".")
	if i < 0 {
		return false
	}
	tld := h[i+1:]
	if looksLikeFilename(h) {
		return false
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	if len(tld) >= 2 && len(tld) <= 6 {
		return true
	}
	switch tld {
	case "technology", "international", "engineering", "enterprises", "foundation":
		return true
	}
	return false
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.Trim(h, ".:/'\""))
	if h == "" || strings.HasPrefix(h, "localhost") {
		return ""
	}
	return h
}

// looksLikeFilename keeps "main.py" and "app.service.ts" out of the target
// field: a stack trace is full of dotted names that are not hosts.
func looksLikeFilename(h string) bool {
	i := strings.LastIndex(h, ".")
	if i < 0 {
		return false
	}
	switch h[i+1:] {
	case "py", "js", "ts", "go", "java", "rb", "php", "cs", "rs", "jsx", "tsx",
		"json", "yaml", "yml", "xml", "html", "log", "txt", "sh", "sql", "exe", "dll":
		return true
	}
	return false
}
