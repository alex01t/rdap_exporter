package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/openrdap/rdap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const version = "v0.3.1"

var (
	defaultInterval, _ = time.ParseDuration("12h")

	// CLI flags
	flagAddress  = flag.String("address", "0.0.0.0:9099", "HTTP listen address")
	flagInterval = flag.Duration("interval", defaultInterval, "Interval to check domains at")
	flagQuiet    = flag.Bool("q", false, "Quiet mode: don't print domains being monitored")
	flagVersion  = flag.Bool("version", false, "Print the rdap_exporter version")

	// Prometheus metrics
	domainExpiration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rdap_domain_expiration_days",
			Help: "Days until the RDAP/WHOIS-reported expiration (negative if expired)",
		},
		[]string{"domain"},
	)
	domainExpired = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rdap_domain_expired",
			Help: "Whether the domain is already expired (1=yes, 0=no)",
		},
		[]string{"domain"},
	)
	rdapRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "rdap_request_duration_seconds",
			Help:    "Duration of RDAP requests",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"domain"},
	)
	rdapRequestErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rdap_request_errors_total",
			Help: "Total number of RDAP+WHOIS resolution errors (incremented only if both fail)",
		},
		[]string{"domain"},
	)

	// RDAP date formats we'll try
	defaultDateFormats = []string{
		"2006-01-02T15:04:05Z",
		time.RFC3339,
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04:05-07:00",
	}

	// WHOIS servers (extend as needed)
	whoisServers = map[string]string{
		"ru":       "whois.tcinet.ru:43",
		"xn--p1ai": "whois.tcinet.ru:43",
		"ae":       "whois.aeda.net.ae:43",
		"at":       "whois.nic.at:43",
		"io":       "whois.nic.io:43",
		"so":       "whois.nic.so:43",
		"fi":       "whois.fi:43",
	}

	// expiry field regexes (case-insensitive), best effort across registries
	expiryREs = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^\s*paid-till:\s*(.+)$`),
		regexp.MustCompile(`(?i)^\s*expire-date:\s*(.+)$`),
		regexp.MustCompile(`(?i)^\s*expiry\s*date:\s*(.+)$`),
		regexp.MustCompile(`(?i)^\s*expiration\s*date:\s*(.+)$`),
		regexp.MustCompile(`(?i)^\s*registrar registration expiration date:\s*(.+)$`),
		regexp.MustCompile(`(?i)^\s*registry expiry date:\s*(.+)$`),   // e.g. .io
		regexp.MustCompile(`(?i)^\s*expires[.\s]*:\s*(.+)$`),          // e.g. .fi "expires............:"
		regexp.MustCompile(`(?i)^\s*valid until:\s*(.+)$`),
	}

	// common WHOIS date layouts (without TZ => assumed via WHOIS_TZ or UTC)
	whoisDateLayouts = []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04:05 -0700",
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"Mon Jan 2 15:04:05 MST 2006",
	}

	// dd.mm.yyyy[ hh:mm[:ss]] like "15.9.2025 14:32:22"
	reDMY = regexp.MustCompile(`^\s*(\d{1,2})\.(\d{1,2})\.(\d{4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?\s*$`)
)

func init() {
	prometheus.MustRegister(domainExpiration, domainExpired, rdapRequestDuration, rdapRequestErrors)
}

func main() {
	flag.Parse()

	if *flagVersion {
		fmt.Println(version) //nolint:forbidigo
		os.Exit(1)
	}

	log.Printf("starting rdap_exporter (%s)", version)

	domains, err := readDomainsEnv()
	if err != nil {
		log.Fatalf("error getting domains: %v", err)
	}
	if !*flagQuiet {
		for i := range domains {
			log.Printf("INFO monitoring %s", domains[i])
		}
	}

	client := &rdap.Client{HTTP: &http.Client{Timeout: 10 * time.Second}}

	check := &checker{
		domains:    domains,
		expiration: domainExpiration,
		expired:    domainExpired,
		duration:   rdapRequestDuration,
		errors:     rdapRequestErrors,
		client:     client,
		interval:   *flagInterval,
	}
	go check.checkAll()

	h := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{})
	http.Handle("/metrics", h)

	log.Printf("listening on %s", *flagAddress)

	server := &http.Server{
		Addr:              *flagAddress,
		Handler:           nil, // DefaultServeMux
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("ERROR binding to %s: %v", *flagAddress, err)
	}
}

type checker struct {
	domains    []string
	expiration *prometheus.GaugeVec
	expired    *prometheus.GaugeVec
	duration   *prometheus.HistogramVec
	errors     *prometheus.CounterVec

	client *rdap.Client

	t        *time.Ticker
	interval time.Duration
}

func (c *checker) checkAll() {
	if c.t == nil {
		c.t = time.NewTicker(c.interval)
		c.checkNow()
	}
	for range c.t.C {
		c.checkNow()
	}
}

func (c *checker) checkNow() {
	for i := range c.domains {
		domain := c.domains[i]

		start := time.Now()
		exp, src, err := c.getExpiration(domain)
		c.duration.WithLabelValues(domain).Observe(time.Since(start).Seconds())

		if err != nil {
			log.Printf("error resolving expiration for %s: %v", domain, err)
			c.expiration.WithLabelValues(domain).Set(math.NaN())
			c.expired.WithLabelValues(domain).Set(math.NaN())
			c.errors.WithLabelValues(domain).Inc()
			continue
		}

		days := math.Floor(time.Until(*exp).Hours() / 24)
		c.expiration.WithLabelValues(domain).Set(days)
		if days < 0 {
			c.expired.WithLabelValues(domain).Set(1)
		} else {
			c.expired.WithLabelValues(domain).Set(0)
		}
		log.Printf("%s expires in %.2f days (source=%s)", domain, days, src)
	}
}

// RDAP first; WHOIS fallback (with best-effort parsing)
func (c *checker) getExpiration(d string) (*time.Time, string, error) {
	// RDAP
	req := &rdap.Request{Type: rdap.DomainRequest, Query: d}
	resp, err := c.client.Do(req)
	if err == nil && resp != nil && resp.Object != nil {
		if dom, ok := resp.Object.(*rdap.Domain); ok && dom != nil {
			for i := range dom.Events {
				ev := dom.Events[i]
				if ev.Action == "expiration" || ev.Action == "expiry" {
					for j := range defaultDateFormats {
						if when, perr := time.Parse(defaultDateFormats[j], ev.Date); perr == nil {
							return &when, "rdap", nil
						}
					}
					if when, perr := time.Parse(time.RFC3339Nano, ev.Date); perr == nil {
						return &when, "rdap", nil
					}
				}
			}
			// RDAP present but no expiration → fallback
		}
	}
	// WHOIS
	when, wsrc, werr := whoisExpiry(d)
	if werr == nil {
		return &when, wsrc, nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("rdap failed (%v); whois failed (%v)", err, werr)
	}
	return nil, "", fmt.Errorf("no rdap expiration; whois failed (%v)", werr)
}

// --- WHOIS helpers ---

func whoisExpiry(domain string) (time.Time, string, error) {
	tld := strings.ToLower(lastLabel(domain))
	server, ok := whoisServers[tld]
	if !ok {
		return time.Time{}, "", fmt.Errorf("no whois server configured for TLD %q", tld)
	}
	raw, err := whoisQuery(server, domain)
	if err != nil {
		return time.Time{}, "", err
	}
	expStr, label, err := extractExpiry(raw)
	if err != nil {
		return time.Time{}, "", err
	}
	when, err := parseWhoisDate(expStr, tld)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("parse whois date %q: %w", expStr, err)
	}
	return when, "whois:"+label, nil
}

func whoisQuery(server, domain string) (string, error) {
	conn, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial whois %s: %w", server, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	if _, err := fmt.Fprintf(conn, "%s\r\n", domain); err != nil {
		return "", fmt.Errorf("write whois query: %w", err)
	}

	var b strings.Builder
	sc := bufio.NewScanner(conn)
	const maxLine = 1024 * 1024
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxLine)

	for sc.Scan() {
		line := sc.Text()
		// Skip obvious comments
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("read whois: %w", err)
	}
	out := b.String()
	if strings.TrimSpace(out) == "" {
		return "", fmt.Errorf("empty whois response from %s", server)
	}
	return out, nil
}

// returns (expiryString, matchedLabel, error)
func extractExpiry(whois string) (string, string, error) {
	lines := strings.Split(whois, "\n")
	for _, ln := range lines {
		for _, re := range expiryREs {
			if m := re.FindStringSubmatch(ln); len(m) == 2 {
				// Identify which label matched for logging/labeling
				label := strings.ToLower(strings.TrimSpace(strings.Split(ln, ":")[0]))
				return strings.TrimSpace(m[1]), label, nil
			}
		}
	}
	return "", "", fmt.Errorf("no expiry field matched")
}

// parse WHOIS date; when TZ is missing, use WHOIS_TZ (IANA name) or UTC
func parseWhoisDate(s, tld string) (time.Time, error) {
	s = strings.TrimSpace(s)

	// 1) Known explicit formats
	for _, layout := range whoisDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
		// Try without TZ but interpret in chosen location
		if t, err := time.ParseInLocation(layout, s, assumedWhoisLoc()); err == nil {
			return t.UTC(), nil
		}
	}

	// 2) dd.mm.yyyy[ hh:mm[:ss]] (e.g., "15.9.2025 14:32:22")
	if m := reDMY.FindStringSubmatch(s); len(m) > 0 {
		day := atoi(m[1])
		mon := atoi(m[2])
		yr := atoi(m[3])
		hh, mm, ss := 0, 0, 0
		if m[4] != "" {
			hh = atoi(m[4])
			mm = atoi(m[5])
			if m[6] != "" {
				ss = atoi(m[6])
			}
		}
		loc := assumedWhoisLoc()
		t := time.Date(yr, time.Month(mon), day, hh, mm, ss, 0, loc)
		return t.UTC(), nil
	}

	// 3) Fallback: if first token looks like YYYY-MM-DD
	if len(s) >= 10 && s[4] == '-' && s[7] == '-' {
		if t, err := time.ParseInLocation("2006-01-02", s[:10], assumedWhoisLoc()); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("unrecognized date format %q", s)
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func assumedWhoisLoc() *time.Location {
	// If WHOIS doesn't provide TZ, use WHOIS_TZ (e.g., Europe/Helsinki) or UTC
	if tz := strings.TrimSpace(os.Getenv("WHOIS_TZ")); tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			return loc
		}
	}
	return time.UTC
}

func lastLabel(d string) string {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	parts := strings.Split(d, ".")
	if len(parts) == 0 {
		return d
	}
	return parts[len(parts)-1]
}

// --- env parsing ---

func readDomainsEnv() ([]string, error) {
	env, ok := os.LookupEnv("RDAP_DOMAINS")
	if !ok || strings.TrimSpace(env) == "" {
		return nil, fmt.Errorf("RDAP_DOMAINS environment variable not set")
	}
	parts := strings.FieldsFunc(env, func(r rune) bool {
		switch r {
		case ',', '\n', '\t', ' ':
			return true
		}
		return false
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no domains provided in RDAP_DOMAINS")
	}
	return out, nil
}
