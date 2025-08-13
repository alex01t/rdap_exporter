package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openrdap/rdap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const version = "v0.2.0"

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
			Help: "Days until the RDAP expiration event states this domain will expire",
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
			Help: "Total number of RDAP request errors",
		},
		[]string{"domain"},
	)

	defaultDateFormats = []string{
		"2006-01-02T15:04:05Z",
		time.RFC3339,
	}
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

	// read and verify domains from environment
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

	// Setup internal checker
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

	// Add metrics to /metrics
	h := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{})
	http.Handle("/metrics", h)

	log.Printf("listening on %s", *flagAddress)

	// Create server with timeout configurations
	server := &http.Server{
		Addr:              *flagAddress,
		Handler:           nil, // Uses DefaultServeMux
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
		c.checkNow() // check domains right away after ticker setup
	}
	for range c.t.C {
		c.checkNow()
	}
}

func (c *checker) checkNow() {
	for i := range c.domains {
		domain := c.domains[i]
		start := time.Now()
		expr, err := c.getExpiration(domain)
		c.duration.WithLabelValues(domain).Observe(time.Since(start).Seconds())
		if err != nil {
			log.Printf("error getting RDAP expiration for %s: %v", domain, err)
			c.expiration.WithLabelValues(domain).Set(math.NaN())
			c.expired.WithLabelValues(domain).Set(math.NaN())
			c.errors.WithLabelValues(domain).Inc()
			continue
		}
		days := math.Floor(time.Until(*expr).Hours() / 24)
		c.expiration.WithLabelValues(domain).Set(days)
		if days < 0 {
			c.expired.WithLabelValues(domain).Set(1)
		} else {
			c.expired.WithLabelValues(domain).Set(0)
		}
		log.Printf("%s expires in %.2f days", domain, days)
	}
}

func (c *checker) getExpiration(d string) (*time.Time, error) {
	req := &rdap.Request{
		Type:  rdap.DomainRequest,
		Query: d,
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap query failed: %w", err)
	}
	if resp == nil || resp.Object == nil {
		return nil, fmt.Errorf("nil rdap response")
	}

	domain, ok := resp.Object.(*rdap.Domain)
	if !ok {
		return nil, fmt.Errorf("unable to read domain response")
	}
	for i := range domain.Events {
		event := domain.Events[i]
		if event.Action == "expiration" {
			for j := range defaultDateFormats {
				when, err := time.Parse(defaultDateFormats[j], event.Date)
				if err != nil {
					continue
				}
				return &when, nil
			}
			return nil, fmt.Errorf("unable to find parsable format for %q", event.Date)
		}
	}
	return nil, fmt.Errorf("no expiration event found")
}

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
	if len(parts) == 0 {
		return nil, fmt.Errorf("no domains provided in RDAP_DOMAINS")
	}
	return parts, nil
}
