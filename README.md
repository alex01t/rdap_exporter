# RDAP Exporter

A simple Prometheus exporter that queries RDAP for domain expiration
information. With fallback to WHOIS.

Based on https://github.com/adamdecaf/rdap_exporter

## Usage

Provide a list of domains via the `RDAP_DOMAINS` environment variable. Domains
can be separated by commas, spaces, or newlines:

```
export RDAP_DOMAINS="example.com, example.net"
rdap_exporter
```

Metrics are exposed on `:9099/metrics` by default.

## Metrics

* `rdap_domain_expiration_days{domain}` – days until the domain expires.
* `rdap_domain_expired{domain}` – whether the domain is already expired (1 or 0).
* `rdap_request_duration_seconds{domain}` – duration of the RDAP query in seconds.
* `rdap_request_errors_total{domain}` – count of RDAP request errors.

## Docker

Build and run using Docker:

```
docker build -t rdap_exporter .
docker run -p 9099:9099 -e RDAP_DOMAINS="example.com,example.net" rdap_exporter
```

