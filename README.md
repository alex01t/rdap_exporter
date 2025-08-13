# RDAP Prometheus Exporter

A simple Prometheus exporter that monitors domain information using the
[rdap.org](https://rdap.org) service.  It fetches data in the background so
the `/metrics` handler remains fast.

## Usage

```
export DOMAINS=example.com,example.net
python rdap_exporter.py
```

The exporter listens on port `8000` by default.  The following environment
variables are supported:

- `DOMAINS` – comma separated list of domains to monitor (required)
- `RDAP_REFRESH_SECONDS` – refresh interval, default `3600`
- `PORT` – port for the HTTP server, default `8000`

## Docker

```
docker build -t rdap-exporter .
docker run -p 8000:8000 -e DOMAINS=example.com,example.net rdap-exporter
```

## Metrics

- `rdap_domain_expiration_timestamp{domain}` – expiration time (Unix timestamp)
- `rdap_domain_registration_timestamp{domain}` – registration time
- `rdap_domain_last_changed_timestamp{domain}` – last change time
- `rdap_domain_status{domain,status}` – domain status values

## Example alert rules

```
groups:
- name: domain-alerts
  rules:
  - alert: DomainExpirationSoon
    expr: (rdap_domain_expiration_timestamp - time()) / 86400 < 30
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: "Domain {{ $labels.domain }} expires in less than 30 days"
  - alert: DomainExpired
    expr: rdap_domain_expiration_timestamp < time()
    for: 1h
    labels:
      severity: critical
    annotations:
      summary: "Domain {{ $labels.domain }} has expired"
```
