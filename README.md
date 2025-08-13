# RDAP Exporter

A simple Prometheus exporter that queries RDAP for domain expiration
information.

## Usage

Create a file containing a list of domains, one per line:

```
example.com
example.net
```

Run the exporter and point it at the file:

```
rdap_exporter -domain-file domains.txt
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
docker run -p 9099:9099 -v $(pwd)/domains.txt:/domains.txt rdap_exporter -domain-file /domains.txt
```

