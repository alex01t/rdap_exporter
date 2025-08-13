import os
import threading
import time
import datetime
from typing import List, Dict, Set

import requests
from prometheus_client import Gauge, start_http_server


def parse_domain_list(value: str) -> List[str]:
    return [d.strip() for d in value.split(',') if d.strip()]


DOMAINS: List[str] = parse_domain_list(os.environ.get('DOMAINS', ''))
REFRESH_SECONDS: int = int(os.environ.get('RDAP_REFRESH_SECONDS', '3600'))
PORT: int = int(os.environ.get('PORT', '8000'))

expiration_gauge = Gauge(
    'rdap_domain_expiration_timestamp',
    'Expiration time of the domain in Unix epoch seconds',
    ['domain'],
)
registration_gauge = Gauge(
    'rdap_domain_registration_timestamp',
    'Registration time of the domain in Unix epoch seconds',
    ['domain'],
)
last_changed_gauge = Gauge(
    'rdap_domain_last_changed_timestamp',
    'Last changed time of the domain in Unix epoch seconds',
    ['domain'],
)
status_gauge = Gauge(
    'rdap_domain_status',
    'Domain status from RDAP (set to 1 if present)',
    ['domain', 'status'],
)

_last_statuses: Dict[str, Set[str]] = {d: set() for d in DOMAINS}


def _to_timestamp(date_str: str) -> float:
    """Convert an ISO 8601 date string to a Unix timestamp."""
    # Replace trailing Z with +00:00 for fromisoformat
    return datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00')).timestamp()


def update_domain(domain: str) -> None:
    try:
        resp = requests.get(f'https://rdap.org/domain/{domain}', timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return

    events = data.get('events', [])
    for event in events:
        action = event.get('eventAction')
        date = event.get('eventDate')
        if not date:
            continue
        ts = _to_timestamp(date)
        if action == 'expiration':
            expiration_gauge.labels(domain=domain).set(ts)
        elif action == 'registration':
            registration_gauge.labels(domain=domain).set(ts)
        elif action == 'last changed':
            last_changed_gauge.labels(domain=domain).set(ts)

    statuses = set(data.get('status', []))
    for status in statuses:
        status_gauge.labels(domain=domain, status=status).set(1)
    # reset statuses not present anymore
    stale = _last_statuses[domain] - statuses
    for status in stale:
        status_gauge.labels(domain=domain, status=status).set(0)
    _last_statuses[domain] = statuses


def fetch_loop() -> None:
    while True:
        for domain in DOMAINS:
            update_domain(domain)
        time.sleep(REFRESH_SECONDS)


def main() -> None:
    if not DOMAINS:
        raise SystemExit('DOMAINS environment variable is required')

    start_http_server(PORT)
    thread = threading.Thread(target=fetch_loop, daemon=True)
    thread.start()

    # Keep the main thread alive.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
