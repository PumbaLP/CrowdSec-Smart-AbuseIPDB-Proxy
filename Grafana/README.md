# Grafana dashboard

A ready-made dashboard for the `/metrics` endpoint: reports sent/suppressed/failed/ignored (rate), pending escalations/retries, AbuseIPDB quota remaining/limit, uptime, and version.

## Prerequisites

- `ABUSEIPDB_ENABLE_METRICS=true` set on the proxy (off by default)
- A Prometheus server with a scrape job pointed at the proxy's `/metrics` endpoint, e.g.:
  ```yaml
  scrape_configs:
    - job_name: abuseipdb-proxy
      static_configs:
        - targets: ["127.0.0.1:9999"]  # or abuseipdb-proxy:9999 inside Docker
  ```
- That Prometheus server already added as a datasource in Grafana

## Import

1. Grafana → Dashboards → New → Import
2. Upload `dashboard.json` (or paste its contents)
3. When prompted, select your Prometheus datasource for the "Prometheus" input
4. Import

The quota panel stays empty until the first report of the day goes out — that's expected, not broken; AbuseIPDB doesn't hand out quota numbers until you've actually made a request.
