# netprobe

A small, dependency-free Go service that monitors HTTP(S) endpoints and breaks every check into its network phases: **DNS lookup → TCP connect → TLS handshake → time-to-first-byte**. It also tracks **TLS version and certificate expiry**, and exposes everything as **Prometheus metrics**.

Built to answer the on-call question "is it down, and *where* is it slow — DNS, the network, TLS, or the app?"

## Features

- Per-phase latency using Go's `net/http/httptrace` (fresh connection per probe, so DNS/TCP/TLS are actually measured)
- TLS version + leaf certificate expiry, with a configurable warning threshold
- Bounded worker pool for concurrent probing; results stay in config order
- Retries with exponential backoff; per-attempt timeouts via `context`
- Two modes:
  - `check` — one-shot table or JSON, **non-zero exit code** when anything is down or a cert is expiring (drop-in for cron, CI, or shell scripts)
  - `serve` — continuous probing with `/metrics` (Prometheus text format), `/healthz`, `/readyz`, structured JSON logs (`log/slog`) that log only **state transitions**, and graceful shutdown on SIGTERM
- Linux deployment: Bash installer + hardened **systemd** unit (dedicated user, `ProtectSystem=strict`, no capabilities, memory cap)
- Prometheus alert rules for endpoint down, cert expiring, slow TLS
- Standard library only — no third-party modules

## Quick start

```bash
make build
./bin/netprobe check -config targets.example.json
```

```
TARGET   STATUS  CODE  DNS ms  TCP ms  TLS ms  TTFB ms  TOTAL ms  TLS      CERT DAYS  NOTE
github   UP      200   3.7     0.4     25.6    69.3     77.0      TLS 1.3  ...
bad-dns  DOWN    -     1.9     -       -       -        2.0       -        -          ... no such host
```

Exit codes: `0` all healthy · `1` something down or cert expiring · `2` usage/config error.

```bash
./bin/netprobe check -config targets.example.json -json | jq '.[] | select(.up == false)'
./bin/netprobe serve -config targets.example.json -listen :9115 -interval 30s
curl localhost:9115/metrics
```

## Config

```json
{
  "targets": [
    { "name": "github", "url": "https://github.com" },
    { "name": "api",    "url": "https://api.example.com/health", "expected_status": 200 }
  ]
}
```

Unknown fields, missing names/URLs and duplicate names are rejected at startup.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `netprobe_up` | gauge | 1 if last probe succeeded |
| `netprobe_http_status_code` | gauge | last HTTP status |
| `netprobe_dns_seconds` / `_connect_seconds` / `_tls_handshake_seconds` / `_ttfb_seconds` / `_total_seconds` | gauge | phase timings |
| `netprobe_cert_expiry_days` | gauge | days until leaf cert expires |
| `netprobe_checks_total` / `netprobe_failures_total` | counter | probe rounds / failures |

Alert rules: [`deploy/prometheus-alerts.yml`](deploy/prometheus-alerts.yml).

## Deploy on Linux (systemd)

```bash
sudo ./scripts/install.sh targets.example.json
journalctl -u netprobe -f
```

Or Docker: `make docker && docker run -p 9115:9115 netprobe:latest`

## Development

```bash
make lint   # gofmt + go vet
make test   # go test -race
```

Tests use local `httptest` HTTP/TLS servers to cover: TLS phase timing and cert parsing, unhealthy and unexpected status codes, retry-then-recover, timeouts, refused connections, and concurrency/ordering of the worker pool. CI runs gofmt, vet, race tests, build and shellcheck.

## Layout

```
cmd/netprobe/        CLI: check + serve
internal/probe/      probing, httptrace timings, retries, worker pool
internal/metrics/    thread-safe result store + Prometheus exposition
deploy/              systemd unit, Prometheus alert rules
scripts/install.sh   Linux installer
```
