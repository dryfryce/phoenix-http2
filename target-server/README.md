# Phoenix Target Server

HTTP/2 test target with real-time analytics. Runs on the target VPS (`81.91.177.199`).

## Stack

| Component | File | Purpose |
|-----------|------|---------|
| nginx | `nginx.conf` + `nginx-phoenix-target.conf` | HTTP/2 + TLS 1.3, unbuffered JSON access log |
| Analytics engine | `phoenix-analytics.py` | Tails access log, computes EMA RPS, pushes via WebSocket |
| Aux endpoints | `phoenix-target-aux.py` | `/heavy` (50ms delay), `/small` (1 byte) |
| Dashboard | `dashboard.html` | Live browser UI — sparkline, latency, top URIs |
| Test page | `index.html` | Main landing page |
| Systemd | `phoenix-analytics.service` | Keeps analytics engine running |

## How the Analytics Work

```
nginx access log (JSON, flush=100ms)
  └── each HTTP/2 stream = 1 log line  ← the truth (not stub_status)
        │
        ▼
phoenix-analytics.py
  ├── tail -f access.json.log
  ├── parse each JSON line
  ├── 5s sliding window counter
  ├── EMA smoothing (α=0.3)  ← prevents timing jitter
  └── WebSocket push every 200ms → port 9001
        │
        ▼ proxied via nginx /ws → wss://
dashboard.html (browser)
  ├── Sparkline (last 60 samples)
  ├── Latency p50/p95/p99/mean
  ├── Top URIs + status code breakdown
  └── Attack alert (RPS > 500)
```

## Why not stub_status?

`nginx_status` only counts **TCP connections**, not HTTP/2 streams.
HTTP/2 multiplexes many requests over 1 connection — stub_status would show
`1 connection` when Phoenix is sending 10,000 streams/sec. The access log sees every stream.

## Setup

```bash
# On target VPS (Ubuntu 22.04)
pip3 install websockets

# Copy files
cp nginx.conf /etc/nginx/nginx.conf
cp nginx-phoenix-target.conf /etc/nginx/sites-available/phoenix-target
ln -sf /etc/nginx/sites-available/phoenix-target /etc/nginx/sites-enabled/
cp phoenix-analytics.py /usr/local/bin/
cp phoenix-target-aux.py /usr/local/bin/
cp phoenix-analytics.service /etc/systemd/system/
cp index.html dashboard.html /var/www/target/

# Start
systemctl daemon-reload
systemctl enable --now phoenix-analytics
nginx -t && systemctl reload nginx
```

## Endpoints

| URL | Description |
|-----|-------------|
| `https://host/` | Main test page |
| `https://host/dashboard` | Live analytics dashboard |
| `https://host/health` | Health check JSON |
| `https://host/heavy` | 50ms simulated heavy endpoint |
| `https://host/small` | 1-byte response (max throughput test) |
| `wss://host/ws` | WebSocket analytics stream |
