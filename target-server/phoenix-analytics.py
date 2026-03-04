#!/usr/bin/env python3
"""
Phoenix Analytics Engine
- Tails nginx JSON access log (each line = 1 HTTP/2 stream)
- Computes EMA-smoothed RPS over sliding 1s buckets
- Pushes state to all WebSocket clients every 200ms
"""

import asyncio, json, time, collections, os, math
from pathlib import Path
import websockets
try:
    import urllib.request as _ur
except ImportError:
    _ur = None

LOG_FILE   = "/var/log/nginx/access.json.log"
WS_HOST    = "0.0.0.0"
WS_PORT    = 9001
EMA_ALPHA  = 0.3          # smoothing factor (0=smooth, 1=raw)
WINDOW_S   = 5            # sliding window for peak/avg
PUSH_EVERY = 0.2          # push to clients every 200ms

# Node metrics agents (port 9002 on each VPS)
NODES = {
    "target": "http://127.0.0.1:9002/metrics",
    "attack": "http://185.203.240.191:9002/metrics",
}

# ── State ────────────────────────────────────────────────────────────────────
clients   = set()
node_metrics = {
    "target": {"cpu": 0.0, "ram_used_mb": 0, "ram_total_mb": 0, "ram_pct": 0.0},
    "attack": {"cpu": 0.0, "ram_used_mb": 0, "ram_total_mb": 0, "ram_pct": 0.0},
}
state = {
    "rps":        0.0,
    "rps_peak":   0.0,
    "rps_ema":    0.0,
    "total":      0,
    "errors":     0,      # 4xx + 5xx
    "active_h2":  0,
    "connections": collections.Counter(),  # conn_id -> last seen
    "latency_sum": 0.0,
    "latency_count": 0,
    "latency_p": [],      # rolling last 1000 rt values
    "by_uri":    collections.Counter(),
    "by_status": collections.Counter(),
    "timeline":  collections.deque(maxlen=300),  # (ts, rps) last 300 samples
    "window_counts": collections.deque(),        # (timestamp, count) pairs
    "last_window_total": 0,
    "last_push": 0.0,
}

# ── Sliding window RPS ───────────────────────────────────────────────────────
def add_to_window(count: int):
    now = time.monotonic()
    state["window_counts"].append((now, count))
    # prune old entries outside window
    cutoff = now - WINDOW_S
    while state["window_counts"] and state["window_counts"][0][0] < cutoff:
        state["window_counts"].popleft()

def window_rps() -> float:
    if not state["window_counts"]:
        return 0.0
    total = sum(c for _, c in state["window_counts"])
    span = state["window_counts"][-1][0] - state["window_counts"][0][0]
    if span < 0.01:
        return float(total)
    return total / span

# ── Parse a single nginx JSON log line ──────────────────────────────────────
def parse_line(line: str):
    line = line.strip()
    if not line:
        return
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        return

    state["total"] += 1
    add_to_window(1)

    status = int(r.get("status", 0))
    if status >= 400:
        state["errors"] += 1

    rt = float(r.get("rt", 0))
    state["latency_sum"] += rt
    state["latency_count"] += 1
    lp = state["latency_p"]
    lp.append(rt)
    if len(lp) > 1000:
        lp.pop(0)

    uri = r.get("uri", "/")
    state["by_uri"][uri] += 1
    state["by_status"][str(status)] += 1

    conn = r.get("conn", 0)
    state["connections"][conn] = time.monotonic()

# ── Poll node metrics agents ─────────────────────────────────────────────────
async def poll_node_metrics():
    loop = asyncio.get_event_loop()
    while True:
        for name, url in NODES.items():
            try:
                data = await loop.run_in_executor(
                    None,
                    lambda u=url: json.loads(_ur.urlopen(u, timeout=1).read())
                )
                node_metrics[name].update(data)
            except Exception:
                pass  # agent unreachable — keep last value
        await asyncio.sleep(1)

# ── Tail the log file ────────────────────────────────────────────────────────
async def tail_log():
    # wait for file to exist
    while not Path(LOG_FILE).exists():
        await asyncio.sleep(0.5)

    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # seek to end — only new lines
        print(f"Tailing {LOG_FILE}")
        while True:
            line = f.readline()
            if line:
                parse_line(line)
            else:
                await asyncio.sleep(0.01)  # 10ms poll when no new data

# ── Compute EMA and broadcast ────────────────────────────────────────────────
def percentile(data: list, p: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    idx = (len(s) - 1) * p / 100
    lo, hi = int(idx), min(int(idx) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (idx - lo)

async def broadcast_loop():
    while True:
        await asyncio.sleep(PUSH_EVERY)

        # EMA update
        raw_rps = window_rps()
        ema = EMA_ALPHA * raw_rps + (1 - EMA_ALPHA) * state["rps_ema"]
        state["rps_ema"] = ema
        state["rps"] = round(ema, 1)
        if ema > state["rps_peak"]:
            state["rps_peak"] = round(ema, 1)

        # prune stale connections (not seen in 10s)
        now = time.monotonic()
        state["connections"] = {
            k: v for k, v in state["connections"].items()
            if now - v < 10
        }

        # latency stats (ms)
        lp = state["latency_p"]
        lat = {
            "p50":  round(percentile(lp, 50)  * 1000, 1),
            "p95":  round(percentile(lp, 95)  * 1000, 1),
            "p99":  round(percentile(lp, 99)  * 1000, 1),
            "mean": round((state["latency_sum"] / state["latency_count"] * 1000) if state["latency_count"] else 0, 1),
        }

        # timeline sample
        state["timeline"].append({
            "t": round(time.time(), 2),
            "rps": state["rps"]
        })

        # top URIs
        top_uri = dict(state["by_uri"].most_common(5))
        # status breakdown
        by_status = dict(state["by_status"])

        payload = json.dumps({
            "rps":         state["rps"],
            "rps_peak":    state["rps_peak"],
            "total":       state["total"],
            "errors":      state["errors"],
            "error_rate":  round(state["errors"] / state["total"] * 100, 1) if state["total"] else 0,
            "connections": len(state["connections"]),
            "latency":     lat,
            "top_uri":     top_uri,
            "by_status":   by_status,
            "timeline":    list(state["timeline"])[-60:],  # last 60 samples
            "attack":      state["rps"] > 500,
            "nodes":       node_metrics,
        })

        dead = set()
        for ws in clients:
            try:
                await ws.send(payload)
            except Exception:
                dead.add(ws)
        clients.difference_update(dead)

# ── WebSocket handler ────────────────────────────────────────────────────────
async def handler(ws):
    clients.add(ws)
    print(f"Client connected ({len(clients)} total)")
    try:
        await ws.wait_closed()
    finally:
        clients.discard(ws)
        print(f"Client disconnected ({len(clients)} total)")

# ── Main ─────────────────────────────────────────────────────────────────────
async def main():
    print(f"Phoenix Analytics Engine starting on ws://{WS_HOST}:{WS_PORT}")
    async with websockets.serve(handler, WS_HOST, WS_PORT):
        await asyncio.gather(
            tail_log(),
            broadcast_loop(),
            poll_node_metrics(),
        )

if __name__ == "__main__":
    asyncio.run(main())
