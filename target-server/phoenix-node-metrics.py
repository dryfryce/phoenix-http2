#!/usr/bin/env python3
"""
Phoenix Node Metrics Agent
Runs on each VPS — exposes CPU % and RAM usage via tiny HTTP server on port 9002.
Poll: GET /metrics → JSON { cpu, ram_used_mb, ram_total_mb, ram_pct }
"""
import time, json
from http.server import HTTPServer, BaseHTTPRequestHandler

def read_cpu():
    """Read CPU % from /proc/stat using 200ms delta sample."""
    def read_stat():
        with open("/proc/stat") as f:
            parts = f.readline().split()
        user, nice, system, idle, iowait = int(parts[1]), int(parts[2]), int(parts[3]), int(parts[4]), int(parts[5])
        total = sum(int(x) for x in parts[1:8])
        return total, idle + iowait
    t1, i1 = read_stat()
    time.sleep(0.2)
    t2, i2 = read_stat()
    dt, di = t2 - t1, i2 - i1
    return round((1 - di / dt) * 100, 1) if dt else 0.0

def read_ram():
    mem = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":")[0], line.split(":")[1].strip().split()[0]
            mem[k] = int(v)
    total = mem.get("MemTotal", 1)
    avail = mem.get("MemAvailable", 0)
    used  = total - avail
    return {
        "ram_used_mb":  round(used  / 1024),
        "ram_total_mb": round(total / 1024),
        "ram_pct":      round(used  / total * 100, 1),
    }

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass  # silence access logs
    def do_GET(self):
        if self.path == "/metrics":
            data = {"cpu": read_cpu(), **read_ram()}
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    port = 9002
    print(f"Node metrics agent on :{port}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
