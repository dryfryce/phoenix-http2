#!/usr/bin/env python3
"""Auxiliary endpoints for Phoenix test target"""
import http.server, json, time, subprocess, threading
from urllib.parse import urlparse

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/stats':
            try:
                out = subprocess.check_output(['curl','-sk','http://127.0.0.1:8080/nginx_status'], text=True)
                lines = out.strip().split('\n')
                active = int(lines[0].split()[-1]) if lines else 0
                nums = lines[2].split() if len(lines) > 2 else ['0','0','0']
                data = {
                    'active_connections': active,
                    'waiting_connections': int(lines[3].split()[-1]) if len(lines) > 3 else 0,
                    'total_connections': int(nums[0]) if nums else 0,
                    'total_requests': int(nums[2]) if len(nums) > 2 else 0,
                    'timestamp': time.time()
                }
            except Exception as e:
                data = {'error': str(e), 'active_connections': 0, 'waiting_connections': 0, 'total_connections': 0, 'total_requests': 0}
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Access-Control-Allow-Origin','*')
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)
        elif path == '/heavy':
            time.sleep(0.05)
            body = b'{"endpoint":"heavy","delay_ms":50}'
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)
        elif path == '/small':
            self.send_response(200)
            self.send_header('Content-Length','1')
            self.end_headers()
            self.wfile.write(b'.')
        else:
            self.send_response(404)
            self.end_headers()

server = http.server.HTTPServer(('127.0.0.1', 8888), Handler)
print('Aux server on :8888')
server.serve_forever()
