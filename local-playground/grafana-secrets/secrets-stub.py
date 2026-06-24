#!/usr/bin/env python3
"""Tiny stand-in for the supervisor's loopback secrets endpoint.

Lets you exercise the grafanasecretsmanager confmap provider WITHOUT a supervisor
or a real Fleet Management server. Serves GET /{name} -> {"value": ...} and
enforces the bearer token, exactly like the real broker.

Usage:
    python3 secrets-stub.py            # listens on 127.0.0.1:8999, token "playtoken"

Then point the collector at it:
    GRAFANA_SECRETS_MANAGER_ENDPOINT=http://127.0.0.1:8999 \
    GRAFANA_SECRETS_MANAGER_TOKEN=playtoken \
    ./bin/otelcontribcol_darwin_arm64 --config local-playground/grafana-secrets/collector-standalone.yaml
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "playtoken"
SECRETS = {
    "demo": "hello-from-secret",
    "api-key": "sk-test-12345",
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_response(401)
            self.end_headers()
            return
        name = self.path.lstrip("/")
        if name not in SECRETS:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({"value": SECRETS[name]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)
        print(f"served secret {name!r}")

    def log_message(self, *args):
        pass  # quiet default logging


if __name__ == "__main__":
    print("secrets stub on http://127.0.0.1:8999 (token: playtoken)")
    HTTPServer(("127.0.0.1", 8999), Handler).serve_forever()
