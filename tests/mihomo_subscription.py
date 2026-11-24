#!/usr/bin/env python3
"""Run against a test subconverter with cache enabled (requires PyYAML)."""
import base64
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

BACKEND = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:25500"
UUID = "00000000-0000-4000-8000-000000000001"
NODES = [
    {"name": "fixture-any", "type": "anytls", "server": "any.example.invalid", "port": 443,
     "password": "test@+%/:", "fingerprint": "00" * 32, "client-fingerprint": "chrome",
     "idle-session-check-interval": 12, "idle-session-timeout": 45, "min-idle-session": 2,
     "alpn": ["h2", "http/1.1", "fixture"], "ech-opts": {"enable": True, "query-server-name": "ech.example.invalid"}},
    {"name": "fixture-hy2", "type": "hysteria2", "server": "hy2.example.invalid", "ports": "20000-20100",
     "password": "fixture:pass", "hop-interval": "10-20", "obfs": "salamander", "obfs-password": "a+b&c"},
    {"name": "fixture-hy2-other-sni", "type": "hysteria2", "server": "hy2.example.invalid", "ports": "20000-20100",
     "password": "fixture:pass", "sni": "other.example.invalid"},
    {"name": "fixture-tuic", "type": "tuic", "server": "tuic.example.invalid", "port": 443,
     "uuid": UUID, "password": "p@ss+", "heartbeat-interval": 7000, "udp-relay-mode": "quic", "alpn": ["h3", "custom"]},
    {"name": "fixture-xhttp", "type": "vless", "server": "xhttp.example.invalid", "port": 443, "uuid": UUID,
     "network": "xhttp", "tls": True, "servername": "sni.example.invalid", "client-fingerprint": "chrome",
     "reality-opts": {"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE", "short-id": "aabb"},
     "xhttp-opts": {"host": "http.example.invalid", "path": "/fixture", "mode": "packet-up", "x-padding-bytes": "100-200",
                    "download-settings": {"server": "down.example.invalid", "port": 443, "path": "/down"}}},
]


def convert(source, target="clash", incoming="clash.meta/v1.19.33", **kwargs):
    args = {"url": source, "target": target, "list": "true", "emoji": "false", "insert": "false", "append_info": "false", **kwargs}
    req = urllib.request.Request(BACKEND + "/sub?" + urllib.parse.urlencode(args), headers={"User-Agent": incoming})
    with urllib.request.urlopen(req, timeout=10) as res:
        return res.read()


def data(body):
    if isinstance(body, str):
        body = body.encode()
    return "data:text/plain;base64," + base64.urlsafe_b64encode(body).decode()


def rows(body):
    return yaml.safe_load(body)["proxies"]


def main():
    fixture = data(yaml.safe_dump({"proxies": NODES}, sort_keys=False))
    for target in ("clash", "mihomo", "auto"):
        actual = rows(convert(fixture, target))
        assert len(actual) == len(NODES), (target, len(actual))
        for got, wanted in zip(actual, NODES):
            for key, value in wanted.items():
                assert got.get(key) == value, (target, wanted['name'], key, got.get(key), value)
    modified = rows(convert(fixture, exclude="fixture-tuic", udp="false", scv="true", tfo="true"))
    assert len(modified) == 4 and all(n["name"] != "fixture-tuic" for n in modified)
    assert modified[0]["udp"] is False and modified[0]["skip-cert-verify"] is True and modified[0]["tfo"] is True

    # target=mixed deliberately represents only what the share schemes can carry.
    mixed = convert(fixture, "mixed", list="false")
    lines = base64.b64decode(mixed).decode().splitlines()
    assert [line.split(":", 1)[0] for line in lines] == ["anytls", "hysteria2", "hysteria2", "tuic", "vless"]
    for source in (data(mixed), data("\r\n".join(lines))):
        round_trip = {node["name"]: node for node in rows(convert(source))}
        assert round_trip["fixture-any"]["password"] == NODES[0]["password"]
        assert round_trip["fixture-hy2"]["ports"] == NODES[1]["ports"]
        assert round_trip["fixture-hy2"]["obfs-password"] == NODES[1]["obfs-password"]
        assert round_trip["fixture-tuic"]["udp-relay-mode"] == "quic"
        assert round_trip["fixture-tuic"]["alpn"] == ["h3", "custom"]
        assert round_trip["fixture-xhttp"]["xhttp-opts"]["host"] == "http.example.invalid"
        assert round_trip["fixture-xhttp"]["servername"] == "sni.example.invalid"

    uri = data("anytls://a%40b+c@[2001:db8::1]/?sni=tls.example.invalid#any\n"
               "hy2://user:secret@example.invalid/?insecure=0#hy2\n"
               "hy2://test@example.invalid:443,5000-5010/?ech=YWJj%2B%3D#multi")
    anytls, hy2, multi = rows(convert(uri))
    assert (anytls["server"], anytls["port"], anytls["password"]) == ("2001:db8::1", 443, "a@b+c")
    assert (hy2["port"], hy2["password"], hy2["skip-cert-verify"]) == (443, "user:secret", False)
    assert multi["ports"] == "443,5000-5010" and multi["ech-opts"]["config"] == "YWJj+="

    seen = []

    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self):
            ua = self.headers.get("User-Agent")
            seen.append(ua)
            body = yaml.safe_dump({"proxies": NODES if ua == "mihomo/1.19.34" else NODES[:1]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Upstream) as upstream:
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{upstream.server_port}/fixture"
            assert len(rows(convert(url, "auto", incoming="clash-verge/v2.5.10"))) == 1
            assert len(rows(convert(url, "auto", incoming="clash-verge/v2.5.10", ua="mihomo/1.19.34"))) == len(NODES)
            assert len(rows(convert(url, "auto", incoming="clash-verge/v2.5.10"))) == 1
            assert seen == ["clash-verge/v2.5.10", "mihomo/1.19.34"], seen
            try:
                convert(url, ua="mihomo\r\nOther: value")
            except urllib.error.HTTPError as exc:
                assert exc.code == 400
            else:
                raise AssertionError("multiline UA was accepted")
        finally:
            upstream.shutdown()
    print("PASS: native Mihomo YAML, node filters, mixed URI round-trip, upstream UA and cache isolation")


if __name__ == "__main__":
    main()
