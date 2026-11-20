"""Run a loopback-only end-to-end check of policy, DNS UDP/TCP, and logs."""

from __future__ import annotations

import json
import os
import socketserver
import struct
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

sys.dont_write_bytecode = True
APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR))
TEMP = tempfile.TemporaryDirectory(prefix="dns-mvp-verify-")
os.environ["DNS_ALT_DB_PATH"] = str(Path(TEMP.name) / "verify.sqlite3")

import dns.message
import dns.query
import dns.rdatatype
import dns.rrset

import server
from dns_runtime import DnsRuntime


class _MockUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        wire, sock = self.request
        sock.sendto(_mock_response(wire), self.client_address)


class _MockTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        prefix = self.rfile.read(2)
        if len(prefix) != 2:
            return
        length = struct.unpack("!H", prefix)[0]
        wire = self.rfile.read(length)
        if len(wire) == length:
            response = _mock_response(wire)
            self.wfile.write(struct.pack("!H", len(response)) + response)


class _UDPServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = False


class _TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


def _mock_response(wire: bytes) -> bytes:
    query = dns.message.from_wire(wire)
    response = dns.message.make_response(query, recursion_available=True)
    if query.question:
        question = query.question[0]
        if question.rdtype == dns.rdatatype.A:
            response.answer.append(dns.rrset.from_text(question.name, 30, "IN", "A", "203.0.113.8"))
        elif question.rdtype == dns.rdatatype.AAAA:
            response.answer.append(dns.rrset.from_text(question.name, 30, "IN", "AAAA", "2001:db8::8"))
    return response.to_wire()


def _api(base: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"} if data else {}, method="GET" if data is None else "POST")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def main() -> None:
    server.init_db()
    mock_udp = _UDPServer(("127.0.0.1", 0), _MockUDPHandler)
    mock_port = mock_udp.server_address[1]
    mock_tcp = _TCPServer(("127.0.0.1", mock_port), _MockTCPHandler)
    mock_threads = [
        threading.Thread(target=mock_udp.serve_forever, daemon=True),
        threading.Thread(target=mock_tcp.serve_forever, daemon=True),
    ]
    for thread in mock_threads:
        thread.start()

    runtime = DnsRuntime(server.DB_PATH, port=0, timeout=1)
    runtime.start()
    server.RUNTIME = runtime
    http = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    server.PORT = int(http.server_address[1])
    http_thread = threading.Thread(target=http.serve_forever, daemon=True)
    http_thread.start()
    base = f"http://127.0.0.1:{server.PORT}"

    try:
        status, health = _api(base, "/api/health")
        assert status == 200 and health["dns_runtime"]["running"]

        status, _ = _api(base, "/api/upstreams", {"name": "lab-upstream", "servers": [{"address": "127.0.0.1", "port": mock_port}], "is_default": True})
        assert status == 201

        status, created = _api(base, "/api/policies", {"name": "固定回答验证", "domain": "fixed.example.test", "network": "127.0.0.0/8", "line": "内网", "action_type": "answer", "target": "192.0.2.42", "priority": 500, "ttl": 45})
        assert status == 201
        fixed_id = created["policy"]["id"]
        status, _ = _api(base, f"/api/policies/{fixed_id}/enable", {})
        assert status == 200

        status, created = _api(base, "/api/policies", {"name": "后缀转发验证", "domain": "*.route.example.test", "network": "127.0.0.0/8", "line": "教育网", "action_type": "forward", "target": "lab-upstream", "priority": 400, "ttl": 60})
        assert status == 201
        forward_id = created["policy"]["id"]
        status, _ = _api(base, f"/api/policies/{forward_id}/enable", {})
        assert status == 200

        listen_port = runtime.port
        fixed_udp = dns.query.udp(dns.message.make_query("fixed.example.test", "A"), "127.0.0.1", port=listen_port, timeout=2)
        fixed_tcp = dns.query.tcp(dns.message.make_query("fixed.example.test", "A"), "127.0.0.1", port=listen_port, timeout=2)
        assert fixed_udp.answer[0][0].address == "192.0.2.42" and fixed_udp.answer[0].ttl == 45
        assert fixed_tcp.answer[0][0].address == "192.0.2.42"

        routed = dns.query.udp(dns.message.make_query("www.route.example.test", "A"), "127.0.0.1", port=listen_port, timeout=2)
        apex = dns.query.udp(dns.message.make_query("route.example.test", "A"), "127.0.0.1", port=listen_port, timeout=2)
        default_tcp = dns.query.tcp(dns.message.make_query("other.example.test", "A"), "127.0.0.1", port=listen_port, timeout=2)
        aaaa = dns.query.udp(dns.message.make_query("fixed.example.test", "AAAA"), "127.0.0.1", port=listen_port, timeout=2)
        assert routed.answer[0][0].address == "203.0.113.8"
        assert apex.answer[0][0].address == "203.0.113.8"
        assert default_tcp.answer[0][0].address == "203.0.113.8"
        assert aaaa.answer[0][0].address == "2001:db8::8"

        status, _ = _api(base, f"/api/policies/{fixed_id}/disable", {})
        assert status == 200
        disabled = dns.query.udp(dns.message.make_query("fixed.example.test", "A"), "127.0.0.1", port=listen_port, timeout=2)
        assert disabled.answer[0][0].address == "203.0.113.8"

        status, _ = _api(base, "/api/upstreams/lab-upstream/delete", {})
        assert status == 400

        status, state = _api(base, "/api/state")
        assert status == 200
        logs = state["logs"]
        assert len(logs) >= 7
        assert any(row[2] == "route.example.test" and row[5] == "默认上游" for row in logs)
        assert any(row[2] == "www.route.example.test" and row[5] == "教育网" for row in logs)

        status, preview = _api(base, "/api/preview", {})
        assert status == 200 and preview["dnsdist_lab_preview"]["complete_config"]
        print(json.dumps({
            "result": "PASS",
            "runtime": f"127.0.0.1:{listen_port} UDP/TCP",
            "fixed_a_udp_tcp": True,
            "suffix_forward": True,
            "suffix_root_uses_default": True,
            "default_forward_tcp": True,
            "aaaa_falls_back": True,
            "policy_toggle_updates_runtime": True,
            "referenced_group_delete_blocked": True,
            "query_logs": len(logs),
            "dnsdist_preview": preview["dnsdist_lab_preview"]["complete_config"],
        }, ensure_ascii=False))
    finally:
        http.shutdown()
        http.server_close()
        runtime.stop()
        server.RUNTIME = None
        mock_udp.shutdown()
        mock_udp.server_close()
        mock_tcp.shutdown()
        mock_tcp.server_close()
        TEMP.cleanup()


if __name__ == "__main__":
    main()
