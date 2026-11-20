"""Small local DNS policy runtime for isolated MVP validation."""

from __future__ import annotations

import ipaddress
import json
import socketserver
import sqlite3
import struct
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset


ACTIVE_STATUS = "启用"
DEFAULT_GROUP = "default"


def now_text() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class _UDPServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = False


class _TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        wire, sock = self.request
        response = self.server.runtime.answer(wire, self.client_address[0])
        if response:
            sock.sendto(response, self.client_address)


class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        prefix = self.rfile.read(2)
        if len(prefix) != 2:
            return
        length = struct.unpack("!H", prefix)[0]
        wire = self.rfile.read(length)
        if len(wire) != length:
            return
        response = self.server.runtime.answer(wire, self.client_address[0])
        if response:
            self.wfile.write(struct.pack("!H", len(response)) + response)


class DnsRuntime:
    def __init__(self, db_path: Path, host: str = "127.0.0.1", port: int = 15300, timeout: float = 1.5):
        self.db_path = Path(db_path)
        self.host = host
        self.port = port
        self.timeout = timeout
        self.udp_server = _UDPServer((host, port), _UDPHandler)
        self.port = int(self.udp_server.server_address[1])
        try:
            self.tcp_server = _TCPServer((host, self.port), _TCPHandler)
        except Exception:
            self.udp_server.server_close()
            raise
        self.udp_server.runtime = self
        self.tcp_server.runtime = self
        self.threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._server_offsets: dict[str, int] = {}
        self._query_count = 0

    def start(self) -> None:
        for label, server in (("udp", self.udp_server), ("tcp", self.tcp_server)):
            thread = threading.Thread(target=server.serve_forever, name=f"dns-runtime-{label}", daemon=True)
            thread.start()
            self.threads.append(thread)

    def stop(self) -> None:
        for server in (self.udp_server, self.tcp_server):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)

    def info(self) -> dict:
        return {
            "running": bool(self.threads),
            "host": self.host,
            "port": self.port,
            "endpoint": f"{self.host}:{self.port}",
            "transports": ["udp", "tcp"],
            "query_count": self._query_count,
        }

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.db_path, timeout=3)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _matching_policies(self, client_ip: str, qname: str, qtype: str) -> list[dict]:
        try:
            client = ipaddress.IPv4Address(client_ip)
        except ipaddress.AddressValueError:
            return []
        qname = qname.rstrip(".").encode("idna").decode("ascii").lower()
        candidates = []
        with self._connect() as db:
            rows = db.execute("SELECT * FROM policies WHERE status=?", (ACTIVE_STATUS,)).fetchall()
        for row in rows:
            try:
                network = ipaddress.ip_network(row["network"], strict=False)
            except ValueError:
                continue
            if not isinstance(network, ipaddress.IPv4Network) or client not in network:
                continue
            domain = row["domain"].rstrip(".").lower()
            suffix_policy = domain.startswith("*.")
            root = domain[2:] if suffix_policy else domain
            matches = qname != root and qname.endswith("." + root) if suffix_policy else qname == root
            if not matches:
                continue
            if row["action_type"] == "answer" and qtype != "A":
                continue
            candidates.append({**dict(row), "prefix": network.prefixlen, "exact": not suffix_policy, "domain_length": len(root)})
        candidates.sort(key=lambda row: (-row["priority"], -row["prefix"], -int(row["exact"]), -row["domain_length"], row["id"]))
        return candidates

    def _get_group(self, name: str | None = None) -> dict | None:
        with self._connect() as db:
            if name is None:
                row = db.execute("SELECT * FROM upstream_groups WHERE is_default=1 LIMIT 1").fetchone()
            else:
                row = db.execute("SELECT * FROM upstream_groups WHERE name=?", (name,)).fetchone()
        if row is None:
            return None
        return {**dict(row), "servers": json.loads(row["servers_json"])}

    def _ordered_servers(self, group: dict) -> list[dict]:
        servers = group["servers"]
        if not servers:
            return []
        with self._lock:
            offset = self._server_offsets.get(group["name"], 0) % len(servers)
            self._server_offsets[group["name"]] = (offset + 1) % len(servers)
        return servers[offset:] + servers[:offset]

    @staticmethod
    def _servfail(query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query, recursion_available=bool(query.flags & dns.flags.RD))
        response.set_rcode(dns.rcode.SERVFAIL)
        return response

    def _log(self, client_ip: str, qname: str, qtype: str, action: str, target: str, rcode: str, elapsed_ms: float) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO query_logs(client_ip,qname,qtype,action,target,rcode,latency_ms,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (client_ip, qname, qtype, action, target, rcode, round(elapsed_ms, 2), now_text()),
            )
            db.execute("DELETE FROM query_logs WHERE id NOT IN (SELECT id FROM query_logs ORDER BY id DESC LIMIT 2000)")
        with self._lock:
            self._query_count += 1

    def answer(self, wire: bytes, client_ip: str) -> bytes | None:
        started = time.monotonic()
        try:
            query = dns.message.from_wire(wire)
            if query.opcode() != dns.opcode.QUERY or len(query.question) != 1:
                response = dns.message.make_response(query, recursion_available=False)
                response.set_rcode(dns.rcode.FORMERR if not query.question else dns.rcode.NOTIMP)
                return response.to_wire()

            question = query.question[0]
            qname = question.name.to_text().rstrip(".")
            qtype = dns.rdatatype.to_text(question.rdtype)
            policy = next(iter(self._matching_policies(client_ip, qname, qtype)), None)
            if policy and policy["action_type"] == "answer":
                response = dns.message.make_response(query, recursion_available=bool(query.flags & dns.flags.RD))
                response.answer.append(dns.rrset.from_text(question.name, policy["ttl"], "IN", "A", policy["target"]))
                self._log(client_ip, qname, qtype, "固定 A", policy["line"], "NOERROR", (time.monotonic() - started) * 1000)
                return response.to_wire()

            group_name = policy["target"] if policy else None
            group = self._get_group(group_name)
            route_name = policy["line"] if policy else "默认上游"
            if group is None:
                response = self._servfail(query)
                self._log(client_ip, qname, qtype, "上游组未配置", group_name or "默认组未设置", "SERVFAIL", (time.monotonic() - started) * 1000)
                return response.to_wire()

            response = None
            for server in self._ordered_servers(group):
                try:
                    response, _used_tcp = dns.query.udp_with_fallback(
                        query,
                        where=server["address"],
                        port=server["port"],
                        timeout=self.timeout,
                    )
                    break
                except (dns.exception.DNSException, OSError):
                    response = None
            if response is None:
                response = self._servfail(query)
                self._log(client_ip, qname, qtype, "上游超时", group["name"], "SERVFAIL", (time.monotonic() - started) * 1000)
            else:
                rcode = dns.rcode.to_text(response.rcode())
                self._log(client_ip, qname, qtype, "上游转发", route_name, rcode, (time.monotonic() - started) * 1000)
            return response.to_wire()
        except (dns.exception.DNSException, ValueError, struct.error):
            return None
