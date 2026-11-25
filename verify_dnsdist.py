"""Validate the generated dnsdist config and exercise its local DNS paths."""

from __future__ import annotations

import argparse
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import dns.message
import dns.query
import dns.rdatatype
import dns.rrset

from dnsdist_compiler import compile_lab_config


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        wire, sock = self.request
        sock.sendto(_response(wire, self.server.answer), self.client_address)


class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        prefix = self.rfile.read(2)
        if len(prefix) != 2:
            return
        length = struct.unpack("!H", prefix)[0]
        wire = self.rfile.read(length)
        if len(wire) == length:
            response = _response(wire, self.server.answer)
            self.wfile.write(struct.pack("!H", len(response)) + response)


class _UDPServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True


class _TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _response(wire: bytes, address: str) -> bytes:
    query = dns.message.from_wire(wire)
    response = dns.message.make_response(query, recursion_available=True)
    if query.question and query.question[0].rdtype == dns.rdatatype.A:
        response.answer.append(dns.rrset.from_text(query.question[0].name, 30, "IN", "A", address))
    return response.to_wire()


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            udp.bind(("127.0.0.1", port))
            return port


def _artifact() -> dict:
    return {
        "schema_version": "dns-policy/v1",
        "policies": [
            {
                "id": 1,
                "name": "engine-smoke-fixed-a",
                "status": "启用",
                "priority": 100,
                "match": {"client_cidr": "127.0.0.1/32", "domain": "fixed.test", "domain_mode": "exact"},
                "decision": {"type": "return_a", "address": "192.0.2.55"},
                "ttl_seconds": 60,
            },
            {
                "id": 2,
                "name": "engine-smoke-pool",
                "status": "启用",
                "priority": 90,
                "match": {"client_cidr": "127.0.0.1/32", "domain": "forward.test", "domain_mode": "suffix"},
                "decision": {"type": "forward_group", "group": "smoke-pool"},
                "ttl_seconds": 60,
            },
        ],
    }


def _addresses(response: dns.message.Message) -> list[str]:
    return [rdata.address for rrset in response.answer for rdata in rrset if rrset.rdtype == dns.rdatatype.A]


def _query(name: str, port: int, tcp: bool) -> list[str]:
    query = dns.message.make_query(name, dns.rdatatype.A)
    if tcp:
        response = dns.query.tcp(query, "127.0.0.1", port=port, timeout=2)
    else:
        response = dns.query.udp(query, "127.0.0.1", port=port, timeout=2)
    return _addresses(response)


def _start_upstream(port: int, answer: str) -> tuple[list[object], list[threading.Thread]]:
    udp = _UDPServer(("127.0.0.1", port), _UDPHandler)
    tcp = _TCPServer(("127.0.0.1", port), _TCPHandler)
    udp.answer = answer
    tcp.answer = answer
    threads = [
        threading.Thread(target=udp.serve_forever, daemon=True),
        threading.Thread(target=tcp.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    return [udp, tcp], threads


def _start_recursor(binary: str, work_dir: Path, name: str, port: int, answer_name: str, answer: str) -> tuple[subprocess.Popen, Path]:
    config_dir = work_dir / name
    config_dir.mkdir()
    zone_path = config_dir / "test.zone"
    owner = answer_name.removesuffix(".test")
    zone_path.write_text(
        "$ORIGIN test.\n"
        "$TTL 60\n"
        "@ IN SOA ns.test. hostmaster.test. 1 3600 600 86400 60\n"
        "@ IN NS ns.test.\n"
        "ns IN A 192.0.2.53\n"
        f"{owner} IN A {answer}\n",
        encoding="utf-8",
    )
    (config_dir / "recursor.yml").write_text(
        "incoming:\n"
        "  listen:\n"
        f'    - "127.0.0.1:{port}"\n'
        "  allow_from:\n"
        '    - "127.0.0.0/8"\n'
        "recursor:\n"
        f'  socket_dir: "{config_dir}"\n'
        "  auth_zones:\n"
        '    - zone: "test."\n'
        f'      file: "{zone_path}"\n',
        encoding="utf-8",
    )
    check = subprocess.run(
        [binary, f"--config-dir={config_dir}", "--config=check"],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if check.returncode:
        raise RuntimeError(f"pdns_recursor config check failed for {name}:\n{check.stdout}{check.stderr}")
    log_path = config_dir / "recursor.log"
    log_file = log_path.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            [binary, f"--config-dir={config_dir}"],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
    finally:
        log_file.close()
    return process, log_path


def _wait_for_answer(process: subprocess.Popen, log_path: Path, name: str, port: int, expected: str, label: str) -> None:
    deadline = time.monotonic() + 10
    while True:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited during startup:\n{log_path.read_text(encoding='utf-8')}")
        try:
            if _query(name, port, False) == [expected]:
                return
        except Exception:
            pass
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{label} did not become ready:\n{log_path.read_text(encoding='utf-8')}")
        time.sleep(0.1)


def _stop_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dnsdist", default="dnsdist", help="Path to the dnsdist executable")
    parser.add_argument("--recursor", help="Optionally use real pdns_recursor upstreams instead of mock servers")
    args = parser.parse_args()

    result = compile_lab_config(_artifact())
    template_ports: dict[str, int] = {}
    for old_port in ("5300", "5399", "5301"):
        port = _reserve_port()
        while port in template_ports.values():
            port = _reserve_port()
        template_ports[old_port] = port
    config = result["config"]
    for old_port, new_port in template_ports.items():
        config = config.replace(f"127.0.0.1:{old_port}", f"127.0.0.1:{new_port}")

    with tempfile.TemporaryDirectory(prefix="dnsdist-engine-verify-") as temp_dir:
        config_path = Path(temp_dir) / "dnsdist.conf"
        log_path = Path(temp_dir) / "dnsdist.log"
        config_path.write_text(config, encoding="utf-8")

        check = subprocess.run(
            [args.dnsdist, "--check-config", "--config", str(config_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if check.returncode:
            raise RuntimeError(f"dnsdist --check-config failed:\n{check.stdout}{check.stderr}")

        version = subprocess.run([args.dnsdist, "--version"], check=True, capture_output=True, text=True, timeout=10)
        print(version.stdout.strip())
        print("dnsdist generated config syntax: PASS")

        upstreams: list[object] = []
        recursors: list[tuple[subprocess.Popen, Path]] = []
        dnsdist_process: subprocess.Popen | None = None
        try:
            backends = result["backend_placeholders"]
            if args.recursor:
                for name, qname, answer in (
                    ("smoke-pool", "api.forward.test", "203.0.113.11"),
                    ("default", "fallback.test", "203.0.113.99"),
                ):
                    original_port = backends[name].rsplit(":", 1)[1]
                    port = template_ports[original_port]
                    process, recursor_log = _start_recursor(args.recursor, Path(temp_dir), f"recursor-{name}", port, qname, answer)
                    recursors.append((process, recursor_log))
                    _wait_for_answer(process, recursor_log, qname, port, answer, f"pdns_recursor {name}")
                recursor_version = subprocess.run([args.recursor, "--version"], check=True, capture_output=True, text=True, timeout=10)
                print(recursor_version.stdout.splitlines()[0])
            else:
                for name, address in backends.items():
                    answer = "203.0.113.11" if name == "smoke-pool" else "203.0.113.99"
                    port = template_ports[address.rsplit(":", 1)[1]]
                    servers, _ = _start_upstream(port, answer)
                    upstreams.extend(servers)

            with log_path.open("w", encoding="utf-8") as log_file:
                dnsdist_process = subprocess.Popen(
                    [args.dnsdist, "--supervised", "--disable-syslog", "--config", str(config_path)],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                )

            listener_port = template_ports["5300"]
            _wait_for_answer(dnsdist_process, log_path, "fixed.test", listener_port, "192.0.2.55", "dnsdist")
            cases = [
                ("fixed.test", "192.0.2.55"),
                ("api.forward.test", "203.0.113.11"),
                ("fallback.test", "203.0.113.99"),
            ]
            for tcp in (False, True):
                for name, expected in cases:
                    actual = _query(name, listener_port, tcp)
                    if actual != [expected]:
                        transport = "TCP" if tcp else "UDP"
                        raise AssertionError(f"{transport} {name}: expected {expected}, got {actual}")
            backend_type = "real Recursor" if args.recursor else "mock upstream"
            print(f"dnsdist runtime smoke ({backend_type}; fixed A, named pool, default pool; UDP/TCP): PASS")
        finally:
            if dnsdist_process is not None:
                _stop_process(dnsdist_process)
            for upstream in upstreams:
                upstream.shutdown()
                upstream.server_close()
            for process, _ in recursors:
                _stop_process(process)


if __name__ == "__main__":
    main()
