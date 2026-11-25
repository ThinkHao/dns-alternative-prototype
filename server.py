#!/usr/bin/env python3
"""Local-only control API and local DNS MVP. No production DNS services are changed."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

from dnsdist_compiler import compile_fragment, compile_lab_config


APP_DIR = Path(__file__).resolve().parent
VERSION = os.environ.get("DNS_ALT_VERSION", (APP_DIR / "VERSION").read_text(encoding="utf-8").strip())
DEFAULT_DB_PATH = APP_DIR.parent.parent / "work" / "dns-alternative-prototype.sqlite3"
DB_PATH = Path(os.environ.get("DNS_ALT_DB_PATH", str(DEFAULT_DB_PATH))).expanduser().resolve()
PORT = int(os.environ.get("DNS_ALT_API_PORT", "8765"))
API_HOST = os.environ.get("DNS_ALT_API_HOST", "127.0.0.1")
DNS_HOST = os.environ.get("DNS_ALT_DNS_HOST", "127.0.0.1")
DNS_PORT = int(os.environ.get("DNS_ALT_DNS_PORT", "15300"))
if PORT < 1 or PORT > 65535:
    raise ValueError("DNS_ALT_API_PORT 必须为 1 至 65535。")
if DNS_PORT < 1024 or DNS_PORT > 65535:
    raise ValueError("DNS_ALT_DNS_PORT 必须为 1024 至 65535 的高位端口。")
ALLOWED_LINES = {"教育网", "中国电信", "中国联通", "中国移动", "备用线路", "内网"}
RUNTIME = None


def now_text() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                domain TEXT NOT NULL,
                network TEXT NOT NULL,
                line TEXT NOT NULL,
                priority INTEGER NOT NULL DEFAULT 100,
                action_type TEXT NOT NULL DEFAULT 'answer',
                target TEXT NOT NULL,
                ttl INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS revisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                kind TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS upstream_groups (
                name TEXT PRIMARY KEY,
                servers_json TEXT NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS query_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT NOT NULL,
                qname TEXT NOT NULL,
                qtype TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                rcode TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        columns = {row[1] for row in db.execute("PRAGMA table_info(policies)")}
        if "priority" not in columns:
            db.execute("ALTER TABLE policies ADD COLUMN priority INTEGER NOT NULL DEFAULT 100")
        if "action_type" not in columns:
            db.execute("ALTER TABLE policies ADD COLUMN action_type TEXT NOT NULL DEFAULT 'answer'")
            db.execute("UPDATE policies SET action_type='forward', target=substr(target, 5) WHERE target LIKE '上游组 %'")
        if db.execute("SELECT COUNT(*) FROM upstream_groups").fetchone()[0] == 0:
            db.execute("UPDATE policies SET status='待复核' WHERE action_type='forward' AND status='启用'")
        stamp = now_text()
        migrated = db.execute(
            "UPDATE policies SET status='待复核' WHERE status='启用' AND "
            "((name='教学平台优选线路' AND target='10.20.8.15') OR "
            "(name='图书馆内网访问' AND target='172.22.4.10'))"
        ).rowcount
        legacy_pending = db.execute("UPDATE policies SET status='待发布' WHERE status='模拟发布'").rowcount
        if migrated or legacy_pending:
            db.execute(
                "INSERT INTO events(message,actor,created_at) VALUES(?,?,?)",
                (f"升级兼容：{migrated} 条示例固定 A 策略转为待复核，{legacy_pending} 条旧模拟发布策略转为待发布", "系统", stamp),
            )
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS one_default_upstream ON upstream_groups(is_default) WHERE is_default=1")
        db.execute("CREATE INDEX IF NOT EXISTS query_logs_created_at ON query_logs(id DESC)")


def capture_config(db: sqlite3.Connection) -> dict:
    policies = [dict(row) for row in db.execute("SELECT * FROM policies ORDER BY id")]
    upstreams = []
    for row in db.execute("SELECT * FROM upstream_groups ORDER BY name"):
        upstreams.append({
            "name": row["name"],
            "servers": json.loads(row["servers_json"]),
            "is_default": bool(row["is_default"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    return {"schema_version": "dns-local-config/v1", "policies": policies, "upstream_groups": upstreams}


def save_revision(db: sqlite3.Connection, kind: str, stamp: str) -> None:
    db.execute(
        "INSERT INTO revisions(config_json,created_at,kind) VALUES(?,?,?)",
        (json.dumps(capture_config(db), ensure_ascii=False), stamp, kind),
    )


def normalize_config(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("配置内容必须是 JSON 对象。")
    if payload.get("schema_version") != "dns-local-config/v1":
        raise ValueError("配置版本不受支持；需要 dns-local-config/v1。")
    raw_policies = payload.get("policies")
    raw_upstreams = payload.get("upstream_groups")
    if not isinstance(raw_policies, list) or len(raw_policies) > 5000:
        raise ValueError("策略清单格式不正确或超过 5000 条。")
    if not isinstance(raw_upstreams, list) or len(raw_upstreams) > 256:
        raise ValueError("上游组清单格式不正确或超过 256 组。")
    policies = []
    policy_names = set()
    policy_ids = set()
    allowed_statuses = {"待发布", "启用", "停用", "待复核"}
    for item in raw_policies:
        if not isinstance(item, dict):
            raise ValueError("策略配置项必须是 JSON 对象。")
        policy = normalize_policy(item)
        if policy["name"] in policy_names:
            raise ValueError("配置中存在重复的策略名称。")
        policy_names.add(policy["name"])
        status = str(item.get("status", "待发布"))
        if status not in allowed_statuses:
            raise ValueError(f"策略「{policy['name']}」的状态不受支持。")
        raw_id = item.get("id")
        if raw_id is not None:
            if isinstance(raw_id, bool):
                raise ValueError("策略 ID 必须是正整数。")
            try:
                policy_id = int(raw_id)
            except (TypeError, ValueError):
                raise ValueError("策略 ID 必须是正整数。")
            if policy_id < 1 or policy_id in policy_ids:
                raise ValueError("策略 ID 必须是唯一正整数。")
            policy_ids.add(policy_id)
        else:
            policy_id = None
        policies.append({**policy, "id": policy_id, "status": status, "created_at": str(item.get("created_at") or now_text())[:64]})
    upstreams = []
    upstream_names = set()
    defaults = 0
    for item in raw_upstreams:
        if not isinstance(item, dict):
            raise ValueError("上游组配置项必须是 JSON 对象。")
        upstream = normalize_upstream(item)
        if upstream["name"] in upstream_names:
            raise ValueError("配置中存在重复的上游组名称。")
        upstream_names.add(upstream["name"])
        defaults += int(upstream["is_default"])
        upstreams.append({
            **upstream,
            "created_at": str(item.get("created_at") or now_text())[:64],
            "updated_at": str(item.get("updated_at") or now_text())[:64],
        })
    if defaults > 1:
        raise ValueError("只能有一个默认上游组。")
    for policy in policies:
        if policy["action_type"] == "forward" and policy["target"] not in upstream_names:
            raise ValueError(f"策略「{policy['name']}」引用的上游组不存在。")
    return {"schema_version": "dns-local-config/v1", "policies": policies, "upstream_groups": upstreams}


def restore_config(db: sqlite3.Connection, config: dict) -> None:
    db.execute("DELETE FROM policies")
    db.execute("DELETE FROM upstream_groups")
    for group in config["upstream_groups"]:
        db.execute(
            "INSERT INTO upstream_groups(name,servers_json,is_default,created_at,updated_at) VALUES(?,?,?,?,?)",
            (group["name"], json.dumps(group["servers"]), int(group["is_default"]), group["created_at"], group["updated_at"]),
        )
    for policy in config["policies"]:
        values = (policy["name"], policy["domain"], policy["network"], policy["line"], policy["priority"], policy["action_type"], policy["target"], policy["ttl"], policy["status"], policy["created_at"])
        if policy["id"] is None:
            db.execute("INSERT INTO policies(name,domain,network,line,priority,action_type,target,ttl,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", values)
        else:
            db.execute("INSERT INTO policies(id,name,domain,network,line,priority,action_type,target,ttl,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (policy["id"], *values))


def policy_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "domain": row["domain"],
        "match": row["network"],
        "network": row["network"],
        "line": row["line"],
        "priority": row["priority"],
        "action_type": row["action_type"],
        "target": row["target"],
        "ttl": f'{row["ttl"]}s',
        "ttl_seconds": row["ttl"],
        "status": row["status"],
        "created_at": row["created_at"],
    }


def read_state() -> dict:
    with connect() as db:
        policies = [policy_dict(row) for row in db.execute("SELECT * FROM policies ORDER BY id DESC")]
        events = [
            {"text": row["message"], "time": row["created_at"], "actor": row["actor"]}
            for row in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 50")
        ]
        revision = db.execute("SELECT COUNT(*) FROM revisions").fetchone()[0]
        revisions = []
        for row in db.execute("SELECT id,kind,created_at,config_json FROM revisions ORDER BY id DESC"):
            try:
                supported = json.loads(row["config_json"]).get("schema_version") == "dns-local-config/v1"
            except (json.JSONDecodeError, AttributeError):
                supported = False
            if supported:
                revisions.append({"id": row["id"], "kind": row["kind"], "created_at": row["created_at"]})
                if len(revisions) == 20:
                    break
        upstreams = [
            {"name": row["name"], "servers": json.loads(row["servers_json"]), "is_default": bool(row["is_default"])}
            for row in db.execute("SELECT * FROM upstream_groups ORDER BY is_default DESC, name")
        ]
        logs = [
            [row["created_at"], row["client_ip"], row["qname"], row["qtype"], row["rcode"], row["target"], f'{row["latency_ms"]:.2f} ms']
            for row in db.execute("SELECT * FROM query_logs ORDER BY id DESC LIMIT 200")
        ]
    dns_runtime = RUNTIME.info() if RUNTIME else {"running": False, "host": DNS_HOST, "port": DNS_PORT, "endpoint": f"{DNS_HOST}:{DNS_PORT}", "transports": [], "query_count": 0}
    return {"policies": policies, "upstreams": upstreams, "logs": logs, "events": events, "revision": revision, "revisions": revisions, "version": VERSION, "mode": "local-mvp", "dns_runtime": dns_runtime}


def normalize_upstream(payload: dict) -> dict:
    name = str(payload.get("name", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
        raise ValueError("上游组名称只能包含字母、数字、点、下划线和连字符。")
    raw_servers = payload.get("servers")
    if not isinstance(raw_servers, list) or not 1 <= len(raw_servers) <= 8:
        raise ValueError("每个上游组需要配置 1 至 8 个 IPv4 DNS 服务器。")
    servers = []
    for raw in raw_servers:
        if isinstance(raw, str):
            host, separator, port_text = raw.strip().partition(":")
            try:
                port = int(port_text) if separator else 53
            except ValueError:
                raise ValueError("上游 DNS 端口必须是整数。")
        elif isinstance(raw, dict):
            host = str(raw.get("address", "")).strip()
            try:
                port = int(raw.get("port", 53))
            except (TypeError, ValueError):
                raise ValueError("上游 DNS 端口必须是整数。")
        else:
            raise ValueError("上游 DNS 服务器格式不正确。")
        try:
            host = str(ipaddress.IPv4Address(host))
        except ValueError:
            raise ValueError("上游 DNS 地址必须是 IPv4 地址。")
        if port < 1 or port > 65535:
            raise ValueError("上游 DNS 端口必须为 1 至 65535。")
        server = {"address": host, "port": port}
        if server not in servers:
            servers.append(server)
    is_default = payload.get("is_default", False)
    if not isinstance(is_default, bool):
        raise ValueError("默认上游标记必须是布尔值。")
    return {"name": name, "servers": servers, "is_default": is_default}


def normalize_policy(payload: dict) -> dict:
    name = str(payload.get("name", "")).strip()
    domain = str(payload.get("domain", "")).strip().lower()
    network = str(payload.get("network", "")).strip()
    line = str(payload.get("line", "")).strip()
    try:
        priority = int(payload.get("priority", 100))
    except (TypeError, ValueError):
        raise ValueError("优先级必须是整数。")
    action_type = str(payload.get("action_type", "answer")).strip()
    target = str(payload.get("target", "")).strip()
    try:
        ttl = int(payload.get("ttl", 0))
    except (TypeError, ValueError):
        raise ValueError("TTL 必须是整数。")

    if not name or len(name) > 48:
        raise ValueError("策略名称不能为空，且最多 48 个字符。")
    if len(domain) > 253:
        raise ValueError("域名长度超限。")
    wildcard = domain.startswith("*.")
    raw_domain = domain[2:] if wildcard else domain
    try:
        ascii_domain = raw_domain.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("域名格式不正确。")
    labels = ascii_domain.split(".")
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if len(labels) < 2 or any(not label_re.fullmatch(label) for label in labels):
        raise ValueError("域名格式不正确，请填写完整域名或通配后缀。")
    domain = ("*." if wildcard else "") + ascii_domain
    try:
        parsed_network = ipaddress.ip_network(network, strict=False)
    except ValueError:
        raise ValueError("网段请使用有效的 IPv4 CIDR 格式。")
    if not isinstance(parsed_network, ipaddress.IPv4Network):
        raise ValueError("当前原型的客户端网段仅接受 IPv4 CIDR。")
    network = str(parsed_network)
    if action_type == "answer":
        try:
            target = str(ipaddress.IPv4Address(target))
        except ValueError:
            raise ValueError("A 记录返回地址必须是有效的 IPv4。")
    elif action_type == "forward":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", target):
            raise ValueError("上游组名称只能包含字母、数字、点、下划线和连字符。")
    else:
        raise ValueError("请选择支持的策略动作。")
    if line not in ALLOWED_LINES:
        raise ValueError("请选择列表中的出口线路。")
    if priority < 0 or priority > 10000:
        raise ValueError("优先级必须为 0 至 10000；数值越大越优先。")
    if ttl < 1 or ttl > 86400:
        raise ValueError("TTL 必须为 1 至 86400 秒。")
    return {"name": name, "domain": domain, "network": network, "line": line, "priority": priority, "action_type": action_type, "target": target, "ttl": ttl}


def build_artifact() -> dict:
    with connect() as db:
        rows = db.execute("SELECT * FROM policies ORDER BY priority DESC, id").fetchall()
    policies = []
    for row in rows:
        policies.append({
            "id": row["id"],
            "name": row["name"],
            "match": {
                "domain": row["domain"],
                "domain_mode": "suffix" if row["domain"].startswith("*.") else "exact",
                "client_cidr": row["network"],
            },
            "decision": ({"type": "return_a", "address": row["target"]}
                         if row["action_type"] == "answer"
                         else {"type": "forward_group", "group": row["target"]}),
            "egress_line": row["line"],
            "priority": row["priority"],
            "ttl_seconds": row["ttl"],
            "status": row["status"],
        })
    return {"schema_version": "dns-policy/v1", "generated_at": now_text(), "policies": policies}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(APP_DIR), **kwargs)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def host_allowed(self) -> bool:
        host = self.headers.get("Host", "").lower()
        try:
            hostname = urlsplit(f"//{host}").hostname
        except ValueError:
            return False
        return hostname in {"127.0.0.1", "localhost", "::1"}

    def read_json(self, max_bytes: int = 16_384) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > max_bytes:
            raise ValueError(f"请求内容为空或超过 {max_bytes // 1024} KB。")
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("请求内容必须是有效 JSON。")
        if not isinstance(body, dict):
            raise ValueError("请求内容必须是 JSON 对象。")
        return body

    def do_GET(self):
        if not self.host_allowed():
            return self.send_json(403, {"error": "仅允许本机访问。"})
        path = urlsplit(self.path).path
        if path == "/api/state":
            return self.send_json(200, read_state())
        if path == "/api/config/export":
            with connect() as db:
                config = capture_config(db)
            return self.send_json(200, {**config, "exported_at": now_text(), "application_version": VERSION})
        if path == "/api/health":
            runtime = RUNTIME.info() if RUNTIME else {"running": False, "endpoint": f"{DNS_HOST}:{DNS_PORT}"}
            ok = bool(RUNTIME and runtime.get("running"))
            return self.send_json(200 if ok else 503, {"ok": ok, "version": VERSION, "mode": "local-mvp", "dns_runtime": runtime, "dnsdist_connected": False, "production_nodes_connected": False})
        return super().do_GET()

    def do_POST(self):
        if not self.host_allowed():
            return self.send_json(403, {"error": "仅允许本机访问。"})
        path = urlsplit(self.path).path
        try:
            payload = self.read_json(max_bytes=1_048_576 if path == "/api/config/import" else 16_384)
            if path == "/api/policies":
                return self.create_policy(payload)
            if path == "/api/upstreams":
                return self.save_upstream(payload)
            if path == "/api/preview":
                return self.preview()
            if path == "/api/apply":
                return self.apply_pending()
            if path == "/api/rollback":
                return self.rollback(payload)
            if path == "/api/config/import":
                return self.import_config(payload)
            match = re.fullmatch(r"/api/policies/(\d+)/(enable|disable|delete)", path)
            if match:
                return self.policy_action(int(match.group(1)), match.group(2))
            match = re.fullmatch(r"/api/upstreams/([A-Za-z0-9_.-]+)/delete", path)
            if match:
                return self.delete_upstream(match.group(1))
            return self.send_json(404, {"error": "接口不存在。"})
        except ValueError as exc:
            return self.send_json(400, {"error": str(exc)})
        except sqlite3.IntegrityError:
            return self.send_json(409, {"error": "策略名称已存在。"})

    def do_PUT(self):
        if not self.host_allowed():
            return self.send_json(403, {"error": "仅允许本机访问。"})
        match = re.fullmatch(r"/api/policies/(\d+)", urlsplit(self.path).path)
        if not match:
            return self.send_json(404, {"error": "接口不存在。"})
        try:
            return self.update_policy(int(match.group(1)), self.read_json())
        except ValueError as exc:
            return self.send_json(400, {"error": str(exc)})
        except sqlite3.IntegrityError:
            return self.send_json(409, {"error": "策略名称已存在。"})

    def create_policy(self, payload: dict) -> None:
        policy = normalize_policy(payload)
        if policy["action_type"] == "forward":
            with connect() as db:
                group = db.execute("SELECT servers_json FROM upstream_groups WHERE name=?", (policy["target"],)).fetchone()
            if group is None or not json.loads(group["servers_json"]):
                raise ValueError("该上游组不存在或没有配置 DNS 服务器。")
        stamp = now_text()
        with connect() as db:
            save_revision(db, "新增策略前", stamp)
            cursor = db.execute(
                "INSERT INTO policies(name,domain,network,line,priority,action_type,target,ttl,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (policy["name"], policy["domain"], policy["network"], policy["line"], policy["priority"], policy["action_type"], policy["target"], policy["ttl"], "待发布", stamp),
            )
            policy_id = cursor.lastrowid
            db.execute("INSERT INTO events(message,actor,created_at) VALUES(?,?,?)", (f'新增策略草稿「{policy["name"]}」', "管理员", stamp))
        return self.send_json(201, {"policy": {**policy, "id": policy_id, "match": policy["network"], "ttl_seconds": policy["ttl"], "ttl": f'{policy["ttl"]}s', "status": "待发布", "created_at": stamp}, "state": read_state()})

    def update_policy(self, policy_id: int, payload: dict) -> None:
        policy = normalize_policy(payload)
        stamp = now_text()
        with connect() as db:
            row = db.execute("SELECT status FROM policies WHERE id=?", (policy_id,)).fetchone()
            if row is None:
                return self.send_json(404, {"error": "策略不存在。"})
            if policy["action_type"] == "forward":
                group = db.execute("SELECT servers_json FROM upstream_groups WHERE name=?", (policy["target"],)).fetchone()
                if group is None or not json.loads(group["servers_json"]):
                    raise ValueError("该上游组不存在或没有配置 DNS 服务器。")
            save_revision(db, f"编辑策略前 #{policy_id}", stamp)
            db.execute(
                "UPDATE policies SET name=?,domain=?,network=?,line=?,priority=?,action_type=?,target=?,ttl=? WHERE id=?",
                (policy["name"], policy["domain"], policy["network"], policy["line"], policy["priority"], policy["action_type"], policy["target"], policy["ttl"], policy_id),
            )
            db.execute("INSERT INTO events(message,actor,created_at) VALUES(?,?,?)", (f'编辑策略「{policy["name"]}」', "管理员", stamp))
        return self.send_json(200, {"state": read_state()})

    def save_upstream(self, payload: dict) -> None:
        upstream = normalize_upstream(payload)
        stamp = now_text()
        with connect() as db:
            save_revision(db, ("更新" if db.execute("SELECT 1 FROM upstream_groups WHERE name=?", (upstream["name"],)).fetchone() else "新增") + "上游组前", stamp)
            if upstream["is_default"]:
                db.execute("UPDATE upstream_groups SET is_default=0")
            existing = db.execute("SELECT 1 FROM upstream_groups WHERE name=?", (upstream["name"],)).fetchone()
            db.execute(
                "INSERT INTO upstream_groups(name,servers_json,is_default,created_at,updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET servers_json=excluded.servers_json,is_default=excluded.is_default,updated_at=excluded.updated_at",
                (upstream["name"], json.dumps(upstream["servers"]), int(upstream["is_default"]), stamp, stamp),
            )
            verb = "更新" if existing else "新增"
            db.execute("INSERT INTO events(message,actor,created_at) VALUES(?,?,?)", (f'{verb}上游组「{upstream["name"]}」', "管理员", stamp))
        return self.send_json(200 if existing else 201, {"state": read_state()})

    def delete_upstream(self, name: str) -> None:
        stamp = now_text()
        with connect() as db:
            row = db.execute("SELECT is_default FROM upstream_groups WHERE name=?", (name,)).fetchone()
            if row is None:
                return self.send_json(404, {"error": "上游组不存在。"})
            if row["is_default"]:
                raise ValueError("请先将默认上游切换到其他组，再删除该组。")
            used = db.execute("SELECT COUNT(*) FROM policies WHERE action_type='forward' AND target=?", (name,)).fetchone()[0]
            if used:
                raise ValueError("该上游组仍被解析策略引用，不能删除。")
            save_revision(db, f"删除上游组 {name} 前", stamp)
            db.execute("DELETE FROM upstream_groups WHERE name=?", (name,))
            db.execute("INSERT INTO events(message,actor,created_at) VALUES(?,?,?)", (f'删除上游组「{name}」', "管理员", stamp))
        return self.send_json(200, {"state": read_state()})

    def policy_action(self, policy_id: int, action: str) -> None:
        stamp = now_text()
        with connect() as db:
            row = db.execute("SELECT * FROM policies WHERE id=?", (policy_id,)).fetchone()
            if row is None:
                return self.send_json(404, {"error": "策略不存在。"})
            if action == "delete":
                if row["status"] == "启用":
                    raise ValueError("请先停用策略，再删除。")
                save_revision(db, f"删除策略 #{policy_id} 前", stamp)
                db.execute("DELETE FROM policies WHERE id=?", (policy_id,))
                message = f'删除策略「{row["name"]}」'
            else:
                status = "启用" if action == "enable" else "停用"
                if status == "启用" and row["action_type"] == "forward":
                    group = db.execute("SELECT servers_json FROM upstream_groups WHERE name=?", (row["target"],)).fetchone()
                    if group is None or not json.loads(group["servers_json"]):
                        raise ValueError("该策略引用的上游组未配置 DNS 服务器。")
                if row["status"] == status:
                    return self.send_json(200, {"state": read_state()})
                save_revision(db, f"{status}策略 #{policy_id} 前", stamp)
                db.execute("UPDATE policies SET status=? WHERE id=?", (status, policy_id))
                message = f'将策略「{row["name"]}」设为{status}'
            db.execute("INSERT INTO events(message,actor,created_at) VALUES(?,?,?)", (message, "管理员", stamp))
        return self.send_json(200, {"state": read_state()})

    def preview(self) -> None:
        artifact = build_artifact()
        pending = [policy for policy in artifact["policies"] if policy["status"] == "待发布"]
        with connect() as db:
            db.execute("INSERT INTO events(message,actor,created_at) VALUES(?,?,?)", (f"生成配置预览，包含 {len(pending)} 条待发布策略", "管理员", now_text()))
        engine_preview = compile_fragment(artifact)
        lab_config_preview = compile_lab_config(artifact)
        return self.send_json(200, {"passed": True, "pending_count": len(pending), "policies": pending, "artifact": artifact, "engine_preview": engine_preview, "dnsdist_lab_preview": lab_config_preview, "dnsdist_connected": False, "production_nodes_connected": False})

    def apply_pending(self) -> None:
        stamp = now_text()
        with connect() as db:
            pending = db.execute("SELECT * FROM policies WHERE status='待发布' ORDER BY id").fetchall()
            for row in pending:
                if row["action_type"] == "forward":
                    group = db.execute("SELECT servers_json FROM upstream_groups WHERE name=?", (row["target"],)).fetchone()
                    if group is None or not json.loads(group["servers_json"]):
                        raise ValueError(f"策略「{row['name']}」引用的上游组不可用。")
            if pending:
                save_revision(db, "本地 DNS 应用前", stamp)
                db.execute("UPDATE policies SET status='启用' WHERE status='待发布'")
            db.execute("INSERT INTO events(message,actor,created_at) VALUES(?,?,?)", (f"应用 {len(pending)} 条待发布策略到本机 DNS", "管理员", stamp))
        return self.send_json(200, {"state": read_state(), "applied_count": len(pending), "production_nodes_connected": False})

    def rollback(self, payload: dict) -> None:
        try:
            revision_id = int(payload.get("revision_id", 0))
        except (TypeError, ValueError):
            raise ValueError("快照 ID 必须是正整数。")
        if revision_id < 1:
            raise ValueError("请选择一个可用快照。")
        stamp = now_text()
        with connect() as db:
            revision = db.execute("SELECT config_json FROM revisions WHERE id=?", (revision_id,)).fetchone()
            if revision is None:
                return self.send_json(404, {"error": "快照不存在。"})
            config = normalize_config(json.loads(revision["config_json"]))
            save_revision(db, f"回滚至快照 #{revision_id} 前", stamp)
            restore_config(db, config)
            db.execute("INSERT INTO events(message,actor,created_at) VALUES(?,?,?)", (f"已回滚至配置快照 #{revision_id}", "管理员", stamp))
        return self.send_json(200, {"state": read_state(), "restored_revision": revision_id})

    def import_config(self, payload: dict) -> None:
        config = normalize_config(payload.get("config", payload))
        stamp = now_text()
        with connect() as db:
            save_revision(db, "导入配置前", stamp)
            restore_config(db, config)
            db.execute("INSERT INTO events(message,actor,created_at) VALUES(?,?,?)", (f"导入配置：{len(config['policies'])} 条策略、{len(config['upstream_groups'])} 个上游组", "管理员", stamp))
        return self.send_json(200, {"state": read_state(), "imported_policies": len(config["policies"]), "imported_upstreams": len(config["upstream_groups"])})


def main() -> None:
    global RUNTIME
    init_db()
    server = ThreadingHTTPServer((API_HOST, PORT), Handler)
    from dns_runtime import DnsRuntime
    try:
        RUNTIME = DnsRuntime(DB_PATH, DNS_HOST, DNS_PORT)
        RUNTIME.start()
    except Exception:
        server.server_close()
        raise
    print(f"域衡 DNS MVP 控制台：http://127.0.0.1:{PORT}")
    print(f"DNS 查询入口：{DNS_HOST}:{DNS_PORT}（UDP/TCP）")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("MVP 服务已停止。")
    finally:
        server.server_close()
        if RUNTIME:
            RUNTIME.stop()
            RUNTIME = None


if __name__ == "__main__":
    main()
