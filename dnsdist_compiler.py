"""Compile dns-policy/v1 into a review-only dnsdist Lua rule fragment."""

from __future__ import annotations

import json
import ipaddress
import re


ACTIVE_STATUSES = {"启用", "待发布", "模拟发布"}


def lua_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def compile_fragment(artifact: dict) -> dict:
    if artifact.get("schema_version") != "dns-policy/v1":
        raise ValueError("不支持的策略配置版本。")
    rules = []
    skipped = []
    pools = set()
    for policy in artifact.get("policies", []):
        status = policy.get("status")
        if status not in ACTIVE_STATUSES:
            skipped.append(policy.get("name", "未命名策略"))
            continue
        match = policy.get("match") or {}
        decision = policy.get("decision") or {}
        cidr = str(match.get("client_cidr", ""))
        domain = str(match.get("domain", ""))
        domain_mode = match.get("domain_mode")
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise ValueError(f"策略「{policy.get('name', '')}」的客户端网段无效。")
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError(f"策略「{policy.get('name', '')}」的客户端网段目前仅支持 IPv4。")
        if not domain or domain_mode not in {"exact", "suffix"}:
            raise ValueError(f"策略「{policy.get('name', '')}」的域名匹配条件无效。")
        try:
            priority = int(policy.get("priority", 100))
            ttl = int(policy.get("ttl_seconds", 0))
        except (TypeError, ValueError):
            raise ValueError(f"策略「{policy.get('name', '')}」的优先级或 TTL 无效。")
        if priority < 0 or priority > 10000 or ttl < 1 or ttl > 86400:
            raise ValueError(f"策略「{policy.get('name', '')}」的优先级或 TTL 超出范围。")

        qname = domain.removeprefix("*.").rstrip(".") + "."
        selectors = [f"NetmaskGroupRule({lua_string(cidr)})"]
        if domain_mode == "exact":
            selectors.append(f"QNameRule({lua_string(qname)})")
        else:
            # Wildcard-style suffix policies exclude the suffix apex itself.
            selectors.extend([
                f"QNameSuffixRule({lua_string(qname)})",
                f"NotRule(QNameRule({lua_string(qname)}))",
            ])

        action_type = decision.get("type")
        if action_type == "forward_group":
            group = str(decision.get("group", ""))
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", group):
                raise ValueError(f"策略「{policy.get('name', '')}」引用了无效的上游组名称。")
            pools.add(group)
            action = f"PoolAction({lua_string(group)})"
        elif action_type == "return_a":
            address = str(decision.get("address", ""))
            try:
                address = str(ipaddress.IPv4Address(address))
            except ValueError:
                raise ValueError(f"策略「{policy.get('name', '')}」的 A 记录地址无效。")
            selectors.append("QTypeRule(DNSQType.A)")
            action = f"SpoofAction({lua_string(address)}, {{ttl={ttl}}})"
        else:
            raise ValueError(f"策略「{policy.get('name', '')}」包含当前编译器不支持的动作。")

        rules.append({
            "priority": priority,
            "network_prefix": network.prefixlen,
            "domain_specificity": (1 if domain_mode == "exact" else 0, len(qname)),
            "id": int(policy.get("id", 0) or 0),
            "name": str(policy.get("name", "")),
            "line": str(policy.get("egress_line", "")),
            "statement": f"addAction(AndRule({{{', '.join(selectors)}}}), {action})",
        })

    rules.sort(key=lambda rule: (-rule["priority"], -rule["network_prefix"], -rule["domain_specificity"][0], -rule["domain_specificity"][1], rule["id"], rule["name"]))
    lines = [
        "-- Generated policy fragment for dnsdist; review before loading.",
        "-- This is not a complete dnsdist.conf and does not configure listeners or servers.",
        "-- Define every referenced backend pool with newServer(..., pool=...) separately.",
        "-- Rules run by priority descending; equal priorities use deterministic name/id order.",
    ]
    if pools:
        lines.append("-- Required pools: " + ", ".join(lua_string(pool) for pool in sorted(pools)))
    for rule in rules:
        lines.append(f"-- Policy {rule['id']} priority={rule['priority']}; egress_line={rule['line']}")
        lines.append(rule["statement"])

    warnings = [
        "当前输出仅为规则片段，未通过目标 dnsdist 版本的配置语法检查，不可直接加载。",
        "上游组必须先在完整 dnsdist 配置中定义并绑定后端服务器。",
        "egress_line 当前只保留为策略元数据；本片段不会配置物理出口或路由。",
        "固定 A 动作只匹配 A 查询；AAAA 和其他类型继续走后续默认规则。",
    ]
    if skipped:
        warnings.append("已排除未启用/待复核策略：" + "、".join(skipped))
    return {
        "target": "dnsdist Lua rules",
        "complete_config": False,
        "runnable": False,
        "rule_count": len(rules),
        "required_pools": sorted(pools),
        "warnings": warnings,
        "config": "\n".join(lines) + "\n",
    }


def compile_lab_config(artifact: dict) -> dict:
    """Wrap the review fragment in a localhost-only config for config-check use."""
    fragment = compile_fragment(artifact)
    default_backend_port = 5399
    first_pool_port = 5301
    if first_pool_port + len(fragment["required_pools"]) > default_backend_port:
        raise ValueError("PoC 上游组数量超过本机测试端口范围。")

    lines = [
        "-- Local-only dnsdist PoC config; backend ports are placeholders.",
        "-- Intended for dnsdist --check-config, not production use.",
        'setLocal("127.0.0.1:5300")',
        'setACL({"127.0.0.0/8"})',
        f'newServer({{address="127.0.0.1:{default_backend_port}"}}) -- default pool placeholder',
    ]
    for index, pool in enumerate(fragment["required_pools"]):
        port = first_pool_port + index
        lines.append(f'newServer({{address="127.0.0.1:{port}", pool={lua_string(pool)}}})')
    lines.extend(["", fragment["config"].rstrip(), ""])

    warnings = list(fragment["warnings"])
    warnings.extend([
        "完整配置中的 listener 固定为 127.0.0.1:5300，所有后端仅指向 127.0.0.1 高位测试端口。",
        "本机没有 dnsdist 运行时和 Recursor 后端；当前只生成配置草稿，不能接收 DNS 查询。",
        "实际运行前需确认 listener 与后端占位端口未被其他本机服务占用。",
    ])
    return {
        "target": "local-only dnsdist PoC config",
        "complete_config": True,
        "runnable": False,
        "listener": "127.0.0.1:5300",
        "backend_placeholders": {"default": f"127.0.0.1:{default_backend_port}", **{
            pool: f"127.0.0.1:{first_pool_port + index}"
            for index, pool in enumerate(fragment["required_pools"])
        }},
        "warnings": warnings,
        "config": "\n".join(lines),
    }
