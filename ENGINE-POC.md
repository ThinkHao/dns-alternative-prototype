# DNS 数据面选型验证记录（临时决策）

日期：2026-11-25
状态：**PowerDNS dnsdist 2.1.3 + Recursor 5.4.9 已通过本机合成权威区路径验证；尚未接入真实递归上游或做性能验证**

## 目前建议验证的组合

**dnsdist + PowerDNS Recursor** 作为递归策略 PoC 的首选：dnsdist 接收客户端请求，按客户端源网段和查询域名选择后端池；每个池再指向相应的 Recursor 集群。PowerDNS Authoritative 单独承担权威区域服务与区域 API 管理，不放进递归上游池。

选择依据：

- dnsdist 官方规则提供 `NetmaskGroupRule`、`QNameRule`、`QNameSuffixRule` 和组合规则；动作提供 `PoolAction`、`SpoofAction`，可以直接承载本原型当前的网段/域名匹配、池转发和固定 A 应答。[规则选择器](https://www.dnsdist.org/reference/selectors.html) [规则动作](https://www.dnsdist.org/reference/actions.html) [服务器池](https://www.dnsdist.org/guides/serverpools.html)
- `QNameSuffixRule` 自 dnsdist 1.9 起可直接接收字符串；因此原型当前生成的规则片段要求目标环境使用 1.9 或更新版本，并须在隔离 PoC 中确认实际加载语法。[官方选择器说明](https://www.dnsdist.org/reference/selectors.html)
- Recursor 提供 Lua 查询钩子，适合定制查询处理；但按请求源网段和域名将流量送入命名上游池，dnsdist 已有更直接的 selector/action 映射。此处是基于官方接口形态的工程判断，不代表已验证性能或完整功能覆盖。[Recursor Lua 钩子](https://doc.powerdns.com/recursor/lua-scripting/hooks.html)
- Authoritative 提供 JSON/REST API 与 OpenAPI 描述，可独立作为权威区管理候选。[API 文档](https://doc.powerdns.com/authoritative/http-api/index.html)

## 原型编译器当前范围

```text
dns-policy/v1
  └─ dnsdist Lua 规则片段
       ├─ 客户端 IPv4 CIDR
       ├─ 精确域名 / 不含根域的通配后缀
       ├─ PoolAction(上游池)
       └─ A 查询 SpoofAction(IPv4, TTL)
```

规则顺序先按显式优先级降序；同优先级再按网段前缀长度、精确域名、后缀长度、策略 ID 确定。预览会将规则包进一份本机 PoC 配置草稿：listener 和后端仅使用 `127.0.0.1`。`verify_dnsdist.py` 在 Ubuntu 24.04 WSL 使用 PowerDNS dnsdist 2.1.3 完成 `--check-config`，并可选启动两个 Recursor 5.4.9 实例，各自加载本地合成权威区，以 UDP/TCP 验证固定 A、命名池后缀转发和默认池回退。它验证引擎配置与路由路径，不访问公网 DNS，不等同真实递归上游集群或高可用验证，也不能将配置用于生产。策略中的“出口线路”仍是元数据，必须后续映射为真实服务器池和网络路由方案。

```text
客户端
  └─> dnsdist 策略入口
       ├─ campus-upstream ─> Recursor 集群 A
       ├─ telecom-upstream ─> Recursor 集群 B
       └─ auth 服务（独立入口/转发路径） ─> Authoritative 集群

管理控制面 ─> 期望配置、编译、预览、审批、发布、回读
观测链路 ───> 查询日志、指标、节点健康与审计
```

控制面不在逐次 DNS 查询时访问数据库或远程 API。dnsdist/Recursor 应使用本地已加载配置；控制面中断不能导致查询路径依赖失效。

## 已知边界

1. 目前只支持 IPv4 客户端 CIDR 和 A 记录固定回答；AAAA、ECS、DoT/DoH、DNSSEC、NXDOMAIN 处置均未纳入该编译器。
2. 上游组必须在完整 dnsdist 配置中声明，并绑定真实 Recursor 服务器；当前原型不会验证池存在或健康。
3. 固定 A 规则只匹配 A 查询，其他类型走后续规则；策略优先级与默认回退规则的关系要在完整配置中定义。
4. “出口线路”字段不等于物理出口选择。若要求按运营商真实出接口转发，还需明确节点多网卡、源地址绑定、策略路由和回程路由设计。
5. PowerDNS Authoritative API 含敏感运行信息；部署时要设置 API 密钥、监听范围与访问控制，不能将管理 API 暴露到不受信任网段。[API 安全说明](https://doc.powerdns.com/authoritative/http-api/index.html)
6. 未确定全量日志的采集、留存和查询方案，也未验证日志开销与目标 QPS 的组合性能。

## 隔离 PoC 验收门

- 在非生产 VM/容器网段以非特权端口运行；不修改现网 DNS 转发器、设备配置或 53 端口绑定。
- 建立至少两个客户端网段、两个 dnsdist 后端池、两个 Recursor 实例和一个权威样例区。
- 验证精确域名、后缀域名、后缀根域排除、策略优先级、未命中回退、A/AAAA、NXDOMAIN 与上游超时回退。
- 逐次增加规则数、QPS、缓存未命中比例和日志量；记录 P95/P99 延迟、丢包、CPU、内存、规则加载时间和日志缺口。
- 在坏配置、后端失联、控制面停止及上游不可用时，验证现有有效配置仍工作，并可按版本回退。
- 以现网忙时峰值和日志保留需求设定性能门槛；产品宣传数据只作参考，不作为验收结果。

## 下一阶段

1. 已在本机 dnsdist 2.1.3 + Recursor 5.4.9 完成 loopback-only 配置语法和查询验证；GitHub Actions 将持续执行该集成检查。
2. 在隔离网段接入真实递归上游集群，验证查询命中、未命中、超时与健康切换。
3. 定义完整的生产 listener、后端池和健康检查配置，再实现“线路/上游组”到池的明确映射。
4. 用相同规则集与流量基准对照 CoreDNS 或其他候选，确认功能覆盖、性能和运维复杂度后再决定架构。

本机 MVP 另含一个 Python 转发运行时，用于验证策略启停、固定 A、上游组、UDP/TCP 与查询日志的行为。它只绑定回环高位端口，不具备生产级性能或完整递归功能；目标部署仍需在隔离 Linux 环境验证 dnsdist 与 Recursor。
