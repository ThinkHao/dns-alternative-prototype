# 域衡 DNS 替代品原型

当前交付：**0.3 跨平台本机版**。控制台、本机 API 和实验用 DNS 转发服务可在 Windows、macOS、Linux 原生运行，也可通过 Docker Compose 部署。默认只绑定回环地址，不连接生产设备。

## 本机运行

需要 Python 3.11 或更高版本。

Windows PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\run.ps1
```

macOS / Linux：

```sh
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
sh ./run.sh
```

打开 `http://127.0.0.1:8765`。默认控制台 API 监听 `127.0.0.1:8765`，DNS 查询监听 `127.0.0.1:15300` 的 UDP 和 TCP。按 `Ctrl+C` 停止。原生运行可用 `DNS_ALT_API_PORT`、`DNS_ALT_DNS_HOST` 和 `DNS_ALT_DNS_PORT` 配置端口与 DNS 监听地址；管理 API 保持回环绑定。DNS 运行端口保留为 1024–65535。

## Docker Compose 部署

Windows、macOS 安装 Docker Desktop，Linux 安装 Docker Engine 与 Compose 插件后，在本目录执行：

```sh
docker compose up --build -d
docker compose logs -f
```

打开 `http://127.0.0.1:8765`。SQLite 数据保存在 Docker named volume `dns-data` 中，容器以非 root 用户运行。默认 API 和 DNS 端口仅发布到本机回环地址。停止服务使用 `docker compose down`；该命令保留数据库。需要清空数据库时再单独删除 `dns-data` volume。

如需让局域网客户端访问 DNS 服务，可将 `.env.example` 复制为 `.env`，把 `DNS_ALT_BIND_ADDRESS` 改成 `0.0.0.0`，并按需把 `DNS_ALT_HOST_DNS_PORT` 改为 `53`。API 的宿主机端口仍绑定本机回环地址；当前没有登录认证，不应将管理页面发布到局域网或公网。

也可以直接打开 `index.html` 查看静态样例界面，但该方式不启用 API，操作只保留在当前页面会话。

## 已实现

- 总览、解析策略、权威域名、节点集群、查询日志、变更记录六个工作区。
- 新建、启用、停用和删除解析策略；本机 API 校验域名、IPv4 CIDR、线路、动作类型、优先级和 TTL，并存入 SQLite。
- 管理 1–8 个 IPv4 DNS 上游服务器组成的上游组；可选一个默认回退组。没有配置的组不会被自动指向公共 DNS。
- 策略动作明确区分固定 A 记录和转发到上游组。
- 本机 DNS 服务支持 UDP/TCP：按客户端 IPv4 CIDR、精确域名/通配后缀和优先级匹配策略；固定 A 应答，其余查询转发到命中上游组或默认回退组。
- 上游服务器按配置顺序轮询起始点，查询失败时尝试组内其他服务器；上游返回截断响应时使用 dnspython 的 TCP 回退。
- 实际 DNS 查询写入 SQLite，控制台可刷新查看最近 200 条记录，运行时最多保留 2000 条。
- 策略支持 0–10000 的优先级，数值越大越先匹配；同优先级按客户端网段更精确、域名精确匹配、域名长度和 ID 确定顺序。
- 配置预览输出版本化 `dns-policy/v1` JSON、dnsdist Lua 规则片段，以及可下载的本机 PoC 完整配置草稿。
- 模拟发布和审计事件只更新本地原型数据库。
- 策略与日志的页面内搜索。
- 集群指标、节点和区域记录均为样例数据；直接打开静态页面时日志也是样例，API 模式下查询日志来自本机 DNS 运行时。

## 尚未实现

- 权威区域托管、完整递归解析器和 DNSSEC 验证；本机服务仅是转发型策略 DNS。
- 多用户认证、细粒度权限和外部审计服务。
- 与 DNS 节点通信、健康探测、配置下发、回读和回滚。
- dnsdist Lua 配置语法检查、dnsdist 运行时查询验证和后端池健康切换。
- 查询日志导出、统计报表与可配置留存周期。
- DNSSEC、AXFR/IXFR、IPv6、ECS、DoT/DoH 等协议能力的实现与验证。
- 威胁情报接入、授权校验和恶意域名处置。

**原生启动默认监听 `127.0.0.1:8765` 控制台 API 和 `127.0.0.1:15300` DNS 高位端口；Docker 部署默认也只发布到本机。程序不修改系统 DNS 设置，不会连接或发布到 DNS 设备。界面里的集群 QPS、节点和区域指标仍是样例数据；只有 DNS 查询日志和运行端点来自本机服务。**

原生启动时，SQLite 文件写入工作区的 `work/dns-alternative-prototype.sqlite3`，不放进交付目录。Docker Compose 启动时，数据库保存在 `dns-data` named volume。删除对应数据库文件或 volume 会清除策略草稿和模拟审计记录。

## 控制面原则

1. 控制面保存结构化的期望配置；运行节点保留最近一次校验通过的配置。
2. 节点运行状态是观测值。发现期望配置和运行配置不一致时报告差异，不静默覆盖。
3. 发布链路固定为：生成配置 → 静态校验 → 展示差异 → 预发布 → 查询与健康检查 → 正式发布 → 回读确认。
4. DNS 查询路径不依赖控制面持续在线。管理服务故障时，解析节点继续提供最近有效配置。
5. 引擎通过适配器接入；先用目标流量、策略和完整日志做选型压测，再锁定引擎与硬件。

当前本机接口：`GET /api/state`、`GET /api/health`、`POST /api/policies`、`POST /api/policies/{id}/enable|disable|delete`、`POST /api/upstreams`、`POST /api/upstreams/{name}/delete`、`POST /api/preview`、`POST /api/simulate-publish`。策略启用/停用会直接影响本机 DNS 运行时；“模拟发布”仍仅写入本机版本记录，不代表 dnsdist 配置已下发。

dnsdist 规则只实现客户端 IPv4 网段 + 精确域名/通配后缀的匹配、上游池选择和固定 A 应答。完整配置草稿将 listener 固定为 `127.0.0.1:5300`，上游占位地址只使用 `127.0.0.1` 的高位端口；这些端口没有 Recursor 后端，配置不能处理实际查询，也不得作为生产配置使用。线路字段目前只作为元数据，不会改变服务器物理出口。固定 A 应答仅匹配 A 查询，其他类型继续走后续规则。生成的 Lua 规则依据 dnsdist 1.9 及以上提供的 `QNameSuffixRule` 字符串接口；当前环境没有 dnsdist，所以尚未通过 `dnsdist --check-config`。

## 验证

Windows PowerShell 可运行 `.\.venv\Scripts\python.exe verify_mvp.py`。
macOS / Linux 可运行 `./.venv/bin/python verify_mvp.py`。

脚本临时启动控制 API、本机 DNS 运行时和 mock DNS 上游，不连接公网 DNS，结束后自动清理临时数据库。

已验证固定 A 的 UDP/TCP 回答、通配后缀上游转发、后缀根域排除、默认组回退、AAAA 回退、查询日志和完整 dnsdist 配置草稿生成。
Windows 本机、WSL Ubuntu 与 Docker Compose 容器均已启动服务，验证 API、UDP/TCP 查询和日志；容器重启后策略与查询日志仍保留。macOS 实机尚未验证。

dnsdist 2.1.3 已在 Ubuntu 24.04 WSL 通过生成配置语法检查，并以 mock 上游验证固定 A、命名池转发、默认池回退的 UDP/TCP 查询。该检查不包含真实 Recursor、故障切换、QPS、延迟或日志性能；Python DNS 运行时也不能替代生产级递归引擎。

## GitHub Actions

工作流位于 `.github/workflows/platform-ci.yml`：每次 push、pull request 或手动触发时，在 Ubuntu、macOS、Windows 上分别用 Python 3.11 和 3.13 运行 DNS 端到端检查；另构建 Compose 镜像，并在 Ubuntu 24.04 安装 PowerDNS dnsdist 2.1 执行配置与 UDP/TCP 查询冒烟。

## 下一阶段

引擎选型的临时假设与隔离 PoC 验收门记录在 [ENGINE-POC.md](ENGINE-POC.md)：下一步是在隔离环境接入真实 PowerDNS Recursor，再与 CoreDNS 做同流量对照。策略 JSON 已将固定应答与上游转发区分开；生成的本机完整配置草稿已由 dnsdist 2.1.3 做语法与 mock 查询验证，但仍不能用于生产。

同时收集现网脱敏配置、峰值流量与验收口径，形成可复现的基准。至少需要确定：

- 权威域与递归业务范围，以及是否要支持 IPv6、DNSSEC、ECS、DoT/DoH。
- 客户端网段如何映射到出口线路，现网是否有可用的链路健康/负载接口。
- 忙时峰值 QPS、延迟目标、全量日志保留时间和查询范围。
- 节点操作系统/CPU 限制、网卡要求、主备或多活方式。
- 恶意域名情报来源及许可范围。

## 公开产品资料

- [网瑞达智能 DNS 产品页](https://www.wrdtech.com/content/content.php?p=2_30_204)
- [DNS 流量调度方案](https://www.wrdtech.com/content/content.php?p=6_28_287)
- [产品停售与服务时间公告](https://www.wrdtech.com/content/content.php?p=56_27_289)
