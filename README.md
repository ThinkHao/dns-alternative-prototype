# 域衡 DNS 替代品

当前版本：**0.4.0**。这是一个可独立部署的单机 DNS 转发与策略服务，包含本机管理控制台、SQLite 配置库、UDP/TCP DNS 运行时、策略校验/应用、配置备份恢复和容器发布工件。

## 功能范围

- 按客户端 IPv4 CIDR、域名精确匹配或通配后缀、优先级匹配策略。
- 固定 A 应答，或转发到可配置的 IPv4 DNS 上游组；支持默认回退组与多上游故障重试。
- DNS 使用 UDP/TCP；日志保留最近 2000 条，界面显示最近 200 条。
- 策略支持新增、编辑、启停、删除和待发布策略校验后应用到本机 DNS。
- 策略/上游组变更前自动保存配置快照，可回滚；控制台可导入/导出 JSON 配置备份。
- 默认空配置启动，不预置示例 A 记录或公共 DNS 上游。
- API/控制台仅绑定宿主机回环地址；DNS 也默认只监听本机高位端口。
- GitHub Actions 覆盖 Windows、macOS、Linux 和 dnsdist/Recursor 集成验证；版本 tag 构建 amd64/arm64 GHCR 镜像并创建 GitHub Release。

本版本是**单机递归转发 DNS 替代品**。权威区托管、DNSSEC、IPv6 客户端策略、DoT/DoH、多节点配置下发、用户认证和外部审计未实现。界面上的节点、QPS 趋势与权威区目录是明确标注的静态样例，不能作为设备运行状态依据。

## Docker Compose 部署

在 Linux 主机安装 Docker Engine 和 Compose 插件后：

```sh
git clone https://github.com/ThinkHao/dns-alternative-prototype.git
cd dns-alternative-prototype
cp .env.example .env
```

编辑 `.env`，至少设置发布版本。要作为局域网 DNS 使用时，再设置 DNS 监听地址和宿主机端口：

```dotenv
DNS_ALT_VERSION=v0.4.0
DNS_ALT_API_PORT=8765
DNS_ALT_BIND_ADDRESS=0.0.0.0
DNS_ALT_HOST_DNS_PORT=53
```

拉取并启动发布镜像：

```sh
docker compose --env-file .env -f compose.release.yml up -d
```

此时管理页面仍只在部署主机访问：`http://127.0.0.1:8765`。API 未实现登录认证，保持回环绑定；不要改成局域网或公网可访问。DNS 监听 `0.0.0.0:53` 后，需在主机防火墙限制允许的客户端网段。若只是本机试用，可保留示例的 `127.0.0.1:15300`。

首次使用请在“上游组”配置 DNS 服务器，并设为默认回退组；空配置没有默认上游时，未命中的查询会返回 `SERVFAIL`。然后新增策略，预览并应用待发布策略。固定 A 策略经编辑或启停后立即影响本机 DNS。

健康状态：

```sh
curl -fsS http://127.0.0.1:8765/api/health
docker compose -f compose.release.yml ps
```

SQLite 位于持久卷 `dns-data`。`docker compose down` 不会删除数据；不要执行 `docker compose down -v`，除非明确要销毁配置与日志。

### 升级与回退

升级时先在控制台导出配置备份，再指定新版本并拉取：

```sh
# 修改 .env 中 DNS_ALT_VERSION，例如改为 v0.4.1
docker compose --env-file .env -f compose.release.yml pull
docker compose --env-file .env -f compose.release.yml up -d
```

如需回退程序版本，把 `DNS_ALT_VERSION` 改回原 tag，再执行相同的 `pull` 和 `up -d`。如果同时要恢复 DNS 配置，在控制台导入之前导出的 JSON 备份；导入前会自动保存当前快照。数据库卷与配置备份分开管理，建议把配置备份放到部署主机以外的受控位置。

### 从源码本机构建

开发或离线部署可用仓库自带的 `docker-compose.yml` 构建源码：

```sh
docker compose up --build -d
```

默认仅本机监听。`.env` 里的端口变量可调整 DNS 宿主机映射；DNS 容器内端口固定为 15300。

## Windows / macOS 原生运行

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

控制台为 `http://127.0.0.1:8765`，DNS 默认监听 `127.0.0.1:15300` 的 UDP/TCP。原生运行的 SQLite 默认保存在仓库父目录下的 `work/dns-alternative-prototype.sqlite3`。可用 `DNS_ALT_API_PORT`、`DNS_ALT_DNS_HOST`、`DNS_ALT_DNS_PORT` 和 `DNS_ALT_DB_PATH` 配置；原生 DNS 端口保持在 1024–65535。

## 配置接口

管理 API 只接受本机 Host：

- `GET /api/state`：策略、上游、日志、审计和最近快照。
- `GET /api/health`：API 与 DNS 运行时状态；DNS 未启动时返回 HTTP 503。
- `GET /api/config/export`、`POST /api/config/import`：导出/导入 `dns-local-config/v1` 配置。
- `POST /api/policies`、`PUT /api/policies/{id}`：新增或编辑策略。
- `POST /api/policies/{id}/enable|disable|delete`：启停或删除策略。
- `POST /api/upstreams`、`POST /api/upstreams/{name}/delete`：维护上游组。
- `POST /api/preview`：结构校验、JSON 与 dnsdist 配置预览。
- `POST /api/apply`：校验并把待发布策略应用到本机 DNS。
- `POST /api/rollback`：恢复指定快照，提交 `{ "revision_id": 1 }`。

**边界：** `/api/apply` 仅更新本机 SQLite 运行配置；不会向其他服务器或 dnsdist 进程下发配置。管理接口无认证，Docker Compose 对宿主机仅映射到 `127.0.0.1`。

## 验证和发布

本机端到端检查（会启动临时 loopback DNS 和 mock 上游，不访问公网 DNS）：

```sh
python -m pip install -r requirements.txt
python verify_mvp.py
```

dnsdist/PowerDNS Recursor 引擎隔离验证由 `verify_dnsdist.py --recursor pdns_recursor` 执行。GitHub Actions 的 `platform-ci.yml` 在 Windows/macOS/Linux 的 Python 3.11 和 3.13 矩阵运行端到端检查，并构建 Compose 镜像、验证 dnsdist/Recursor 实际查询及后端故障恢复。

发布时更新 `VERSION`，提交后创建同名 tag（例如 `v0.4.1`）。`release.yml` 检查 tag 与 `VERSION` 一致，构建并推送 `linux/amd64`、`linux/arm64` 镜像到 GHCR，再创建 GitHub Release。首次发布后需在 GitHub Packages 将镜像包设为 Public，才能让未登录部署主机匿名拉取；公开仓库本身不会自动让容器包公开。

## 产品参考

- [网瑞达智能 DNS 产品页](https://www.wrdtech.com/content/content.php?p=2_30_204)
- [DNS 流量调度方案](https://www.wrdtech.com/content/content.php?p=6_28_287)
- [产品停售与服务时间公告](https://www.wrdtech.com/content/content.php?p=56_27_289)
