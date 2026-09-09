# 开发与验证

本仓是独立 Rust workspace。需要 Rust 1.96.0（rustfmt、clippy）、Python 3.11+、Docker 和 cargo-deny 0.19.9。使用 `/usr/bin/git`，RSS 仓库需要读取权限。

```sh
cargo install cargo-deny --version 0.19.9 --locked
make ci
```

`make check` 执行 locked 编译、fmt、clippy；`make test` 为无 provider 的测试；`make test-pg` 与 `make test-oidc` 启动真实容器并显式运行 ignored 集成测试。Docker 不可用直接失败。容器只绑定 loopback，采用临时名称和运行后清理，不使用开发者数据库；测试账号和明文 HTTP 只属于这些隔离 fixture。

`make dependencies` 通过完整 Cargo metadata 检查 RSS 解析闭包：同一 Git URL、完整 SHA、无双来源/外部 path/patch，打印六个基础包版本；按 package ID 核对 metadata 测试 feature 精确集合，并从 `cargo check --workspace --lib --message-format=json` 的实际 compiler-artifact 按 package ID 单独核对生产集合。固定 revision 和独立 Cargo.lock 是构建身份，RSS checkout 内部的包间 path 仍属于该 Git 来源。无需等待 registry 发布。`make licenses` 检查安全公告、第三方许可证与来源；RSS 六包在固定基线缺少 license 字段，会显示警告，目前只作自有私有源码消费，不能据此宣称有对外再分发许可。

`azure-pipelines.yml` 调用同一 `make ci`。Azure job token 仅在 `cargo fetch --locked` 的进程环境 Git 配置中读取 RSS，不写入 checkout 或命令参数；随后清除 job token 与全部运行时 `GIT_CONFIG_*`，以 `CARGO_NET_OFFLINE=true` 构建和测试；流水线身份必须有 RSS 仓库 Read 权限。Azure Repos PR validation 需要分支 build policy，提交 YAML 本身不代表已注册或已运行托管流水线。

## 实际实现与证明范围

- `rss-identity-core` 持有账户、会话与下游协议策略；真实账户/member/session/source 判定归 PG authority，client 只在完成在线验证后返回可信上下文。旧绑定快照骨架已删除。
- `rss-identity-postgres` 注入 RSS PgRuntime，具体账户操作与关闭的安全事件在同一事务提交；不再开放 I02 的任意 SQL/字节事件探针。明确保留回滚、回滚失败、提交不确定及 fencing。
- `rss-identity-oidc` 通过 openidconnect 完成 discovery、Authorization Code + PKCE、state/nonce/ID token 校验，返回经过验证的上游 claims；I05 的 Federation 用例执行持久登录事务/JIT/关联及中央会话原子结算。出站由部署批准的 issuer origin/地址范围约束，DNS 解析后再次检查，禁隐式环境代理；后续端点保持 issuer 同源、禁止重定向、5 秒超时和 1 MiB 响应上限。生产配置必须 HTTPS，`test-support` 仅开放显式 loopback fixture 构造器。

真实 PG 测试覆盖正常提交、SQL 失败回滚、CommitUnknownAfterAck、重复事件、跨租户 RLS 与 outbox 绑定。真实 Keycloak 上游与 Hydra 下游测试覆盖发现、code exchange、S256、重放、错误 state/nonce/verifier/redirect 及 provider 不可用。补充签名 token 的 azp/issuer/audience/expiry 负例、外源 discovery/JWKS、禁止跳转、响应上限和容器清理失败测试。Hydra 下游测试运行真实 Identity bridge，见[下游接入](downstream.md)。

固定容器版本与摘要的单源为 `hack/providers.py`：PostgreSQL 17.6、Keycloak 26.7.3、Hydra v26.2.0。首次执行会拉取镜像。此测试不证明生产 TLS、持久化 Hydra、Keycloak 升级、生产恢复流程或 MDM 接入；这些由 #2333–#2343 各自验收。在线身份验证已由 I06 router/client 提供，尚无可启动产品 binary。

## 独立消费复核

在 RSS 目录之外检出本仓并运行 `make dependencies check test`，使用独立 target；本仓 `.cargo/config.toml` 与 `clippy.toml` 固定配置边界。不得以父仓编译成功代替此验证。实际交付结果记录在 PR，构建输出中的 RSS source 必须是 Cargo Git URL + 完整 revision。

## 门禁与已接受风险

Provider runner 先枚举 canonical ignored 测试集合，再核对完整执行名及 passed/failed/ignored/filtered 计数；
零测试或部分执行直接失败。Hydra 下游使用已绑定的 TLS gateway 地址生成 issuer，provider 随机端口由 Docker 分配。
失败时在移除容器前输出 provider、退出状态和有界日志尾部的安全统计；原始日志文本全部不输出，
避免任意 provider 输出中的 token/password/URL 泄漏。readiness 错误保留 HTTP 状态或错误类别；诊断/清理异常不覆盖原始失败。

OIDC 的网络/响应读取失败与 HTTP 429/5xx 返回 `Unavailable`，非法 discovery/token 协议仍为
`Discovery`/`Exchange`；尝试已被消费，即便暂时不可用也须重新登录。公共入口启用 missing_docs 守卫。

唯一公告例外：[风险记录 #2357](https://dev.azure.com/shengming0923/rss/_workitems/edit/2357)，
owner shengming。仅 rss-identity-oidc 0.1.0 → openidconnect 4.0.1 → rsa 0.9.10 的 registry 路径，
当前只作 RSA 公钥验签，无 RSA 私钥操作。依赖门拒绝版本、source、反向路径漂移和其它 ignore；
上游修复、私钥用途或 I08 生产接纳前必须重新评估并撤销/更新接受，不能据此宣称漏洞已修复。

参考：[Cargo fetch](https://doc.rust-lang.org/cargo/commands/cargo-fetch.html)、
[Cargo build messages](https://doc.rust-lang.org/cargo/reference/external-tools.html#json-messages)、
[RustSec 公告](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)、
[openidconnect DiscoveryError](https://github.com/ramosbugs/openidconnect-rs/blob/4.0.1/src/discovery/mod.rs)、
[oauth2 semantic types](https://github.com/ramosbugs/oauth2-rs/blob/5.0.0/src/types.rs)。

## 本机账户管理与维护

构建 `cargo build --locked -p rss-identity-admin`，离线参数说明用 `identity-admin --help`。工具不启动 HTTP，不自动迁移或清空数据库。

配置 JSON 必填：`host`、`port`、`database`、`user`、`password_file`、`ca_file`、`tenant_id`、`storage_target`、`storage_lineage`、`storage_tenant_epoch`。后两个 identity 为非零 16 字节数组，epoch 为 RSS 存储 fencing 值。拒绝未知配置字段；生产连接始终 VerifyFull。RSS schema、lineage、tenant binding 和 Identity 安装 SQL 由部署 owner 先配置。

配置/CA 只接受有界普通文件（16 KiB / 1 MiB）；数据库密码、当前口令和新口令从私有普通文件读取，拒绝末端 symlink、FIFO、group/other 权限和超长输入。密码按原字节读取，不自动去掉换行；不得将秘密放入命令参数、环境变量或日志。PG 关闭最多等 5 秒，关闭超时不改变已确认操作结果。

### 日常操作

日常身份属于 `identity_account_runtime`，仍须验证操作者账户口令。以下参数中的密码均为文件路径：

```text
```

日常改密：用户持当前口令对自己执行 password，或同租户管理员协助重置。普通用户忘记密码：联系可用管理员；自助邮件找回尚未实现。管理员无法登录：走独立维护身份的管理员密码恢复。密码恢复不自动启用账户或成员；停用状态仍由正常管理规则处置，不允许恢复命令扩大权限。

### 初始化与管理员密码恢复

独立身份属于 `identity_account_maintenance`，只注入受控维护任务；日常服务不得读取其凭据。每次仅需维护配置和新口令文件，无签发步骤或输出授权文件。

```text
identity-admin MAINTENANCE_CONFIG initialize PRINCIPAL_UUID LOGIN PASSWORD_FILE
identity-admin MAINTENANCE_CONFIG recover PRINCIPAL_UUID NEW_PASSWORD_FILE
```

配置显式指定 tenant，命令显式指定 principal，不按登录名猜测管理员。初始化 UUID 由部署 owner 随机生成，成功后永久记录该 tenant；重复或跨租户再次初始化被拒绝。恢复只针对已有本地管理员，保留 enabled、administrator、emergency 和 membership，更新 `local_credentials` 中的密码哈希并推进 `auth_epoch`，使旧密码认证候选和既有会话失效。并发恢复按事务顺序执行，最后提交的密码生效。

成功仅输出主体/epoch。NotStarted 或确认回滚不表示提交成功；CommitUnknown/RollbackFailed 必须当作结果不确定，不自动重试或交付凭据。运维按 [只读核实与判定表](local-maintenance.md#不确定提交只读核实) 核实非秘密安全事件/状态与账户可用性，再决定是否执行新的恢复；不能根据失败退出码推断密码没变。输入密码文件由操作者管理，工具不创建或自动删除它。

维护身份隔离不等于双人审批，也不抵御 runtime 数据库凭据直接改库、维护凭据泄漏或宿主机失陷；远程执行授权与人工审计由运维入口承担。MFA、外部 IdP、身份关联、密钥和备份恢复不属于本命令。

### 开发库重建与兼容性

#2334 再次确认只有可丢弃开发库，I05 初始安装 SQL 直接改为 schema version 4。旧库/旧角色/旧参数不兼容，不提供增量迁移、旧命令别名或运行时兼容开关。

具体 owner 连接、删除顺序、RSS 前置角色、固定八个 RSS 迁移、Identity 初始安装、lineage/epoch、登录身份及 GRANT 和验收命令见 [开发库重建与安装](local-maintenance.md#重建与安装)。安装 SQL 全批单事务执行；CLI 不自动清库，遇到未知角色依赖停止，不使用 CASCADE。

安装遇到同名全局角色即失败，不静默复用。`Authority::connect` 检查当前完整结构摘要、十二张表、十张 tenant RLS 表及精确有效权限；运行角色无 deployment 写权限，维护角色无 attempts/session 和成员更新权限。权限漂移、旧 schema 和高权身份均拒绝连接。错误提供 schema 版本、角色不匹配、权限漂移和 schema/RLS 契约漂移四类安全诊断，底层 provider 故障仍保留 settlement。

### 简化结果与验证范围

| 每次初始化/恢复 | #2333 旧流程 | #2358 当前流程 |
| --- | --- | --- |
| 命令数 | 2 | 1 |
| 使用配置 | issuer + runtime | maintenance |
| 授权临时文件 | 1 | 0 |
| 部署身份数 | 2 | 2 |
| 文件交付失败 | 重签、重新交付 | 无授权文件交付环节 |

日常管理统一使用[中央管理 HTTP/UI](management.md)，旧日常 CLI 已退出。`make test-pg` 执行维护初始化/恢复、权限隔离、并发和 settlement 故障及密码文件接缝；runner 核对完整测试名与执行计数。`cargo test` 默认忽略真实 provider 测试，不能代替该证据。真实 binary/config/TLS PG 装配仍归 #2341/T32 的独立 PR。


## 中央会话 HTTP 接入

`rss_identity_http_axum::router(authority, HttpConfig::new(origin, timeout)?)?` 返回 Router（构造时拒绝 Maintenance authority）；authority 必须使用 Runtime 数据库身份。origin 是显式 canonical HTTPS origin（无尾斜线、路径、userinfo、query、fragment），timeout 为非零且不超过 60 秒。使用真实连接的 `ConnectInfo<SocketAddr>` 提供登录尝试来源；反向代理的可信客户端地址接缝归装配方，不直接接受 X-Forwarded-For。不能给 Router 添加跨源凭据开放。

[会话 wire](../architecture/identity-wire-v1.md#中央会话-httpi04) 定义 cookie、Origin、CSRF 和分页。日志/反代不能记录 Cookie、Set-Cookie、口令 body 或 CSRF；不把 session 响应缓存为新请求认证。新增 PG+Router 测试由 make test-pg 运行，界面由 rss-web apps/identity 提供，生产 listener/TLS 仍由 I08 提供；I06 的 Hydra 下游验证见下游指南，真实 MDM 接入独立。

HTTP 外部错误保持模糊；宿主可从 response extensions 读取 `HttpFailure`，区分内部 AuthorityError（含 CommitUnknown/RollbackFailed/Fenced）与 RequestTimeout。该分类不含 SQL/provider 原文，不作为自动重试许可。body 读取受 HTTP timeout 限制；下游操作接收原截止点的剩余预算，由 Authority/RSS 完成有界结算。宿主不应再用同截止点的通用 timeout 包住会话 Router，否则取消写 future 会丢失 CommitUnknown/RollbackFailed 分类；取消本身不证明回滚。

GET/HEAD 会话查询不续期。客户端在有效用户活动期间通过受 Origin+CSRF 保护的 POST refresh 续期，串行处理新 cookie/CSRF；不以无条件后台心跳绕过 idle。会话 ID 和游标在 Rust 中统一使用 core SessionId，JSON/SQL 边界仍为 UUID 字符串且拒绝 nil。


## I05 联合身份

新增 `make test-federated`：固定 Keycloak HTTPS + PostgreSQL + in-process Axum，验证真实 JIT、本地/纯联合账户关联、TLS、浏览器绑定与 Cookie 释放；它已纳入 make ci。此接缝不替代生产 binary/域名/反代/MDM 的 T3。

[联合身份指南](federation.md) 持有管理 HTTP 与部署注入参数。[I05 ADR](../architecture/adr/202609082050-2335-federated-identity.md) 持有单行配置/version、state HMAC、单次领取、原子事件、provider epoch 和无兼容退出。更新 schema 时通过 `python3 hack/schema_signature.py` 取得新安装结构摘要，再同步受控 `schema-signature.sha256`；不从现有业务库自动接受漂移。
