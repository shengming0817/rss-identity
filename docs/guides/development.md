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

- `access-core` 持有租户/issuer/client/audience 绑定及会话快照有效性检查。issuer/client/audience、principal/session、epoch/UnixTime 分别由私有字段 newtype 表达，参数互换有 compile-fail 验证。它不认证 HTTP 请求，也不把普通输入转换为 VerifiedContext。
- `access-postgres` 注入 RSS PgRuntime，业务 SQL 与安全事件 Outbox 在同一事务内提交。明确返回回滚、回滚失败、提交不确定及 fencing；重复事件拒绝并回滚本次业务写入。
- `access-oidc` 通过 openidconnect 完成 discovery、Authorization Code + PKCE、state/nonce/ID token 校验，返回上游 subject，尚不执行 Access JIT 或建立产品会话。出站限制为配置 issuer 同源、禁止重定向、5 秒超时和 1 MiB 响应上限。生产配置必须 HTTPS，`test-support` 仅开放显式 loopback fixture 构造器。

真实 PG 测试覆盖正常提交、SQL 失败回滚、CommitUnknownAfterAck、重复事件、跨租户 RLS 与 outbox 绑定。真实 Keycloak/Hydra 测试覆盖发现、code exchange、S256、重放、错误 state/nonce/verifier/redirect 及 provider 不可用。补充签名 token 的 azp/issuer/audience/expiry 负例、外源 discovery/JWKS、禁止跳转、响应上限和容器清理失败测试。Hydra 的 login/consent 接受逻辑是测试夹具，不是 Access authority 实现。

固定容器版本与摘要的单源为 `hack/providers.py`：PostgreSQL 17.6、Keycloak 26.7.3、Hydra v26.2.0。首次执行会拉取镜像。此测试不证明生产 TLS、持久化 Hydra、Keycloak 升级、JIT、账户恢复、完整撤销或 MDM 接入；这些由 #2333–#2343 各自验收。会话验证 HTTP wire 文档是 I01 契约，尚无可启动产品 binary。

## 独立消费复核

在 RSS 目录之外检出本仓并运行 `make dependencies check test`，使用独立 target；本仓 `.cargo/config.toml` 与 `clippy.toml` 固定配置边界。不得以父仓编译成功代替此验证。实际交付结果记录在 PR，构建输出中的 RSS source 必须是 Cargo Git URL + 完整 revision。

## 门禁与已接受风险

Provider runner 先枚举 canonical ignored 测试集合，再核对完整执行名及 passed/failed/ignored/filtered 计数；
零测试或部分执行直接失败。Hydra 仅对端口绑定冲突最多尝试三次，每次整体重建 issuer 配置。
失败时在移除容器前输出 provider、退出状态和有界日志尾部的安全统计；原始日志文本全部不输出，
避免任意 provider 输出中的 token/password/URL 泄漏。readiness 错误保留 HTTP 状态或错误类别；诊断/清理异常不覆盖原始失败。

OIDC 的网络/响应读取失败与 HTTP 429/5xx 返回 `Unavailable`，非法 discovery/token 协议仍为
`Discovery`/`Exchange`；尝试已被消费，即便暂时不可用也须重新登录。公共入口启用 missing_docs 守卫。

唯一公告例外：[风险记录 #2357](https://dev.azure.com/shengming0923/rss/_workitems/edit/2357)，
owner shengming。仅 access-oidc 0.1.0 → openidconnect 4.0.1 → rsa 0.9.10 的 registry 路径，
当前只作 RSA 公钥验签，无 RSA 私钥操作。依赖门拒绝版本、source、反向路径漂移和其它 ignore；
上游修复、私钥用途或 I08 生产接纳前必须重新评估并撤销/更新接受，不能据此宣称漏洞已修复。

参考：[Cargo fetch](https://doc.rust-lang.org/cargo/commands/cargo-fetch.html)、
[Cargo build messages](https://doc.rust-lang.org/cargo/reference/external-tools.html#json-messages)、
[RustSec 公告](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)、
[openidconnect DiscoveryError](https://github.com/ramosbugs/openidconnect-rs/blob/4.0.1/src/discovery/mod.rs)、
[oauth2 semantic types](https://github.com/ramosbugs/oauth2-rs/blob/5.0.0/src/types.rs)。
