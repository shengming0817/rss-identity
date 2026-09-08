# 需求证据索引

读取日期：2026-09-07。仅做源码和文档分析，未运行 WinMDM、历史 RSS 或 Plane。此段记录历史需求分析；当前 I01/I02 实现与测试见开发指南。引用上游行为用于补全需求，不证明本产品支持同一能力。

## 消费者与 RSS 当前状态

| 来源 | 固定基线 / 文件 | 结论与需求影响 |
| --- | --- | --- |
| rss-mdm | `e64d760`，`docs/product/rss-mdm-prd.md` §06.13 | WMD-A01/02 为一级真实需求入口，A03 业务授权归 MDM；A04 二级、A05 三级。Identity 租户身份模型不提高 MDM 的 MSP 优先级 |
| rss 当前 | `1b650c166`，`Cargo.toml`、`docs/rules/project-scope.md`、`docs/rules/api-versioning.md` | runtime/messaging/PG/AMQP 已提取；实验性 release surface 不证明已发布。Identity 不重复提取；I02 核实实际版本消费 |
| rss 历史退出 | `3cd2b5573`（PR 902） | Identity/OIDC 产品面已退出主仓；退出不等于迁移到 Identity 或旧缺陷已修复 |

MDM 当前 PRD 的一级 AuthN 与本仓目标存在 owner 对齐工作，见实施计划 M01。本文读取该固定基线，不替代 MDM 后续变更。

## RSS 历史

唯一基线：`5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`（`baseline/pre-community-core-20260902`）。用 [恢复说明](../../reference/README.md) 中的 Git 命令读取。

| ID | 基线内路径 | 已读行为 / 新产品处置 |
| --- | --- | --- |
| RSS-H01 | `crates/identity/src/application/mod.rs` | LoginService、RefreshService、账户安全和事件编排；只提取规则，不复制 generated/httpserve/bootstrap/diport 依赖 |
| RSS-H02 | `adapters/postgres/src/auth_grant_lifecycle.rs` | `persist_login_grant` 同事务授权根、初始 refresh 与 outbox，账户 epoch/锁检查；映射 ACC-03/09 |
| RSS-H03 | `adapters/postgres/src/integration_tests/identity_persistence_tests.rs` | 存在登录原子性、refresh 复用、CommitUnknown、并发/回滚测试实现；转为新接口的 T1/T2 用例，未宣称本次运行通过 |
| RSS-H04 | `adapters/oidc/src/lib.rs` | profile-typed JWT/JWKS verifier；不是浏览器 authorization code client。只按需要继承验签语义 |
| RSS-H05 | `crates/identity/src/application/mod.rs`，`FederatedIdentityDomain` | 无本地 signer/login/refresh 字段的 federated listener surface，不是 SSO BFF |

## WinMDM 历史

本地入口 [winmdm20260220-develop](../../reference/winmdm20260220-develop)，非 Git 内容；完整来源与恢复步骤见 [reference](../../reference/README.md)。下面路径相对于该目录的 `src/`。

| ID | 已读文件 | 行为与补全要求 |
| --- | --- | --- |
| WIN-H01 | `internal/application/sso/oidc_provider.go` | Go OIDC/OAuth2 discovery、code exchange、claims；authorization 和 exchange 接口没有 PKCE verifier/challenge，固定 `prompt=login` 不可机械继承为 SSO 策略；ACC-05/06 |
| WIN-H02 | `internal/application/sso/sso_login_service.go` | state→nonce 持久化/原子消费、JIT/linking、组映射与 token issuance；stateStore 为 nil 时存在跳过校验分支，callback 重新取 enabled config。新设计必须 fail-closed，并绑定 tenant/provider/config-version，不能复制该降级 |
| WIN-H03 | `internal/domain/session/entity.go` | refresh hash、token family、认证方式、撤销原因和替换链；证明有会话生命周期，不证明 token 全部保存在服务端；ACC-04 |
| WIN-H04 | `internal/api/handler/sso_auth_handler.go` | callback 取 code/state、调用服务、将 access/refresh 放 cookie 后跳转；cookie 持有 token 不等于不透明服务端 session，按 ACC-04/08 重建 |
| WIN-H05 | `internal/application/setup/admin.go` | 初始管理员与角色建立流程，使用 no-op audit/event；提取初始化旅程，不能继承为安全事件原子性证明；ACC-02/09 |

已读文件 SHA-256（标识本次具体内容，不代表完整 ZIP 校验）：

```text
cba087fb8fece64751e7afbc3ae3c71b63d22c221323ed6b0967b1b196b177eb  internal/application/sso/oidc_provider.go
61621f3b5fdd69730d48cef0bb33d2a455f95b40e45c2505590b572a4b37a2ca  internal/application/sso/sso_login_service.go
a6247e275fbc5cccfee6491cb85fd476e23e331aa9a0a95db9e25ac2618d5244  internal/domain/session/entity.go
aaaff24fb3b59357bd7667e0c0bfbc6b8320fb54563eb3d44c4f642c85667c02  internal/api/handler/sso_auth_handler.go
84f1543f7df988fec617c718cb206aefb19c9d13e08c9bbfd93c9da07bcbe432  internal/application/setup/admin.go
```

## Plane 产品参考

通过 GitHub API 固定读取 `makeplane/plane` preview revision `1fec307f91003df96351557af32ce87891a3678a`。只借鉴账户流程和验收问题，未复制源码；所读源码声明 AGPL-3.0-only，后续源码复用须按实际许可证处理。

- [email.py](https://github.com/makeplane/plane/blob/1fec307f91003df96351557af32ce87891a3678a/apps/api/plane/authentication/views/app/email.py)：登录入口限流、受控跳转与 session 登录；用于 ACC-03/10。
- [password_management.py](https://github.com/makeplane/plane/blob/1fec307f91003df96351557af32ce87891a3678a/apps/api/plane/authentication/views/app/password_management.py)：账户恢复与密码重置旅程；Identity 首期明确受控管理员恢复，邮件恢复列为可选，不直接增加邮件服务依赖。
- [login.py](https://github.com/makeplane/plane/blob/1fec307f91003df96351557af32ce87891a3678a/apps/api/plane/authentication/utils/login.py)：服务端 session 与管理员 cookie 期限区分；客户端元数据不能当作设备信任证明。
- [signout.py](https://github.com/makeplane/plane/blob/1fec307f91003df96351557af32ce87891a3678a/apps/api/plane/authentication/views/app/signout.py)：退出交互来源；新产品必须用实际 session 失效证明退出，不只验证重定向。
- [官方安全公告 GHSA-mqjv-rwgv-4gxq](https://github.com/makeplane/plane/security/advisories/GHSA-mqjv-rwgv-4gxq)：验证码验证入口限流缺口的历史案例。引出“验证路径必须有失败预算，不能只限流发送路径”的验收；不由此推断固定 preview revision 仍存在该问题。

没有取得 Plane 企业 OIDC 实现证据，不宣称其租户联合身份实现已经满足 Identity；Plane 不能代替协议规范和 Rust 上游。

## 协议与 Rust 上游

- [openidconnect 4.0.1 文档](https://docs.rs/openidconnect/4.0.1/openidconnect/)：Authorization Code/PKCE、nonce 校验及禁用 HTTP 自动跳转示例；优先用于 OIDC client，产品另持有登录事务、租户与关联策略。版本在实施时重核依赖与供应链，不把示例当产品实现。
- [IETF browser-based apps draft-27 §6](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-27#section-6)：区分代理 BFF 与 token-mediating backend；该来源是草案，不标为正式 RFC。用于 I01 决定浏览器和服务端 token 路径。
- [Keycloak 官方 identity broker 文档](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker)：成熟上游可承担身份代理。用于 I01 的 build/buy 比较，不承诺本产品复制其 IAM 平台范围；动态文档须在实施时固定具体版本。

安全需求并非由单个参考项目自动批准；PRD 的目标、I01 的协议决定、实现与测试证据各自保有 owner。

## I01/I02 当前引用（2026-09-08）

- RSS Git `bf5dd1350997d01aa834094a3347fce30247814e`：`crates/transactional-messaging-postgres/src/transaction.rs`、`tests/postgres-integration/tests/lifecycle/mod.rs`；公共 local_tx/with_connection/Outbox 事务组合。历史 `5b63e10...` 仍只作历史语义参考。
- [openidconnect 4.0.1 src/lib.rs](https://github.com/ramosbugs/openidconnect-rs/blob/4.0.1/src/lib.rs)：客户端 discovery、PKCE、nonce 和 token 校验。
- [Hydra v26.2.0 oauth2/handler.go](https://github.com/ory/hydra/blob/v26.2.0/oauth2/handler.go)：标准授权/token 端点，Apache-2.0；只通过协议组合，不复制 Go 实现。
- 2026-09-08 crates.io 复核：contract/request-context/redact/transactional-messaging/transactional-messaging-postgres 索引 404；diag-context 0.1.0 artifact SHA-256 `31262d0e465e713c8d86b1f0907f03866ce66069d5ddbb4dac6de0c9e00c7d48` 与索引相符。该历史事实不再是 Git 消费的阻塞，也不证明完整闭包已发布。
