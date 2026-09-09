# Identity v1 wire

I01 协议 owner：#2331；internal validate 和下游 bridge 的实现 owner 为 #2336，见[接入指南](../guides/downstream.md)。I04 中央会话 Router 已实现，见末节；listener/TLS 属于后续装配。标准 OIDC discovery/authorize/token/JWKS/logout 由 Hydra 提供，不在 Identity 复制同名端点。

## POST /internal/v1/identity/validate

调用方：已注册产品后端；TLS + 产品独立凭据认证，凭据与 Hydra client 身份严格绑定。浏览器不调用该接口。

请求：`credential`（不透明服务端协议凭据）、`tenant_id`、`audience`。client_id 来自认证凭据，不接受请求覆盖；issuer 来自服务端配置，不接受任意 URL。

成功 JSON 包含 `subject`、`tenant_id`、`session_id`、`client_id`、`audience`、`issuer`、`auth_time`、`amr`、`acr`、`expires_at`；可选 groups 包含 provider 来源和 mapping_version，不含 MDM roles/permissions 或 DeviceContext。Identity 不暴露内部跨产品 PrincipalId。该快照只用于本次请求，禁止跨请求复用为认证缓存。

流程：认证 client → 有界 Hydra introspection → 检查 tenant/client/audience/issuer 与精确 grant/session 关联 → 读取 Identity 当前状态/epoch/expiry → 输出事实。任何一步失败都不返回部分可信上下文。

错误：400 malformed_request；401 invalid_client/invalid_credential（外部不区分详细原因）；403 identity_not_active（不暴露账户存在性）；503 identity_unavailable（存储/上游不可用）；请求预算耗尽 503。宿主通过 DownstreamDiagnostic 读取安全内部分类及同一 correlation_id；client 的 Error::Server 保留闭集 code 和 correlation UUID。响应 `Cache-Control: no-store`；error 仅 code 和不含敏感信息的 correlation_id。

## 产品浏览器回调

`GET /auth/callback?code=...&state=...`：产品验证自己保存的 state，服务端带原 redirect_uri 与 PKCE verifier 兑换；校验 issuer/audience/nonce 后调用上述复核入口，成功才创建/旋转产品 cookie。回调 URL 不保留 code，不记录 query 或把 code 发向第三方资源。

## 演进与来源

新可选字段仅在旧 consumer 可忽略时增加；身份字段含义、错误安全语义和隔离边界变化使用新 major。未知 auth strength 不提升 assurance，未知必要 identity enum 拒绝。首版 amr 为本地 pwd 或联合空数组，acr 为 unspecified；首版省略可选 groups。I02 绑定骨架已由真实 authority/client 路径替换；wire DTO 不等于可信上下文，只有 client 在线验证成功返回 VerifiedIdentity。

## 中央会话 HTTP（I04）

Owner：#2334。rss-identity-http-axum 提供可挂载 Router；生产 listener/TLS 配置由 I08 实施，UI 由 rss-web apps/identity 持有。身份绑定的 internal validate 仍归 I06，不由这些接口替代。

路径前缀 `/api/v1/tenants/{tenant}/`；tenant 是 UUID，只认证其固定租户的会话。

| 方法 / 路径 | 输入与成功结果 |
| --- | --- |
| POST login | JSON `{login,password}`；X-Identity-Request: 1；200 session + csrf_token，并设置新 cookie。有效旧 cookie 另需 CSRF，同主体原子替换。 |
| GET session | cookie；200 session + csrf_token，只读验证、不延长 idle，不重发 cookie。 |
| POST session/refresh | cookie + CSRF；200 session + 新 csrf_token，并轮换 cookie；不改变 session ID 和 absolute。 |
| POST session/logout | cookie + CSRF；204，确认撤销后清除 cookie。 |
| POST sessions/logout-all | cookie + CSRF；204，确认推进账户 auth_epoch 后清除 cookie。 |
| GET sessions | cookie；可选 cursor UUID、limit 1–100（默认 50）；200 `{sessions,next_cursor}`，只读列出本主体本租户有效会话，不延长 idle；nil/无效游标400。 |

登录/current/refresh 均返回 `{session,identity,csrf_token}`；identity 为 `{principal_id,administrator,has_local_password}`，来自同一会话验证快照，仅用于显示，不代替后续授权。

session 形状为 `{id,auth_time,idle_expires_at,absolute_expires_at}`，时间是 Unix 秒。CSRF 通过 `X-CSRF-Token` 呈递，随 cookie 轮换。GET/HEAD 查询不续期；客户端只在需要续期的有效用户活动期间串行调用受 Origin+CSRF 保护的 POST refresh，不用后台无条件心跳绕过 idle。客户端应串行刷新；并发失败方不覆盖已有 cookie/CSRF，失败响应不发送 Set-Cookie。刷新响应丢失后须重新登录。

所有写入口必须有精确同源 Origin；登录仅 JSON，不接受表单。Cookie 固定 `__Host-identity-session`、Path=/、Secure、HttpOnly、SameSite=Lax、无 Domain。Max-Age 为剩余 absolute 时间，不能以浏览器仍持 cookie 推断会话有效。

400 malformed_request；401 invalid_credential（密码错误、无效/失效凭据不暴露具体原因）；403 csrf_rejected；429 rate_limited；503 identity_unavailable（含存储故障、未确认提交）。业务错误 JSON 仅 code，不输出 SQL/provider 原文；所有响应 Cache-Control: no-store。路由框架的路径/方法/体积拒绝沿用其 HTTP 状态，仍 no-store。

## 租户 OIDC / JIT / 关联（I05）

Owner：#2335。`federated_router` 包含原 I04 路由及下列接口；所有入口使用同一 Authority，不提供 raw claims→session 接口。

| 方法 / 路径 | 输入与结果 |
| --- | --- |
| POST /api/v1/tenants/{tenant}/oidc/{provider}/login | JSON `{client_id,return_target}`，精确 Origin、X-Identity-Request: 1；有效旧 session 还须 CSRF。200 `{authorization_url}`，必要时设置独立浏览器 cookie。 |
| POST /api/v1/tenants/{tenant}/oidc/{provider}/link | 当前 session + Origin/CSRF；JSON `{client_id,return_target,password?}`。本地账户提供本人密码，纯联合账户省略；200 `{authorization_url}`。 |
| GET /api/v1/oidc/callback | code 或 error（二选一）、state、必需 iss；允许标准 session_state，拒绝 tenant/provider/return 覆盖。浏览器 cookie 必需，关联/替换另验证当前 session。完成后 303 到保存且仍注册的回跳目标，关联附加 identity_result=linked 或 already_linked；联合再认证第一步 303 到目标 IdP，不签发会话。HEAD 不兑换。 |

provider/tenant 必须非空有效 UUID。client_id/return_target 是部署注册项选择器，不接受任意 URL。
`__Host-identity-oidc-browser` 为 Secure/HttpOnly/SameSite=Lax/Path=/、无 Domain，独立于中央 session；默认 Max-Age 3600 秒，登录事务最多 300 秒。已有浏览器 cookie 不随 begin 覆盖；首次建立后再并发其它 flow。

只有已确认提交的最终成功返回中央 Cookie；失败不设置、清除或覆盖 session Cookie。callback 拒绝过期、错误浏览器、重复消费、issuer 错配、配置修改或停用；源 session 退出/失效也拒绝关联。400 malformed_request、401 invalid_credential、403 csrf_rejected、409 identity_link_conflict/configuration_changed、429 rate_limited、503 identity_unavailable。框架拒绝保持原 HTTP 状态；所有响应 no-store/no-referrer，URI 上限 8192 字节。

登录返回 Identity 中央会话，不返回上游 token 或下游 VerifiedIdentityContext。邮箱不作为关联键；账户合并不在本次范围。管理 HTTP/UI 与部署配置见[联合身份指南](../guides/federation.md)，事务/撤销规则见 [I05 ADR](adr/202609082050-2335-federated-identity.md)。


## 日常管理 HTTP（I07）

前缀 `/api/v1/tenants/{tenant}/`，所有管理请求均检查中央 cookie；写入另要求精确 Origin、X-Identity-Request: 1、X-CSRF-Token。JSON 不接受额外字段；管理 body 上限 16 KiB。未确认事务不返回成功。

| 方法 / 路径 | 输入 / 输出 |
| --- | --- |
| GET login-options | 匿名；`{providers:[{provider_id,label}]}`，仅 enabled provider 的安全展示投影 |
| GET accounts | 管理员；cursor UUID/limit 1–100 默认50；`{accounts,next_cursor}` |
| POST accounts | 管理员；`{login,password,role}`，role=member/administrator/emergency；201 AccountView |
| POST accounts/{principal}/enabled | 管理员；`{enabled}`；200 AccountView |
| POST accounts/{principal}/administrator | 管理员；`{enabled}`；200 AccountView |
| POST accounts/{principal}/membership | 管理员；`{enabled}`；200 AccountView |
| POST accounts/{principal}/password | 管理员重置他人；`{password}`；200 AccountView |
| POST account/password | 本人改密；`{current_password,password}`；200 AccountView |
| GET providers | 管理员；`{providers:[ProviderView]}` |
| POST providers | ProviderSettings；201 ProviderView，默认 disabled |
| PUT providers/{provider} | `{expected_version,settings}`；200 ProviderView |
| POST providers/{provider}/enabled | `{expected_version,enabled}`；200 ProviderView |
| POST providers/{provider}/test | 200 `{passed:true,report}` 或 `{passed:false,diagnostic:{stage,reason}}`；报告须在权限/version 重检与事件提交确认后返回 |

AccountView 是 `{principal_id,login,enabled,administrator,emergency,member_active,has_local_password}`；login 可为 null，写操作返回状态投影，不填造 login。ProviderView 和 settings 使用 I05 的既有形状。

错误 JSON 为 `{code}`：401 invalid_credential；403 insufficient_privilege/reauthentication_failed/csrf_rejected；409 last_administrator/configuration_changed/identity_link_conflict/provider_limit_reached/account_already_exists；400 malformed_request；429 rate_limited；503 identity_unavailable。错误 code 与状态严格对应；秘密与 SQL/provider 原文不输出。框架方法/路径拒绝保持其 HTTP 状态且 no-store。

OIDC callback 的失败现在统一 303 到固定同源 `/auth/error?reason=cancelled|failed|unavailable`，上游 error_description/error_uri 只接受并丢弃，不回显。成功仍到注册 target；没有第二 callback 或 JSON 错误兼容分支。

每租户 provider 容量为 100，创建在同一租户写锁下原子检查。超过容量返回 409 provider_limit_reached，不撤销会话；列表及停用仍可用。

重复本地登录名仅在已授权创建操作中返回 409 account_already_exists；会话仍有效，失败创建与安全事件原子回滚。登录选项展示既有 issuer、client 与 provider 标识，区分同 host 的 realm/client，不增加展示 schema。
