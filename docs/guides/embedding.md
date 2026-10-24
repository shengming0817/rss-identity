# 嵌入认证组件

宿主通过公开能力包装配本地认证和可选 OIDC，不依赖参考应用。每个来源仓库的依赖使用固定 URL 与完整 Git revision，由宿主 manifest/lock 持有；不使用本机跨仓 path。实际装配示例见 [参考宿主](../../app/identity/src/assembly.rs)，接口以各能力的 Rust API 为准。

## 本地认证与安装

1. 宿主提供已绑定 storage/fence 的 `Arc<PgRuntime>`、共享有界 KDF、显式实例与租户、会话策略、事件预算和管理策略。Identity 不创建、更换或关闭宿主池，不自动发现租户。
2. 数据库 owner 先安装所选 RSS 版本的完整消息 migration，再安装 Identity schema 并授予 runtime/maintenance profile。仅接受当前全新安装；在提交安装事务前，以实际目标角色验证有效权限和结构。入口见 [schema owner](../../crates/identity-postgres/src/schema.rs)；生产迁移执行属于宿主。
3. 维护身份只用于初始化和本地密码恢复，凭据不注入日常服务。恢复推进失效代际，保留账户/成员启停状态，不授予宿主角色。
4. runtime Authority 必须接收宿主 ManagementPolicy。密码校验和凭据签发经单一登录入口完成；浏览器 JSON、普通账户快照或上游结构值不能构造可信会话。

业务变更与安全事件使用同一 PG 事务。角色有效权限包含继承/PUBLIC/列权限检查；角色名不能替代权限证明。RSS migration 与授权接缝以实际 pin 对应源码为准，不能只复制部分 SQL。

## 密码防护与资源预算

Cookie 登录、Bearer 登录、密码重认证及本人改密共用密码防护。每租户／规范化登录名的错误凭据从首次失败起累计固定 10 分钟，允许 5 次失败；第 5 次仍是认证失败，随后等待该窗口剩余时间。成功密码认证清零，拒绝请求不延长窗口；密码重置和受控维护恢复清理失败状态并作废在途验证。未知、禁用账号使用相同公开行为。多来源共享账号窗口，故恶意失败仍可能暂时阻止合法登录；现有会话不因此撤销。宿主应保留可用的管理会话及受控维护恢复路径。

来源预算独立计算全部准入认证尝试，成功不退款；每租户／可信来源仍为 30 次／300 秒。来源来自真实连接或已验证网关链，不接受调用者自选。账号额度修复不绕过此资源保护；KDF 仍共享最多 4 个在执行的计算，计算取消后容量由真正完成的任务释放。这些数值为固定策略，无运行时覆盖或关闭开关：账号阈值和窗口为产品选择，来源和 KDF 延续既有资源预算，不表示已完成特定部署的容量验证。定义见 [密码失败策略](../../crates/identity-postgres/src/password_attempts.rs)、[来源预算](../../crates/identity-postgres/src/attempts.rs) 和 [KDF](../../crates/identity-core/src/account.rs)。

同一登录名的并发校验返回暂不可用；数据库校验许可最多 60 秒且受请求剩余期限约束，过期结果不得签发会话。密码计算期间不持有租户锁。取消和基础设施失败不计作密码错误，来源额度不退回。数据库状态有界，耗尽或计算忙碌返回 503，不伪造恢复时间。

正常会话内调用复用已有凭据，不重复密码登录。无人值守接入优先使用消费产品提供的最小权限机器凭据；Identity Bearer 仍通过密码签发并受相同防护，不能作为反复使用管理员密码的后台任务设计。

## 请求与管理授权

浏览器 HTTP 宿主通过 `authenticate_request` 取得当前请求的 AuthenticatedSession，再执行产品资源授权。Active 请求检查 cookie、同源、请求标记和 CSRF 后续期；Passive 只读验证，不延长 idle。会话保留签发时的 idle/absolute 策略，宿主配置变更只影响新会话；refresh 旋转凭据但不延长绝对期限，重新认证只能绑定当前主体。不要跨请求缓存成功身份、组或部门事实。

每次管理事务重新核对实例、租户、账户、成员、会话和失效代际后调用宿主 ManagementPolicy。策略是有界异步回调，借用当前事务连接读取宿主权威规则，不另开连接、不提交或修改租户作用域；组件落实策略要求的重新认证/MFA。宿主持有管理角色、防锁死和并发一致性，Identity 不保存 administrator/emergency/platform 角色。

异步业务可在认证原请求后，通过 `AuthenticatedSession::reference()` 将非凭据会话引用存入宿主可信数据。后续用 `Authority::recheck_session_reference` 复核原会话、账户和来源，取得本次有界的 `RevalidatedSession` 身份/组/部门事实。被撤销、失效或过期的会话不能通过；检查不延长 idle 或快照期限。引用不是登录凭据，不能从 HTTP 请求接收它替代认证，返回事实也不能用于管理操作；宿主仍负责资源授权和原请求归属。

宿主业务写入需要与会话撤销串行化时，在自己已有的、绑定 actor 租户的 READ COMMITTED 事务内调用 `recheck_authenticated_session_on(connection, &actor)`。它复用当前凭据与会话来源复核，Identity guard 保持至宿主提交或回滚；不消费 step-up、不续期、不产生新身份事实。调用顺序为已有 Audit/Ledger 锁 → Identity guard → 平台 verifier 权威锁及宿主授权/业务锁。平台 binding/source 写入必须遵守 verifier 使用同一连接取得的权威锁，不能仅依赖 Identity guard。不要在已持有这些锁时调用自开事务的引用复核接口。

通过 `PgRuntime::local_tx` 组合时，`with_connection` 回调的外层错误类型是 SQLx；使用 `tx.with_connection(|c| Box::pin(async move { Ok(recheck_authenticated_session_on(c, &actor).await) })).await??` 将内部 `PgError` 原样传播到宿主事务，不能吞掉内层错误后继续提交。

任何复核错误都要求宿主回滚；宿主继续负责 fencing、操作预算、资源授权和最终结算。复核成功不等于业务已提交，`CommitUnknown` 与回滚失败必须保留原结算语义。guard 串行化状态变更，不冻结自然时间或延长 actor 的原期限，不得跨事务缓存成功结果。该接口只接受当前请求的 `AuthenticatedSession`；异步保存的 `SessionReference` 不含当前凭据摘要，其独立复核用途不变。

参考宿主为每个配置租户指定唯一 bootstrap 账户，并阻止其自我禁用；这是示范宿主策略，不成为其它产品的默认授权。密码恢复与 IdP 故障都不能自动提升权限或复活禁用状态。

## 可选程序化 Bearer

宿主显式挂载 `bearer_router(authority, http)`，并在其外层及选定业务 API 统一执行产品 IP 准入。浏览器 router 不自动开启程序化路由。宿主仍负责 HTTPS、真实 peer/受信代理来源、租户路由、资源授权和秘密脱敏；API Key 属于消费产品，不进入 Identity。

`POST /api/v1/identity/tenants/{tenant}/bearer/login` 使用 JSON 账号密码，返回一次性 `accessToken`、`tokenType`、`sessionId`、`principalId`、`idleExpiresAt` 和 `absoluteExpiresAt`。随后使用 `Authorization: Bearer`，通过 `authenticate_bearer_request` 获取真实身份和仅限当前请求的凭据。每次有效认证包括 GET 都续空闲期限，不延长绝对期限；宿主续查使用 `inspect_bearer`，不续空闲。不存在 refresh token；绝对到期后重新密码登录。

两种呈现共用账户、密码限流及签发时会话策略；数据库持久化用途，Cookie/Bearer 双向串用均拒绝。Bearer 路由不需要浏览器 Origin/CSRF，不设置或清除 Cookie，拒绝身份 Cookie、API Key、重复 Authorization 和 URL 查询参数。不得将凭据放入 URL、日志、审计或浏览器持久存储。响应为 `no-store`；没有凭据回查入口。

`POST /api/v1/identity/tenants/{tenant}/bearer/logout` 只撤销当前 Bearer；浏览器当前注销不影响其它会话。账户全注销、密码重置、账户停用及成员撤销按既有 epoch/state 合同同时约束两种呈现。密码登录只证明密码认证，不产生 MFA；产品授权仍消费当前账户与可信 assurance。当前 schema 为全新安装，旧 schema 和旧引用结构不兼容。

## 组与可选可信部门树快照

组与部门是带来源和固定期限的认证事实，不是资源权限。缺失、空值、非法断言与过期不同；宿主应显式处理不可用状态。当前模型、受控构造和边界见 [组](../../crates/identity-core/src/groups.rs) 与 [部门](../../crates/identity-core/src/department.rs)。

组 Available 视图只能借自本次可信认证结果，每次读取 `values()` 都检查请求证明和快照截止；部门通过 `snapshot()` 做同样检查。请求证明到期使读取失败，事实独立到期不自动否定基础身份。未来观察在下次权威请求前保持不可用。已经复制的值、借出的引用和已经产生的业务效果由宿主负责。宿主需维持可信数据库时钟；请求内单调期限不能修正数据库墙钟偏差。

部门由 provider 显式启用签名 ID Token 内的完整树快照，不能从安全组、名称、路径或浏览器补齐。示例输入：

```json
{"version":1,"sourceRevision":"directory-revision-42","nodes":[
  {"id":"root","displayName":"Company","parentId":null},
  {"id":"engineering","displayName":"Engineering","parentId":"root"}
],"memberships":["engineering"]}
```

树必须完整、单根、有界；稳定标识精确匹配，显示名不提供身份。空成员表示未分配，缺失不是未分配声明。配置与输入结构由 [OIDC 适配器](../../crates/identity-oidc/src/lib.rs) 和 core 模型持有。

instance、tenant、principal、provider 和配置版本由权威会话绑定；观察来自 signed iat，期限为 signed iat 加显式配置的有界 TTL，且不超过 token exp。refresh、活动请求和组件重建不延长快照。provider 更新/禁用及主体/session 撤销作用于旧会话和在途流程；link target 不覆盖当前 source 快照。sourceRevision 是上游不透明版本，不表示 Identity 全局最新目录。

已验签但非法或超限的部门断言关闭整个部门事实，不截断树；其余认证事实仍超限则拒绝认证。签名、会话、存储格式/内容损坏或数据库故障拒绝身份，不降级为普通缺失。

Keycloak 使用内置 JSON UserAttributeMapper，把管理员维护的单个完整对象仅投影到 ID Token；属性只能由管理员查看/修改，关闭多值与聚合。来源 owner 负责完整树、稳定标识及各用户断言的同步。配置示例见现有 [provider fixture](../../hack/providers.py) 的 `configure_department_profile`。此机制适用于预算内的小型组织树，不代表目录同步、AAD 部门集成或 Keycloak 原生组织 API。资源子树授权归 MDM。

## 可选 OIDC 与 HTTP 装配

Federation 接收 Authority、上游适配器、状态签名、凭据密钥、事实期限、固定 HTTPS callback 与 return-target 白名单。本地模式不要求这些依赖。HttpOidc 的私网访问必须由宿主按 tenant/issuer/client 明确授权，网络授权与 MFA 解释相互独立，部署配置见[操作指南](../deployment/operations.md)。

```rust,ignore
let routes = rss_identity_http_axum::router(authority, http.clone())?
    .merge(rss_identity_http_axum::federated_router(federation, http)?);
```

OIDC 使用 Code/PKCE、state/nonce 和浏览器绑定，登录事务原子单次消费；邮箱不是自动关联依据。显式关联与 step-up 绑定当前主体，provider 配置变化使旧流程失效。唯一 callback 是宿主 origin 下的 `/api/v1/identity/oidc/callback`，回跳只接受宿主白名单键。

宿主持有 TLS、listener、可信代理、日志脱敏和有界关闭，必须注入 `ClientAddress`；仅有 ConnectInfo 不会自动转换，缺失来源时登录拒绝。直连中间件可从真实 peer 注入：

```rust,ignore
async fn client_address(
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    request.extensions_mut().insert(rss_identity_http_axum::ClientAddress(peer.ip()));
    next.run(request).await
}
```

直连 listener 还须通过 `into_make_service_with_connect_info::<SocketAddr>()` 提供 peer。RSS listener 的参考宿主使用 AcceptedConnectionInfo；反代须先验证真实 peer 是可信网关，再读取它覆盖的来源头。不能直接信任浏览器 forwarded headers。

不要用通用 timeout 丢弃数据库写 future。组件/RSS 持有有界事务结算；CommitUnknown、RollbackFailed 等内部结果保留在 HttpFailure 中，不能据 503 推断可安全重试。对外错误、cookie 与 CSRF 规则见 [HTTP 接入](../architecture/identity-http.md)。安全事件 schema 由 postgres 持有，不含凭据或上游 token。

密钥重加密复用组件的租户事务接口与既有 storage fence，宿主最终提交或回滚；维护角色不因此扩权。参考部署的操作顺序见[恢复与轮换](../deployment/recovery.md)。

## Entra 浏览器与原生人员身份

每个 provider 的 `claims.subject` 必须显式选择 `{"kind":"oidc"}` 或 `{"kind":"entra","tenant":"<tenant UUID>"}`。Entra 只接受该租户的 `https://login.microsoftonline.com/<tenant UUID>/v2.0` issuer。浏览器必须配置 `openid` 与 `profile` scopes；Microsoft 的 `oid` 需要 `profile`，缺失此 scope 的配置在保存/恢复时直接拒绝（见 [ID Token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)）。已验签 ID Token 中的 `(tid, oid)` 是唯一人员关联，不使用 pairwise `sub`、邮箱、UPN 或 device ID。浏览器与原生接入必须装配同一个 Identity tenant/provider；不同 provider 不自动合并账户。当前 schema 仅全新安装，旧原始 subject 和省略 subject 的配置不再读取。

原生接入由宿主装配 `HttpEntra` 与 `EntraAuthority`，固定 customer tenant、MDM appId、允许的 `azp` 客户端、委派 scopes 和设备 claim profile；请求不能选择这些信任参数。仅接受 Microsoft 公共云 Entra v2 的 RS256 人员 access token，`aud` 精确为 appId。部署应用须为 access token 配置 `idtyp` 的 `include_user_token`，使人员令牌明确携带 `idtyp=user`；缺失或 app-only 一律拒绝。scopes、客户端与设备 claim 按实际应用契约配置，不能从任意客户端 token 猜测。参考 [Microsoft access-token claims](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference) 与 [optional claims](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference)。

先 `verify` 得到不可构造的 `VerifiedExternalSubject`，宿主检查组织、注册范围、TOU、设备与配额策略后，才调用 `resolve`。已有 canonical 关联复用同一账户；未知人员仅在 provider 显式开启 JIT 时原子创建账户、关联及安全事件。JIT 默认应关闭。CommitUnknown 不返回证明；调用方按结算语义处理，不据超时断言未创建。原生接入不签发浏览器会话，也不调用管理授权接口。

`RevalidatedAccount` 是短期、不可序列化的人员事实，不能替代 `AuthenticatedSession`。在业务最终绑定前通过 `recheck` 检查账户、成员、provider epoch 与关联当前状态；它不会延长原证明期限。长期业务任务须用当前 token 重新验证，不保存此证明或借其延长身份。宿主持有资源权限、设备身份、同意及注册事务；Identity 不对设备授权。

JWKS 只从固定 Microsoft tenant 地址经有界、禁重定向的 HTTPS 取回，公共 key 缓存最多 60 秒，过期后重新获取；缓存期间的新 key 或移除 key 可能分别被拒绝或继续用于验签，最长受该缓存期限约束。token 有效期与本地 proof 期限仍单独检查。外部 Entra 撤权依赖签名 token 的剩余期限，本接口不承诺即时 CAE；本地禁用及配置变更在复核时立即拒绝。TOU 阶段可没有设备 claim，实际设备注册必须由 MDM 的操作 profile 要求并绑定设备 claim。原生 access token 不使用浏览器 OIDC nonce。

## 认证审计交付

`rss_identity_postgres::audit::AuditDelivery` 持有 Identity 事件语义。宿主注入同库的 worker `Arc<PgRuntime>`、`Arc<PgAudit>`、真实实例与租户绑定、delivery budget 和独立恢复保护密钥 `Arc<K: Aead + Send + Sync>`，调用 `run_once(NonZeroUsize)` 一次领取当前可用容量内的一批消息并跨分区并发执行；每事件拥有独立执行预算。异步构造在一个有界预算内使用 worker 实际事务连接完成 Audit（启用 Ledger 时包括 Ledger）启动验证，并检查已有 dead-letter，worker 至少配置两个连接，为 effect 执行期间续租保留连接。Audit、Ledger（启用时）、Inbox 及源 Outbox 终态在唯一事务提交；返回的 `AuditProjectionReport` 区分已确认投影和延期。提交未知的恢复身份由短锁保护，核对期间不持锁；后续调用先按原恢复凭证核对持久终态，未提交消息仅由租约重新认领；不再进行独立成功确认。不创建任务或接管连接关闭；构造和运行统一返回 `AuditDeliveryError`，宿主只对 `is_retryable()` 为真的错误重试。权限通过公开 `audit::grant_worker` / `verify_worker` 接缝装配，不复制参考 app 的 SQL。参考实现见 [审计装配](../../app/identity/src/audit.rs)。

producer 保持 `connect_producer`；worker 使用独立角色的 `PgRuntime::connect_consumer`，Audit 开启 `messaging`。worker 不读取 Identity 私有表，也不能直接修改 Audit/Outbox；schema owner 和实际权限必须通过 startup probe。宿主负责保证来源实例对应当前 Identity 数据库，不接受请求指定的 source。

存储角色、结构或函数的受控变更须先停止相关写实例并排空，再变更、以实际 worker 角色重新验证并恢复接流；不承诺逐次操作主动发现管理员带外漂移。真实 SQL 权限失败仍停止投递、不 ACK。

有安全事件的业务事务在全部 Outbox append 后调用同事务 `pg_notify`，提交后发送空 payload；通知 SQL 失败按原事务错误传播，未知提交仍为未知。无事件的条件写入不发送通知。宿主通过公开 `audit::notification_channel(instance, tenant)` 计算每个可信实例/租户的稳定频道，先完成同库 `LISTEN` 再扫描，重连后重新扫描。频道不提供访问控制或投递证明，通知可能丢失或被伪造；不要发送身份、令牌或事件内容。

宿主调用 `AuditDelivery::next_wakeup(OperationDeadline)` 获取原 RSS `OutboxWakeup`：`due_now` 与未来最早 `next_deadline` 独立存在，已到期但被其他 worker 锁住的工作不会掩盖未来期限。查询不领取、发布或证明审计成功，仍受 worker runtime 的租户 fencing、领域和总预算约束。宿主持有通知、期限和周期恢复扫描的等待策略，并在空领取后限制即时重扫；连接池与 worker 生命周期仍由宿主负责。

当前只接收 account v3、account.provisioning v1、session v1、federation v2 的精确 schema，映射为 Audit V1。账户主体来自 actor，维护事件标识维护主体；会话主体来自 principal，all_revoked 的对象是账户会话集合；联合身份按 action 区分 provider 和认证主体。provider_test_failed 为 Failed，其余已提交事件为 Succeeded。UUID 会话坐标不是 bearer secret。输出只含稳定坐标、epoch、状态、配置版本和封闭诊断码。

业务与安全事件先原子提交到 Outbox。独立 worker 在另一事务内同时提交 Audit 和 Inbox receipt，之后才确认源 Outbox。发生时间来自原事件，落录时间来自该 PG 事务；乱序不改变原事件含义。**认证成功及 Outbox 已提交均不表示 Audit 已落库**。查询授权仍由宿主持有。

审计 worker 的日志保留发布、结算、重试和故障等闭合事件；成功 claim 的耗时 tick 不写入日志，避免空轮询制造活动记录。该日志选择不改变底层 RSS observation、投递或 readiness 语义。

## 受限账户创建

跨租户创建账户由独立 `AccountProvisioner` 承接，普通 Authority 管理仍然只允许同租户。宿主显式装配 Provisioning 数据库 profile、固定源租户与已准入的目标租户，并持有 PgRuntime 和 KDF 生命周期。此 profile 不拥有凭据恢复、会话签发或 IdP 写能力。

先用 `prepare_local_account` 处理密码，再在宿主目标事务中调用 `authorize_in`（包括历史回执重放）和 `create_local_account_in`。组件在源租户作用域复查真实会话与宿主 ProvisionAccount 权限，恢复目标作用域后才写账户及安全事件；组件通过 RSS 同连接接缝校验源租户 execution binding 并持有源栅栏直至目标事务结算，源 epoch 失效时拒绝操作。宿主在同事务写产品授权和回执，任何组件错误均须传播并回滚，禁止捕获错误后继续提交。组件不签发目标租户会话，也不赋予产品管理员权限。

`identity.account.provisioning/v1` 事件包含源 actor 的实例、租户和主体，消费者使用组件审计 worker。产品持有操作幂等、密码安全指纹和首次使用登记；不得用随机盐密码编码作为请求指纹或把明文秘密写进回执。

## 消费方的事实到期测试

仅测试构建可启用 `rss-identity-postgres/test-support`，以
`Authority::with_fact_time(ControlledFactTime::default())` 给指定 Authority 配置事实时间。
保留该控制句柄，在首次成功读取后用 `advance_to(fact.expires_at())` 推进后续读取；
`inspect_session`、活动认证、reference 重检及管理事务仍走实际存储与身份校验。
时间只影响新加载的 group/department 事实投影，不改变 JWT、持久事实、会话有效期、
借用中的旧证明或事务预算。已有 Authority 克隆不受新配置影响，后续克隆共享该控制句柄；
生产装配不启用此 feature。借用事实的即时到期边界由组件 T1 持有，无需消费方重复真实等待。


## 登录资料与属性

Provider claims 使用当前结构 `profile: {"extensionsClaim": "attributes", "maxAgeSeconds": 14400}`，
常用资料读取标准 `name/preferred_username/email/email_verified`，不再配置任意 email 映射。
`extensionsClaim` 指向管理员批准的非凭据发布对象，不能指向原始 token 或安全声明；没有配置时不采集扩展。
动态对象默认最多 64 KiB、256 个成员、8 层、每数组 128 项；宿主可通过 `AuthorityConfig::with_profile_limits`
进一步收紧预算及 TTL。业务 key 不需要增加 Rust 字段或数据库列。

成功登录原子提交资料观察、会话绑定和安全事件。普通资料非法或缺失不默认拒绝登录；签名、主体绑定、存储损坏与持久化失败仍拒绝。
`Authority::current_profile(&session, deadline)` 只提供该会话本次接受的观察；平台未取得属性时返回 unavailable。
同一账户／来源只保存最新观察，新观察替换旧观察后，旧会话的 current 不自动跟随。
`latest_profile` 接受明确账户和来源，并通过 `ReadLatestProfile` 宿主策略；过期值仅供获准的最近观察展示，不是当前事实。
每次通过 `TrustedProfile::view()` 读取都检查请求／事实期限。DTO、复制后的值及已发生的业务效果不是受信证明。

`observedAt/expiresAt` 为 Unix 秒；`collectedAtMicros` 是宿主 PG 记录的采集时间（Unix 微秒），
供 MDM 新映射的采集门槛使用，不把 IdP iat 当作宿主时序。TTL 与来源到期及采集会话绝对期限取最早，读取再受当前会话期限约束。
refresh、idle 和 GET 不重新采集。组与部门的独立短期合同不变。

本地资料管理使用 `ReadLocalProfile/UpdateLocalProfile`，来源目录使用 `ReadProfileSources`，
必须由宿主明确授权，不能默认把字段配置写权限映射为这些权限。
HTTP 本地资料位于 `/api/v1/identity/tenants/{tenant}/accounts/{principal}/profile`，
PUT 使用 operationId、expectedRevision、value（必须出现，显式 null 删除），GET 返回 revision 与 value。
响应丢失时查询其 `/operations/{operationId}`；409 后重新读取，不自动重放写。
每账户最多保留 4096 条本地资料操作回执；达到容量后新操作拒绝（Rejected），原回执仍可查询和精确重放。
回执不按时间删除，不重用 operationId；账户删除时随账户清理。
本地修改只更新本地 authority，下次成功登录才产生新观察；首期没有本地邮箱验证声明。

## 平台会话接缝

宿主持有的原生平台协议在签发或接受令牌前，调用 `platform::admit_platform_subject_on`，借用同实例、同租户的显式 READ COMMITTED 事务。
该接口只复核账户、成员资格、外部身份关联和 provider 当前代际，不签发 Cookie，也不读取密码。
首次受控注册保存返回的 `PlatformSubjectVersion`，后续使用必须传回该版本；禁用再启用不能恢复旧注册。
锁顺序为 Audit/可选 Ledger → Identity tenant guard → 宿主设备、绑定与业务锁，保持同一事务直到原生操作提交或回滚。
宿主仍须校验平台签名、用途、挑战、设备、绑定和业务授权；返回版本不是认证凭据或 assurance。
部署使用 `grant_platform_subject_admission` 并在启动时调用 `verify_platform_subject_admission`。
此组合权限包含来源发布元数据准入，替代该角色原来的 profile-source-only 权限校验；不授予完整 Runtime 权限。


宿主实现 `platform::PlatformVerifier` 并通过 `AuthorityConfig::with_platform` 在启动时安装。
`resolve/recheck` 必须借传入 PG connection 锁定 MDM 当前绑定与资格；不得另取连接、提交、切租户或在事务内调用网络。
绑定必须由受控注册／人员关联流程建立，设备本地账号名、邮箱或浏览器 principal 均不构成绑定证明。
可信装配代码本身属于信任边界；Rust opaque proof 不防止恶意宿主替换 verifier。

`begin_platform_login` 显式接收 `PlatformPurpose`，为固定 audience 及用途生成最长 120 秒的挑战；宿主必须用安全 Cookie 将 browser binding 绑定实际浏览器，
并实施同源、CSRF／登录替换保护和请求预算。`complete_platform_login` 返回 `PlatformLogin`；设备签名必须覆盖 `PlatformChallengeContext::signing_payload()` 的完整字节（包括用途、RP、身份与期限），只接受挑战、nonce、browser binding 和有界证据，
不接受 principal 或 assurance DTO。`verify` 在事务外验证来源、平台签名、用途、nonce 和用户证据，
最终签发事务重新检查账户／成员、外部关联和宿主绑定，消费挑战并提交会话及安全事件。

平台仅签发 Cookie；`issued_session_response` 复用现有 Set-Cookie／CSRF 与 no-store 响应格式。
未知提交绝不返回秘密，不能通过重放挑战取回可能已经提交的凭据。
verifier 随 Authority 持续存在，会话请求、refresh、管理和后台 session reference 都重新执行绑定复核；缺少 verifier 时拒绝。
硬件持有、用户在场和用户验证不自动映射为 MFA；缺少真实用户认证时间时 assurance.auth_time 为 None。
`PlatformProfile::Unavailable` 不复活旧 IdP 属性；显式 IdentityLocal 在签发事务采集本地资料，
Idp 仅允许本次经过验证且绑定该挑战、provider 和 external identity 的属性证据。不会继承旧组／部门。

会话 `issuedAt` 仅表示签发时间；敏感操作必须使用受信 assurance.auth_time 检查近期认证。
本次替换不提供旧 authTime 会话字段、旧配置解码或旧库升级路径。


宿主将字段定义写入与来源准入组合时，使用 `admit_profile_source_on` 借用已打开 READ COMMITTED 事务、已设置租户 fence 的 PG 连接。
部署使用 `grant_profile_source_admission` 为该业务角色授权，并在启动时用 `verify_profile_source_admission` 验证；
不授予完整 Runtime 或 Provisioning 权限。该接口只读取来源发布元数据，不授予用户资料或管理权限。
锁顺序为 Audit/可选 Ledger → Identity tenant guard → 宿主授权锁 → 业务定义/回执；
调用方保持同一事务直至提交或回滚，不能在已持有宿主授权锁后调用该接口。


聚合某个账户的 latest 资料时，先用 `latest_profile_sources` 按目标账户分页发现观察来源，再调用 `latest_profile`。
来源发现与值读取均执行 `ReadLatestProfile` 策略；不从查看者登录来源、业务字段映射或邮箱猜测目标来源。
来源定位符不是认证证明，也不保证观察仍有效；值读取继续执行当前来源、账户和有效期限复核。


人员目录查询使用 `Authority::with_personnel_read`：必须传入组件签发的会话，组件在原事务复核会话及 `ListAccounts`、`ReadLatestProfile` 的全局/本人授权后切为数据库只读模式。生命周期受限的 `PersonnelRead` 仅运行宿主静态 SELECT 与绑定参数，提供固定 `identity_personnel` 关系；产品 SQL 不引用 Identity 私表，不传入用户 SQL。关系的 login、display_name、username 在授权和来源有效性筛选后才可搜索和返回。宿主在一个 SELECT 中完成设备关联、授权、过滤、统计和 keyset 分页，返回行数有硬上限。

`PersonnelRevision` 包含人员变更 generation、授权形态及有效期；cursor 还须绑定宿主自身的实例、租户、主体、授权范围和查询。关系按来源产生行，宿主使用 EXISTS 或适当聚合，避免多来源把设备重复计数。该接缝不会缓存人员数据，也不提供认证证明。宿主策略和静态 SQL 属于可信嵌入代码；组件不把此接缝作为任意 SQL 服务。

`identity_session_references` 提供同租户、账户/成员 epoch、会话期限及来源当前性已筛选的定位关系，供产品按完整 SessionReference 坐标集合关联；它不是 AuthenticatedSession。平台来源的 `requires_platform_check` 为 true，产品必须再 JOIN 自己持有的当前平台绑定/来源资格关系，核对返回的绑定 ID/epoch 和来源 ID/version，不能仅凭该关系宣称平台资格有效。原请求 actor 的平台检查仍由既有 verifier 执行。

没有自然人会话的产品入口（例如产品自己认证的 API key）使用 `Authority::with_session_references_read(tenant, deadline, query)`，仅在可信宿主保存的 SessionReference 与业务关系之间进行集合关联。该入口复用 admitted tenant、实例和执行 fencing，锁定现有租户 guard 后进入只读事务；它不调用人员管理策略，不安装 `identity_personnel`，不提供 login/profile、组、部门或认证证明。宿主必须在同一个 SELECT 中应用调用者的资源授权，并匹配 reference 的 instance、tenant、principal、session、credentialKind 全部坐标；不得把客户端提交的 locator 当作身份。平台资格仍须由宿主验证。返回的 revision 固定 `logins=false`、`profiles=None`，期限只受会话当前性和原调用预算限制。

会话关系不公开滑动 idle expiry；它只供按完整定位坐标关联当前会话。普通 touch 延长存活时间不改变关系中的可排序值；cursor 到期上界沿用签发时的保守期限，过期后必须重新查询。人员回调本身也受同一资料/会话最早过期时间限制。

## 企业 RP 与 WebAuthn 操作证明

`AuthorityConfig::with_enterprise` 安装固定目标和独立 ES256 signer。每个 RP 使用独立 issuer/Keycloak trust alias，仅对应 confidential client 可以使用该 alias；固定 scope 与 audience，禁止 assertion reuse，最大断言期限 30 秒，限制下游 token 不超过断言期限。预先按稳定 `(issuer,sub)` 关联上游账户，不通过邮箱关联。`PlatformVerifier::authorize_purpose` 在挑战创建和最终结算事务中复核该 RP 的宿主授权。

只有提交确认后才返回后端专用 `EnterpriseAssertion`。宿主使用 `HttpOidc::exchange_enterprise`，沿用现有 TLS、地址限制及有界传输，核验固定 Keycloak issuer/client/audience/subject 后自行建立 RP 会话。不得序列化断言到浏览器或自动重试未知结果。RP 保存可信 `SessionReference` 并按受保护请求重新检查；本地撤销与已签发外部 token 的剩余期限分别处理。

`WebauthnAuthority` 绑定实例级 HTTPS origin 与 RP ID，支持 UV passkey，包括同步凭据；不证明企业硬件或设备合规。宿主策略允许本人首次登记，组件检查近期主认证；后续管理使用 WebAuthn 或 OIDC MFA 生成的用途绑定证明。`RegistrationAuthorization::HostRecovery` 只供可信宿主调用，必须独立实现 `AuthorizeWebauthnRecovery` 策略并在事务中核对恢复授权，参考宿主默认拒绝；普通浏览器不能选择此路径。恢复完成不重置“曾登记”状态。

新候选直接替换旧 step-up 签名与会话升级行为，仅接受当前全新 schema。旧 revision 的消费者继续使用其固定闭包；升级时同步适配新请求、结果和消费接口，不使用 alias、旧 DTO 或运行时降级。

`WebauthnAuthority::connect` 将部署配置与 PG 中的当前 RP 指纹/代际核对；首次使用可登记，已有指纹不匹配则拒绝启动。改变 origin 或 RP 策略时，部署 owner 使用 tenant-scoped READ COMMITTED 事务调用 `activate_webauthn_rp_on`，提供预期旧代际，再重建组件。runtime 只有配置表 SELECT/INSERT 权限，不能推进或回退代际。配置切换撤销旧凭据；旧进程、挑战和操作证明不能跨代际继续使用，用户通过独立企业 MFA 或受权恢复重新登记。部署 owner 持有此次配置切换的授权、审计和结算。
