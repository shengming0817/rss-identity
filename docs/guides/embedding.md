# 嵌入认证组件

宿主通过公开能力包装配本地认证和可选 OIDC，不依赖参考应用。四个公共 Identity 包、Audit 与基础库使用同一 RSS URL 与完整 Git revision，由宿主 manifest/lock 持有；不使用本机跨仓 path。实际装配示例见 [参考宿主](../../app/identity/src/assembly.rs)，接口以各能力的 Rust API 为准。

## 本地认证与安装

1. 宿主提供已绑定 storage/fence 的 `Arc<PgRuntime>`、共享有界 KDF、显式实例、逐操作执行作用域、会话策略、显式 Audit `Integrity` 和管理策略。Identity 不创建、更换或关闭宿主池，不自动发现租户。

`connect_runtime/connect_maintenance` 以宿主提供的一次性 probe binding 验证 schema、数据库角色、Audit 与 instance，之后丢弃 probe，不将其作为服务租户名单。宿主登记新 tenant fence 后，已有 Authority 和 router 可立即接收该租户的明确 scope。普通 HTTP 请求必须由可信宿主注入 RSS `ExecutionBinding` extension；组件核对路径 tenant，登录后生成的不可构造证明保存完整原 scope。借用连接的证明复核同样比较 storage、lineage、tenant 和 epoch。

`StateSigner` 由 `rss_identity_postgres` 导出。OIDC state v2 签名绑定 instance 和完整执行坐标；callback 从验签结果继续原 scope，旧 epoch/lineage 不能用新配置重认。state 不是当前用户或资源授权证明。
2. 在全新 PostgreSQL 17 数据库中，数据库 owner 先安装所选 RSS 版本的完整消息 migration，再以独立受限 owner 安装 Audit schema，安装 Identity schema 并授予 runtime/maintenance profile。仅接受当前全新安装；在提交安装事务前，以实际目标角色验证有效权限和结构。入口见 [schema owner](https://dev.azure.com/shengming0923/rss/_git/rss?path=/crates/identity-postgres/src/schema.rs&version=GC023deeac41dd2c02a764b95c1fe8a44bb2faa86f)；生产迁移执行属于宿主。
3. 维护身份只用于初始化和本地密码恢复，凭据不注入日常服务。恢复推进失效代际，保留账户/成员启停状态，不授予宿主角色。
4. runtime Authority 必须接收宿主 ManagementPolicy。密码校验和凭据签发经单一登录入口完成；浏览器 JSON、普通账户快照或上游结构值不能构造可信会话。

业务变更与安全事件使用同一 PG 事务。角色有效权限包含继承/PUBLIC/列权限检查；角色名不能替代权限证明。RSS migration 与授权接缝以实际 pin 对应源码为准，不能只复制部分 SQL。

## 后台读取人员属性

宿主为后台计算角色调用 `grant_personnel_fact_read`，启动时用该角色直接登录数据库并执行 `verify_personnel_fact_read`。在宿主已设置租户的数据库事务中，`read_personnel_facts_on` 接受实例、租户、至多 64 个不同主体及一个来源字段。支持已发布资料字段的标量、指定 IdP 的组标识列表和部门快照。资料路径使用解码后的 JSON Pointer 段。资料结构预算在采集时生效，读取方可进一步收紧标量的有效期。宿主负责字段可见性、敏感性和业务权限检查。

每页返回同一数据库快照中汇总的租户人员事实修订、采样时间和各主体的结果。空主体页可用于轮询版本。组列表为空表示来源明确声明零个组。缺失、过期及不可用状态均无值。后台任务应在版本变化或页的 `next_transition_at()` 到达时重算。这个时间覆盖未来观察开始生效和已有观察过期。每条观察携带采集时的来源配置版本及观察序号。宿主应跟踪时间边界，并在使用结果前检查有效期。

## 密码防护与资源预算

Cookie 登录、Bearer 登录、密码重认证及本人改密共用密码防护。默认每租户／规范化登录名的认证拒绝从首次失败起累计 10 分钟，允许 5 次；达到所选阈值后等待该窗口剩余时间。成功密码认证清零，拒绝请求不延长窗口；密码重置和受控维护恢复清理失败状态并作废在途验证。未知、禁用账号使用相同公开行为。多来源共享账号窗口，故恶意失败仍可能暂时阻止合法登录；现有会话不因此撤销。宿主应保留可用的管理会话及受控维护恢复路径。

来源预算独立计算全部准入认证尝试，成功不退款；来源来自真实连接或已验证网关链。`AuthenticationPolicy` 由宿主通过 `AuthorityConfig::with_authentication_policy` 选择三类阈值、窗口、两表合计记录容量、清理批次和有限 claim TTL。阈值调整直接比较保留的历史计数；窗口变更只影响新窗口，已有 expiry 不改写。各实例须由宿主协调使用一致策略，数据库锁只保证共享计数的串行更新。

`PasswordKdf::new(concurrency, reserved_memory_bytes)` 要求非零参数和名义 Argon2 工作区之外的开销余量；该预留不是进程 RSS 硬限制。全部克隆共享 gate，调用取消后 permit/tracker 仍由真正执行完毕的 blocking 工作释放。密码强度和 PHC 格式固定在 `PasswordPolicy`，不能通过容量配置降低。

同一登录名的并发校验返回暂不可用；claim TTL 与原请求截止分别生效，过期 owner 不能结算或签发会话。参考宿主从操作预算提供 TTL，不保留另一个隐藏截断。密码计算期间不持有租户锁。取消和基础设施失败不计作认证拒绝，已提交的来源额度不退回。容量耗尽返回明确的忙碌结果，不伪造恢复时间。过期接管可能与旧进程尚未结束的 blocking 工作重叠，fencing 保护结算，本地 gate 保护本进程资源。

正常会话内调用复用已有凭据，不重复密码登录。无人值守接入优先使用消费产品提供的最小权限机器凭据；Identity Bearer 仍通过密码签发并受相同防护，不能作为反复使用管理员密码的后台任务设计。

## 执行与事实预算

HTTP 接受可表示的有限正预算。上游 `prepare/exchange/test/verify` 及 enterprise exchange 显式接收 RSS `Deadline`；整个调用链只消耗该绝对截止，PG 事务沿用该截止和宿主执行时钟。

组与部门快照各数量支持 1024；部门树深仍为 16。`with_auth_facts_budget` 选择完整 JSONB 表示的字节预算，数量合法不保证任意长名称组合都能装入预算。普通资料由 core 限制 raw JSON，HTTP 另限制完整请求包络；JSONB 的空格和数值展开不再受另一份不等价的文本长度上限拦截，SQL 保留对象结构约束。

关联意图和替换会话在写入时都使用当前宿主预算。预算足够时原样传递来源事实；若宿主收紧预算，组件可将整份部门快照标记为 `invalid_claim`，保留来源观察序号、组和认证信息。降级后仍超限则拒绝本次写入。宿主授权和会话引用复核读取目标会话实际接纳的事实及其原有期限。

`with_future_skew`、`with_operation_proof_lifetime` 和 `PlatformVerifier::challenge_seconds` 持有相应时间选择。策略只决定新签发内容，已有事实、证明和在途登记执行冻结期限；任何本地预算都不能延长签名 exp、会话或已存 expiry。

## 请求与管理授权

浏览器 HTTP 宿主通过公共 Rust 包 `rss-identity-web-credentials` 的 `authenticate_request` 取得当前请求的 AuthenticatedSession，再执行产品资源授权。Active 请求检查 cookie、同源、请求标记和 CSRF 后续期；Passive 只读验证，不延长 idle。会话保留签发时的 idle/absolute 策略，宿主配置变更只影响新会话；refresh 旋转凭据但不延长绝对期限，重新认证只能绑定当前主体。不要跨请求缓存成功身份、组或部门事实。

```rust,ignore
let (proof, _) = rss_identity_web_credentials::authenticate_request(
    &authority, &http, binding, &headers,
    rss_identity_web_credentials::SessionActivity::Passive, deadline,
).await?;
```

每次管理事务重新核对实例、租户、账户、成员、会话和失效代际后调用宿主 ManagementPolicy。策略是有界异步回调，借用当前事务连接读取宿主权威规则，不另开连接、不提交或修改租户作用域；组件落实策略要求的重新认证/MFA。宿主持有管理角色、防锁死和并发一致性，Identity 不保存 administrator/emergency/platform 角色。

异步业务可在认证原请求后，通过 `AuthenticatedSession::reference()` 将非凭据会话引用存入宿主可信数据。后续用 `Authority::recheck_session_reference` 复核原会话、账户和来源，取得本次有界的 `RevalidatedSession` 身份/组/部门事实。被撤销、失效或过期的会话不能通过；检查不延长 idle 或快照期限。引用不是登录凭据，不能从 HTTP 请求接收它替代认证，返回事实也不能用于管理操作；宿主仍负责资源授权和原请求归属。

宿主业务写入需要与会话撤销串行化时，在自己已有的、绑定 actor 租户的 READ COMMITTED 事务内调用 `recheck_authenticated_session_on(connection, &actor)`。它复用当前凭据与会话来源复核，Identity 在本连接锁定当前来源、账户、成员和会话，保持至宿主提交或回滚；不消费 step-up、不续期、不产生新身份事实。调用顺序为已有 Audit/Ledger 锁 → Identity 来源、账户及会话锁 → 平台 verifier 权威锁及宿主授权/业务锁。平台 binding/source 写入必须遵守 verifier 使用同一连接取得的权威锁，不能仅依赖 Identity 资格锁。不要在已持有这些锁时调用自开事务的引用复核接口。

单会话先定位，再按 Provider、账户与成员、会话的顺序取锁。同层对象按 UUID 排序，同一对象直接取本次操作所需的最强模式。锁后重新读取凭据、代际、来源和期限。

| 协调对象 | 要保护的操作及持锁范围 |
|---|---|
| 实例 | 复用宿主事务的 storage、lineage、tenant epoch fence，并核对不可变的部署 ID。启用 Ledger 时先取得 Audit head。 |
| 租户 | 已知主体的普通操作取 `KEY SHARE`。宿主借用和平台 verifier 取 `SHARE`，允许多个独立准入并行。会持有资格写锁并调用宿主策略的管理事务先取 `NO KEY UPDATE`。全租户集合窗口、跨来源链接及批量维护从入口取 `UPDATE`。 |
| Provider、账户与成员 | 复核取共享锁。Provider 撤权和账户禁用、改密、成员变更锁相应写目标。维护改密先锁租户登记行，再锁目标账户与尝试容量行，更新账户时推进相应资格修订；相关锁持到事务结算。 |
| 会话 | 被动检查和借用准入持共享锁，续期及当前会话撤销取非键更新锁，轮换凭据取更新锁。全部会话撤销通过账户代际与该账户的所有准入协调。 |
| 租户事务状态 | 资料序号、回执时钟与尝试容量分别协调。先取得所需序号或时钟，再由业务写入推进相关类别与来源的目录修订；同一行涉及多个修订键时按固定顺序更新。回执 GET、PUT 均在取得时钟锁后采样。 |

宿主在业务锁之前完成会话准入和 step-up。已准入的组合在同连接内复用保护，平台 binding/source 写入遵循 verifier 的权威锁。宿主提交或回滚释放全部锁。纯续期和凭据轮换保留原人员版本。

通过 `PgRuntime::local_tx_until(binding, deadline, ...)` 组合时，`with_connection` 回调的外层错误类型是 SQLx；使用 `tx.with_connection(|c| Box::pin(async move { Ok(recheck_authenticated_session_on(c, &actor).await) })).await??` 将内部 `PgError` 原样传播到宿主事务，不能吞掉内层错误后继续提交。

任何复核错误都要求宿主回滚；宿主继续负责 fencing、操作预算、资源授权和最终结算。复核成功不等于业务已提交，`CommitUnknown` 与回滚失败必须保留原结算语义。资格行锁串行化相应状态变更，不冻结自然时间或延长 actor 的原期限，不得跨事务缓存成功结果。该接口只接受当前请求的 `AuthenticatedSession`；异步保存的 `SessionReference` 不含当前凭据摘要，其独立复核用途不变。

参考宿主为每个初始化目标指定唯一 bootstrap 账户，并阻止其自我禁用；这是示范宿主策略，不成为其它产品的默认授权。密码恢复与 IdP 故障都不能自动提升权限或复活禁用状态。

## 可选程序化 Bearer

嵌入宿主定义登录和注销入口并执行网络来源准入。密码登录调用 `Authority::login_local_bearer`，以产品契约交付一次性令牌。后续请求通过 `authenticate_bearer_request` 验证已有 Authorization 头，获得本次请求的身份与凭据。活动认证更新空闲期限，`inspect_bearer` 仅复核；注销以同一会话证明调用 `Authority::revoke_current_session`。账户全注销、重置密码、停用账户和撤销成员资格均按原有会话代际生效。

凭据处理拒绝身份 Cookie、API Key 和重复 Authorization 混用。宿主负责 TLS、可信 peer、操作时限、资源授权及响应 `no-store`；凭据只通过凭据通道交付。密码登录的 assurance 仅表示密码认证。

独立服务可选的固定路径、JSON 字段和 HTTP 状态归 `rss-identity-service-http`。[程序化 Bearer 接口](../architecture/identity-http.md#程序化-bearer-接口) 描述其路径、响应和启用条件。参考宿主默认关闭程序化端点。

## 组与可选可信部门树快照

组与部门是带来源和固定期限的认证事实，不是资源权限。缺失、空值、非法断言与过期不同；宿主应显式处理不可用状态。当前模型、受控构造和边界见 [组](https://dev.azure.com/shengming0923/rss/_git/rss?path=/crates/identity-core/src/groups.rs&version=GC023deeac41dd2c02a764b95c1fe8a44bb2faa86f) 与 [部门](https://dev.azure.com/shengming0923/rss/_git/rss?path=/crates/identity-core/src/department.rs&version=GC023deeac41dd2c02a764b95c1fe8a44bb2faa86f)。

组 Available 视图只能借自本次可信认证结果，每次读取 `values()` 都检查请求证明和快照截止；部门通过 `snapshot()` 做同样检查。请求证明到期使读取失败，事实独立到期不自动否定基础身份。未来观察在下次权威请求前保持不可用。已经复制的值、借出的引用和已经产生的业务效果由宿主负责。宿主需维持可信数据库时钟；请求内单调期限不能修正数据库墙钟偏差。

部门由 provider 显式启用签名 ID Token 内的完整树快照，不能从安全组、名称、路径或浏览器补齐。示例输入：

```json
{"version":1,"sourceRevision":"directory-revision-42","nodes":[
  {"id":"root","displayName":"Company","parentId":null},
  {"id":"engineering","displayName":"Engineering","parentId":"root"}
],"memberships":["engineering"]}
```

树必须完整、单根、有界；稳定标识精确匹配，显示名不提供身份。空成员表示未分配，缺失不是未分配声明。配置与输入结构由 [OIDC 适配器](https://dev.azure.com/shengming0923/rss/_git/rss?path=/crates/identity-oidc/src/lib.rs&version=GC023deeac41dd2c02a764b95c1fe8a44bb2faa86f) 和 core 模型持有。

instance、tenant、principal、provider 和配置版本由权威会话绑定；观察来自 signed iat，期限为 signed iat 加显式配置的有界 TTL，且不超过 token exp。refresh、活动请求和组件重建不延长快照。provider 更新/禁用及主体/session 撤销作用于旧会话和在途流程；link target 不覆盖当前 source 快照。sourceRevision 是上游不透明版本，不表示 Identity 全局最新目录。

已验签但非法或超限的部门断言关闭整个部门事实，不截断树；其余认证事实仍超限则拒绝认证。签名、会话、存储格式/内容损坏或数据库故障拒绝身份，不降级为普通缺失。

Keycloak 使用内置 JSON UserAttributeMapper，把管理员维护的单个完整对象仅投影到 ID Token；属性只能由管理员查看/修改，关闭多值与聚合。来源 owner 负责完整树、稳定标识及各用户断言的同步。配置示例见现有 [provider fixture](../../hack/providers.py) 的 `configure_department_profile`。此机制适用于预算内的小型组织树，不代表目录同步、AAD 部门集成或 Keycloak 原生组织 API。资源子树授权归 MDM。

## 可选 OIDC 与 HTTP 装配

HttpOidc 和 HttpEntra 构造时接收 `ProviderClock::new(runtime.execution_timer().clone(), SystemTime::now)`，以宿主执行时钟处理绝对截止，以 UTC 墙钟检查协议时间。宿主通过 `AuthorityConfig::with_oidc` 安装上游适配器，登录、会话复核和管理授权复用此配置。Federation 接收该 Authority、状态签名、凭据密钥、事实期限、固定 HTTPS callback 与 return-target 白名单。Authority 不保存租户名单；无认证证明的操作接收 `ExecutionBinding`，已认证操作沿用证明的原 binding。连接固定 storage，每次事务核对 tenant/epoch，不从数据库自动更新代际。本地模式不要求这些依赖。HttpOidc 的私网访问必须由宿主按 tenant/issuer/client 明确授权，网络授权与 MFA 解释相互独立，部署配置见[操作指南](../deployment/operations.md)。

宿主登录入口用 `BrowserBinding::start` 获取关联值及首次签发的 Cookie，将关联值和可信执行绑定传给 `Federation::begin_login`。回调用 `BrowserBinding::require` 取回关联值，经 `CallbackOutcome::from_parts` 判定结果后调用 `Federation::complete` 或 `cancel`。独立服务的示例见[OIDC 路由](../../crates/identity-service-http/src/oidc.rs)。

OIDC 使用 Code/PKCE、state/nonce 和浏览器绑定，登录事务原子单次消费；邮箱不是自动关联依据。显式关联与 step-up 绑定当前主体，provider 配置变化使旧流程失效。唯一 callback 是宿主 origin 下的 `/api/v1/identity/oidc/callback`，回跳只接受宿主白名单键。

通用 OIDC 宿主在构造 `HttpOidc` 时显式提供 `TransportPolicy` 和 `ReusePolicy`。运行入口使用 `BoundProvider` 绑定实例、租户、Provider ID、单调配置版本与本次凭据。宿主在权威配置读取锁内或串行安装配置时以 `oidc.revisions().install(revision, settings, credentials)` 一次安装版本、设置与凭据。运行入口接收该不可重绑的快照；共享公开数据的缓存仅保留非秘密代际标记。配置变更提交后向使用该配置的每个活跃适配器调用 `revisions().observe(new_revision)`。适配器按活跃快照跟踪代际，缓存淘汰不会恢复旧快照。池条目持有非秘密退役信号，直到条目被淘汰。操作结束或宿主卸载配置后释放快照及其 clone；长期持有会占用版本登记容量（每实例上限为 maxProviders 加 maxRefreshes），即使连接池可被淘汰。参考宿主的 `oidc.reuse` 必填，例如：

```json
{"maxProviders":128,"maxResidentBytes":8388608,"maxRefreshes":8,"maxIdlePerHost":2,"idleSeconds":30,"discoverySeconds":300,"jwksSeconds":60,"refreshCooldownSeconds":10}
```

登录准备只获取 Discovery。回调按签名算法读取密钥，JWKS 故障可能在完成上游登录后才报告，失败后须重新登录。每次 token 交换仅提交一次；管理员连接测试始终新建连接并读取两份文档。复用、冷却与在途撤权均以适配器实例为界，PostgreSQL Federation 在变更事务内先退役旧快照，再结算并按权威数据库版本复核。提交结果不明或回滚后，新的权威读取可取得当前配置；已经退役的在途操作须重试。撤权会取消本地 HTTP 等待，已经发送到上游的请求可能已产生效果。直接调用企业交换的宿主须在交付或使用返回的凭据前自行复核权威版本。

宿主持有 TLS、listener、可信代理、日志脱敏和有界关闭。从已核实的连接取得客户端地址，并在密码登录等操作中显式传入 `AttemptSource`。独立 Identity 宿主将验证后的地址通过产品 HTTP 扩展注入。

使用 Axum ConnectInfo 的直连 listener 通过 `into_make_service_with_connect_info::<SocketAddr>()` 提供 peer。RSS listener 的参考宿主使用 AcceptedConnectionInfo；反代须先验证真实 peer 是可信网关，再读取它覆盖的来源头。不能直接信任浏览器 forwarded headers。

不要用通用 timeout 丢弃数据库写 future。组件/RSS 持有有界事务结算；CommitUnknown、RollbackFailed 等内部结果保留在公共凭据错误的 Authority 分类中，不能据 503 推断可安全重试。对外错误、cookie 与 CSRF 规则见 [HTTP 接入](../architecture/identity-http.md)。安全事件 schema 由 postgres 持有，不含凭据或上游 token。

`Federation::check_credential_keys(binding, deadline)` 只检查一个明确目标，宿主持有分页与全库覆盖结论。密钥重加密复用组件的租户事务接口与既有 storage fence，宿主最终提交或回滚；维护角色不因此扩权。参考部署的操作顺序见[恢复与轮换](../deployment/recovery.md)。

## Entra 浏览器与原生人员身份

每个 provider 的 `claims.subject` 必须显式选择 `{"kind":"oidc"}` 或 `{"kind":"entra","tenant":"<tenant UUID>"}`。Entra 只接受该租户的 `https://login.microsoftonline.com/<tenant UUID>/v2.0` issuer。浏览器必须配置 `openid` 与 `profile` scopes；Microsoft 的 `oid` 需要 `profile`，缺失此 scope 的配置在保存/恢复时直接拒绝（见 [ID Token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)）。已验签 ID Token 中的 `(tid, oid)` 是唯一人员关联，不使用 pairwise `sub`、邮箱、UPN 或 device ID。浏览器与原生接入必须装配同一个 Identity tenant/provider；不同 provider 不自动合并账户。当前 schema 仅全新安装，旧原始 subject 和省略 subject 的配置不再读取。

原生接入由宿主装配 `HttpEntra` 与 `EntraAuthority`，固定 customer tenant、MDM appId、允许的 `azp` 客户端、委派 scopes 和设备 claim profile；请求不能选择这些信任参数。仅接受 Microsoft 公共云 Entra v2 的 RS256 人员 access token，`aud` 精确为 appId。部署应用须为 access token 配置 `idtyp` 的 `include_user_token`，使人员令牌明确携带 `idtyp=user`；缺失或 app-only 一律拒绝。scopes、客户端与设备 claim 按实际应用契约配置，不能从任意客户端 token 猜测。参考 [Microsoft access-token claims](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference) 与 [optional claims](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference)。

先 `verify` 得到不可构造的 `VerifiedExternalSubject`，宿主检查组织、注册范围、TOU、设备与配额策略后，才调用 `resolve`。已有 canonical 关联复用同一账户；未知人员仅在 provider 显式开启 JIT 时原子创建账户、关联及安全事件。JIT 默认应关闭。CommitUnknown 不返回证明；调用方按结算语义处理，不据超时断言未创建。原生接入不签发浏览器会话，也不调用管理授权接口。

`RevalidatedAccount` 是短期、不可序列化的人员事实，不能替代 `AuthenticatedSession`。在业务最终绑定前通过 `recheck` 检查账户、成员、provider epoch 与关联当前状态；它不会延长原证明期限。长期业务任务须用当前 token 重新验证，不保存此证明或借其延长身份。宿主持有资源权限、设备身份、同意及注册事务；Identity 不对设备授权。

JWKS 只从固定 Microsoft tenant 地址经有界、禁重定向的 HTTPS 取回。`TransportPolicy` 选择请求、连接、响应字节和键数预算；`JwksCachePolicy` 选择 TTL、租户容量和刷新冷却，原生 token 输入预算单独提供。有效缓存遇到未知 kid 时，在每租户锁内按冷却规则刷新一次并完整验签；失败和取消同样进入冷却，有效旧键可以继续使用，过期失败则拒绝。冷却是实例内语义，不承诺跨实例全局单次刷新。token 有效期与本地 proof 期限仍单独检查。外部 Entra 撤权依赖签名 token 的剩余期限，本接口不承诺即时 CAE；本地禁用及配置变更在复核时立即拒绝。TOU 阶段可没有设备 claim，实际设备注册必须由 MDM 的操作 profile 要求并绑定设备 claim。原生 access token 不使用浏览器 OIDC nonce。

## 认证审计交付

Identity 直接将内部安全事件映射成准备好的 Audit 记录，在原业务事务内批量追加。
`AuthorityConfig::new(instance, sessions, integrity, audit_budget)` 接收宿主共享的审计写入预算。独立服务按每个数据库连接最多一个 8 行、1 MiB 批次设置总容量，使用
`rss_audit_postgres::Integrity::Plain`，不存在禁用审计分支。嵌入宿主可通过同源 Audit feature
启用 Ledger，并注入其认证器。启动在实际业务连接上验证 Audit；无专用审计池、worker、通知或恢复密钥。

产品决定来源真实性、事件含义和业务授权。Identity 每次操作生成一次事件身份，在原连接取得
记录时间，直接调用 Audit 的无池批量入口。成功提交包含业务和 Audit；追加失败回滚原事务，
提交未知仍为未知，不自动重执行业务或重新生成审计材料。普通读取不新增安全事件。

runtime、maintenance、provisioning profile 授予 Audit records SELECT 和 append_batch EXECUTE；
不授予直接表写入、sequence 或 owner 权限。共享 PgRuntime、fencing 和 producer profile 所需
RSS schema/权限保留，不代表 Identity 仍发布审计 Outbox 消息。Ledger 模式在业务锁前取得链锁。

仅支持全新安装；变更角色/结构须由宿主停写并重新验证，旧配置与旧数据库不自动迁移。

## 受限账户创建

跨租户创建账户由独立 `AccountProvisioner` 承接，普通 Authority 管理仍然只允许同租户。宿主显式装配 Provisioning 数据库 profile、固定源租户与已准入的目标租户，并持有 PgRuntime 和 KDF 生命周期。此 profile 不拥有凭据恢复、会话签发或 IdP 写能力。

先用 `prepare_local_account` 处理密码，再在宿主目标事务中调用 `authorize_in`（包括历史回执重放）和 `create_local_account_in`。组件在源租户作用域复查真实会话与宿主 ProvisionAccount 权限，恢复目标作用域后才写账户及安全事件；组件通过 RSS 同连接接缝校验源租户 execution binding 并持有源栅栏直至目标事务结算，源 epoch 失效时拒绝操作。宿主在同事务写产品授权和回执，任何组件错误均须传播并回滚，禁止捕获错误后继续提交。组件不签发目标租户会话，也不赋予产品管理员权限。

`identity.account.provisioning/v1` 事件包含源 actor 的实例、租户和主体，在原目标事务内直接追加 Audit。产品持有操作幂等、密码安全指纹和首次使用登记；不得用随机盐密码编码作为请求指纹或把明文秘密写进回执。

## 登录资料与属性

Provider claims 使用当前结构 `profile: {"extensionsClaim": "attributes", "maxAgeSeconds": 14400}`，
常用资料读取标准 `name/preferred_username/email/email_verified`，不再配置任意 email 映射。
`extensionsClaim` 指向管理员批准的非凭据发布对象，不能指向原始 token 或安全声明；没有配置时不采集扩展。
动态对象支持 1024 个成员、每数组 1024 项，仍受 64 KiB 和 8 层约束；宿主通过 `AuthorityConfig::with_profile_limits`
选择更小资源预算及有限正 TTL。成员/数组与字节预算共同生效。业务 key 不需要增加 Rust 字段或数据库列。

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
账户资料 GET 返回 revision 与 value。PUT 必须同时提供 operationId、expectedRevision 和 value；省略 value 返回 HTTP 400。
提交时用 UUIDv7 生成一次 operationId；Rust 使用 `ProfileOperationId::now()`。保存原 ID、expectedRevision 和 value（显式 null 表示删除）。首次提交须在 ID 时间起 5 分钟内到达事务接纳点，客户端时钟最多可快 30 秒。其它 UUID 版本或过大的未来偏差返回 HTTP 400。
成功事务以 PostgreSQL 记录的接纳时间为起点保留回执 24 小时。期间经当前授权原样重提交返回原 revision；用同 ID 更换目标账户、actor、expectedRevision 或 value 返回 409 `operation_conflict`。新操作的 CAS 失败返回 409 `revision_conflict`。
响应丢失时，原 actor 用 `GET /operations/{operationId}`（相对账户资料路径）查询。返回回执即已提交；首次提交窗口内没有可见回执返回 200 null。窗口关闭且没有可见有效回执时，查询或原请求重试返回 410 `profile_operation_expired`。此时历史结果可能未知，重新读取资料，确认仍需变更后再生成新 ID。查询和重放均须当前会话与宿主授权。
宿主用 `AuthorityConfig::with_profile_receipt_capacity` 设置每账户活动回执容量，默认 4096。达到容量时新操作返回 409 `profile_receipt_capacity_reached`；已有有效回执仍可查询和重放。提高或降低容量立即影响新操作。过期名额立即释放；过期行在后续成功写入时分批删除。
本地修改只更新本地 authority，下次成功登录才产生新观察；首期没有本地邮箱验证声明。

## 平台会话接缝

宿主持有的原生平台协议在签发或接受令牌前，调用 `platform::admit_platform_subject_on`，借用同实例、同租户的显式 READ COMMITTED 事务。
该接口只复核账户、成员资格、外部身份关联和 provider 当前代际，不签发 Cookie，也不读取密码。
首次受控注册保存返回的 `PlatformSubjectVersion`，后续使用必须传回该版本；禁用再启用不能恢复旧注册。
锁顺序为 Audit/可选 Ledger → Identity 主体与来源准入 → 宿主设备、绑定与业务锁，保持同一事务直到原生操作提交或回滚。
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

平台仅签发 Cookie；宿主通过 `rss_identity_web_credentials::issued_cookie(&issued)` 取得同一次签发的 Set-Cookie 和 CSRF 值，按产品契约投影响应，并添加 no-store。
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
锁顺序为 Audit/可选 Ledger → Identity 资料来源准入 → 宿主授权锁 → 业务定义/回执；
调用方保持同一事务直至提交或回滚，不能在已持有宿主授权锁后调用该接口。


聚合某个账户的 latest 资料时，先用 `latest_profile_sources` 提供显式 limit、按目标账户分页发现观察来源，再调用 `latest_profile`。
来源发现与值读取均执行 `ReadLatestProfile` 策略；不从查看者登录来源、业务字段映射或邮箱猜测目标来源。
来源定位符不是认证证明，也不保证观察仍有效；值读取继续执行当前来源、账户和有效期限复核。


人员目录查询使用 `Authority::with_personnel_read`：必须传入组件签发的会话，组件在原事务复核会话及 `ListAccounts`、`ReadLatestProfile` 的全局/本人授权后切为数据库只读模式。生命周期受限的 `PersonnelRead` 仅运行宿主静态 SELECT 与绑定参数，提供固定 `identity_personnel` 关系；产品 SQL 不引用 Identity 私表，不传入用户 SQL。关系的 login、display_name、username 在授权和来源有效性筛选后才可搜索和返回。宿主在一个 SELECT 中完成设备关联、授权、过滤、统计和 keyset 分页，返回行数有硬上限。

`PersonnelRevision` 包含人员变更 generation、授权形态及有效期；cursor 还须绑定宿主自身的实例、租户、主体、授权范围和查询。关系按来源产生行，宿主使用 EXISTS 或适当聚合，避免多来源把设备重复计数。该接缝不会缓存人员数据，也不提供认证证明。宿主策略和静态 SQL 属于可信嵌入代码；组件不把此接缝作为任意 SQL 服务。

`identity_session_references` 提供同租户、账户/成员 epoch、会话期限及来源当前性已筛选的定位关系，供产品按完整 SessionReference 坐标集合关联；它不是 AuthenticatedSession。平台来源的 `requires_platform_check` 为 true，产品必须再 JOIN 自己持有的当前平台绑定/来源资格关系，核对返回的绑定 ID/epoch 和来源 ID/version，不能仅凭该关系宣称平台资格有效。原请求 actor 的平台检查仍由既有 verifier 执行。

没有自然人会话的产品入口（例如产品自己认证的 API key）使用 `Authority::with_session_references_read(binding, deadline, query)`，仅在可信宿主保存的 SessionReference 与业务关系之间进行集合关联。该入口复用宿主提供的明确 binding、实例和执行 fencing，取得覆盖全租户集合的锁后进入只读事务；它不调用人员管理策略，不安装 `identity_personnel`，不提供 login/profile、组、部门或认证证明。宿主必须在同一个 SELECT 中应用调用者的资源授权，并匹配 reference 的 instance、tenant、principal、session、credentialKind 全部坐标；不得把客户端提交的 locator 当作身份。平台资格仍须由宿主验证。返回的 revision 固定 `logins=false`、`profiles=None`，修订有效期受会话集合的有界到期探针与 60 秒一致性上限约束，回调还受原调用预算约束。

会话关系通过完整定位坐标关联当前会话。列 `session_valid_until` 是读取当时该会话空闲期限与绝对期限的较早者，续期会更新该值。宿主用它限制投影的有效期。分页按稳定定位坐标排序，cursor 沿用签发时的保守期限，到期后重新查询。人员回调受可见资料的下次生效或到期、会话引用到期及单次 60 秒一致性窗口限制。引用期限探针按到期顺序最多复核 32 条候选会话。达到上限时，窗口最晚到最后一条已检查候选的到期时刻，集中撤权后可能提前重查。返回给宿主的每条引用仍完整复核资格。

## 企业 RP 与 WebAuthn 操作证明

`AuthorityConfig::with_enterprise` 安装固定目标和独立 ES256 signer。每个 RP 使用独立 issuer/Keycloak trust alias，仅对应 confidential client 可以使用该 alias；固定 scope 与 audience，禁止 assertion reuse，最大断言期限 30 秒，限制下游 token 不超过断言期限。预先按稳定 `(issuer,sub)` 关联上游账户，不通过邮箱关联。`PlatformVerifier::authorize_purpose` 在挑战创建和最终结算事务中复核该 RP 的宿主授权。

只有提交确认后才返回后端专用 `EnterpriseAssertion`。宿主使用 `HttpOidc::exchange_enterprise`，沿用现有 TLS、地址限制及有界传输，核验固定 Keycloak issuer/client/audience/subject 后自行建立 RP 会话。不得序列化断言到浏览器或自动重试未知结果。RP 保存可信 `SessionReference` 并按受保护请求重新检查；本地撤销与已签发外部 token 的剩余期限分别处理。

`WebauthnAuthority` 绑定实例级 HTTPS origin 与 RP ID，支持 UV passkey，包括同步凭据；不证明企业硬件或设备合规。宿主策略允许本人首次登记，组件检查近期主认证；后续管理使用 WebAuthn 或 OIDC MFA 生成的用途绑定证明。`RegistrationAuthorization::HostRecovery` 只供可信宿主调用，必须独立实现 `AuthorizeWebauthnRecovery` 策略并在事务中核对恢复授权，参考宿主默认拒绝；普通浏览器不能选择此路径。恢复完成不重置“曾登记”状态。

新候选直接替换旧 step-up 签名与会话升级行为，仅接受当前全新 schema。旧 revision 的消费者继续使用其固定闭包；升级时同步适配新请求、结果和消费接口，不使用 alias、旧 DTO 或运行时降级。

`WebauthnAuthority::new` 只构造 RP verifier，不枚举或预装租户。宿主为每次操作明确提供 `RpGeneration`；首次合法使用在既有租户集合锁下登记该代际，后续精确核对持久化指纹与代际。改变 origin 或 RP 策略时，部署 owner 在租户 READ COMMITTED 事务调用 `activate_webauthn_rp_on`，以预期旧代际推进配置；随后宿主明确选择新配置与新代际。runtime 只有 SELECT/INSERT 权限，不自动推进、回退或刷新代际。配置切换继续撤销凭据、挑战及旧操作证明。HTTP 宿主注入 `RpGeneration` extension，不从浏览器字段构造它。
