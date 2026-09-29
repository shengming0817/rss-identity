# 嵌入认证组件

宿主通过公开能力包装配本地认证和可选 OIDC，不依赖参考应用。每个来源仓库的依赖使用固定 URL 与完整 Git revision，由宿主 manifest/lock 持有；不使用本机跨仓 path。实际装配示例见 [参考宿主](../../app/identity/src/assembly.rs)，接口以各能力的 Rust API 为准。

## 本地认证与安装

1. 宿主提供已绑定 storage/fence 的 `Arc<PgRuntime>`、共享有界 KDF、显式实例与租户、会话策略、事件预算和管理策略。Identity 不创建、更换或关闭宿主池，不自动发现租户。
2. 数据库 owner 先安装所选 RSS 版本的完整消息 migration，再安装 Identity schema 并授予 runtime/maintenance profile。仅接受当前全新安装；在提交安装事务前，以实际目标角色验证有效权限和结构。入口见 [schema owner](../../crates/identity-postgres/src/schema.rs)；生产迁移执行属于宿主。
3. 维护身份只用于初始化和本地密码恢复，凭据不注入日常服务。恢复推进失效代际，保留账户/成员启停状态，不授予宿主角色。
4. runtime Authority 必须接收宿主 ManagementPolicy。密码校验和凭据签发经单一登录入口完成；浏览器 JSON、普通账户快照或上游结构值不能构造可信会话。

业务变更与安全事件使用同一 PG 事务。角色有效权限包含继承/PUBLIC/列权限检查；角色名不能替代权限证明。RSS migration 与授权接缝以实际 pin 对应源码为准，不能只复制部分 SQL。

## 请求与管理授权

HTTP 宿主统一通过 `authenticate_request` 取得当前请求的 AuthenticatedSession，再执行产品资源授权。Active 请求检查 cookie、同源、请求标记和 CSRF 后续期；Passive 只读验证，不延长 idle。会话保留签发时的 idle/absolute 策略，宿主配置变更只影响新会话；refresh 旋转凭据但不延长绝对期限，重新认证只能绑定当前主体。不要跨请求缓存成功身份、组或部门事实。

每次管理事务重新核对实例、租户、账户、成员、会话和失效代际后调用宿主 ManagementPolicy。策略是有界同步回调，不执行阻塞 I/O；组件落实策略要求的重新认证/MFA。宿主持有管理角色、防锁死和并发一致性，Identity 不保存 administrator/emergency/platform 角色。

参考宿主为每个配置租户指定唯一 bootstrap 账户，并阻止其自我禁用；这是示范宿主策略，不成为其它产品的默认授权。密码恢复与 IdP 故障都不能自动提升权限或复活禁用状态。

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

OIDC 使用 Code/PKCE、state/nonce 和浏览器绑定，登录事务原子单次消费；邮箱不是自动关联依据。显式关联与 step-up 绑定当前主体，provider 配置变化使旧流程失效。唯一 callback 是宿主 origin 下的 `/api/v2/oidc/callback`，回跳只接受宿主白名单键。

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

不要用通用 timeout 丢弃数据库写 future。组件/RSS 持有有界事务结算；CommitUnknown、RollbackFailed 等内部结果保留在 HttpFailure 中，不能据 503 推断可安全重试。对外错误、cookie 与 CSRF 规则见 [HTTP 接入](../architecture/identity-wire-v2.md)。安全事件 schema 由 postgres 持有，不含凭据或上游 token。

密钥重加密复用组件的租户事务接口与既有 storage fence，宿主最终提交或回滚；维护角色不因此扩权。参考部署的操作顺序见[恢复与轮换](../deployment/recovery.md)。

## 认证审计交付

`rss_identity_postgres::audit::AuditDelivery` 持有 Identity 事件语义。宿主注入同库的 worker `Arc<PgRuntime>`、`Arc<PgAudit>`、真实实例与租户绑定和 delivery budget，调用有界 `run_once`。异步构造在一个有界预算内检查已有 dead-letter，不创建任务或接管连接关闭；构造和运行统一返回 `AuditDeliveryError`，宿主只对 `is_retryable()` 为真的错误重试。权限通过公开 `audit::grant_worker` / `verify_worker` 接缝装配，不复制参考 app 的 SQL。参考实现见 [审计装配](../../app/identity/src/audit.rs)。

producer 保持 `connect_producer`；worker 使用独立角色的 `PgRuntime::connect_consumer`，Audit 开启 `messaging`。worker 不读取 Identity 私有表，也不能直接修改 Audit/Outbox；schema owner 和实际权限必须通过 startup probe。宿主负责保证来源实例对应当前 Identity 数据库，不接受请求指定的 source。

当前只接收 account v3、session v1、federation v2 的精确 schema，映射为 Audit V1。账户主体来自 actor，维护事件标识维护主体；会话主体来自 principal，all_revoked 的对象是账户会话集合；联合身份按 action 区分 provider 和认证主体。provider_test_failed 为 Failed，其余已提交事件为 Succeeded。UUID 会话坐标不是 bearer secret。输出只含稳定坐标、epoch、状态、配置版本和封闭诊断码。

业务与安全事件先原子提交到 Outbox。独立 worker 在另一事务内同时提交 Audit 和 Inbox receipt，之后才确认源 Outbox。发生时间来自原事件，落录时间来自该 PG 事务；乱序不改变原事件含义。**认证成功及 Outbox 已提交均不表示 Audit 已落库**。查询授权仍由宿主持有。

审计 worker 的日志保留发布、结算、重试和故障等闭合事件；成功 claim 的耗时 tick 不写入日志，避免空轮询制造活动记录。该日志选择不改变底层 RSS observation、投递或 readiness 语义。
