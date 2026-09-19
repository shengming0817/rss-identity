# 嵌入认证组件

宿主以同一仓库 URL、同一完整 Git SHA 消费四个公开能力包，提交自己的 Cargo.lock；不引用本机跨仓 path，不依赖参考应用。可执行样例在 [独立消费者](../../tests/consumers/)；[验证入口](../../hack/check_consumer.py) 将两种宿主放在仓库祖先之外，各自解析依赖、编译和运行真实 provider 测试。

## 本地认证

1. 宿主提供已有、绑定 StorageIdentity/ExecutionBinding 的 `Arc<PgRuntime>`，共享有界 `Arc<PasswordKdf>`，以及显式 `InstanceId`、租户列表、`SessionPolicy` 和事件预算。Identity 不创建、更换、关闭宿主连接池，不自动发现租户。
2. 宿主预建数据库角色，数据库 owner 先安装 RSS 消息 schema，再调用 `install(connection, instance)` 和 `grant_profile(connection, role, profile)`。Identity 只接受全新 v9 schema；v8/旧配置失败关闭，不升级、不双读。结构签名和有效权限检查独立于角色名称。提交安装事务前以实际目标角色调用 `verify_profile(connection, profile, instance)`；参考安装器用 `SET LOCAL ROLE` 对 runtime/maintenance 都执行同一检查，失败整体回滚。
   RSS 安装必须使用 pin 对应的完整 `MIGRATION_SQL`。runtime/maintenance 仅持有 Outbox SELECT 和公开 `prepare_outbox_partitions(jsonb)` / `append_outbox(bytea,jsonb)` EXECUTE，无直接 INSERT、分区表或 sequence 权限。安全事件保持 unordered，不声明分区；RSS 的运行准入拒绝旧权限或不匹配 schema。
3. Maintenance authority 仅用于一次性 `initialize` 与 `recover_local_password`。恢复只更换本地密码并推进 epoch，不自动启用账户或成员、不授予宿主权限。
4. `Authority::connect_runtime` 必须提供 `ManagementPolicy`。调用 `login_local` 完成密码验证及原子签发；外部不能构造 AuthenticationCandidate 或调用底层签发函数。
5. 每个宿主认定为用户活动的业务请求调用 `authenticate_session` 获得不可反序列化、不可克隆的 `AuthenticatedSession`。不要将前端 JSON 当作认证证明，也不要跨请求缓存该值。

```rust,ignore
let authority = Authority::connect_runtime(
    runtime.clone(), kdf, config, host_policy, deadline,
).await?;
let issued = authority.login_local(
    tenant, login, password, source, None, request_deadline,
).await?;
let actor = authority.authenticate_session(tenant, session_secret, request_deadline).await?;
let account = actor.account();
let groups = actor.groups()?;
```

`SessionPolicy` 显式指定 idle/absolute 秒数，须为正且 idle ≤ absolute。参考宿主为 900/14400。会话持久化原始策略，refresh 旋转凭据并保留 auth_time、absolute deadline 和组快照期限；`reauthenticate_local` 绑定当前账户并重新认证，不能切换为请求指定的其他账户。撤销、密码变化、账户或成员禁用在下一次权威读取时生效。数据库不可用时拒绝认证；提交不确定不释放成功凭据。

## 宿主管理策略

每次管理操作均在事务内重新检查当前会话、实例、租户、账户、成员和 epoch，再调用宿主 `ManagementPolicy::authorize`。Context 只能由组件生成，包含 actor、target、操作、当前 assurance 和当前组投影；策略是有界同步回调，不能阻塞 I/O。宿主返回拒绝或 `None` / `Recent(Duration)` / `RecentMfa(Duration)`，组件落实重新认证要求。

Identity 不存储 administrator、emergency 或平台角色。宿主维护管理角色、防锁死和授权映射，并负责其并发一致性。参考宿主的 `bootstrapAccounts` 必须恰好覆盖配置中的每个租户，各有一个 AccountKey，禁止重复、遗漏和跨租户配置。每个管理员只能管理本租户，禁止其自我禁用/移除成员，并要求 300 秒内重新认证。普通账户可调用 `ChangeOwnPassword`，也必须经过同一管理策略并满足其重新认证要求；当前密码证明不替代宿主授权。

`actor.groups()?` 和 `ManagementContext::groups()?` 共用检查路径，返回 `VerifiedGroups::Available`、`Unavailable` 或 `Expired`。Available 包装器只能借自本次认证结果；`groups.values()?` 每次读取重新检查请求证明与快照期限，不能由请求 JSON 构造。空组、缺失组、过期组语义不同。组是有来源和期限的认证事实，资源授权由宿主决定。观察时间取已验签 ID token 的 iat，期限为 min(iat + 1–300 秒策略, exp)；普通刷新不延长。provider/账户/session 撤销使整次验证失败，组独立过期只移除组事实。

`GroupAccessError::ProofExpired` 表示请求证明到期；已借出的组对象也不能继续读取值。快照独立到期时，新的 `groups()` 返回 `Expired`，保留对象的 `values()` 返回 `GroupAccessError::SnapshotExpired`；两者同时到期优先返回 `ProofExpired`。元数据仅描述来源，不能替代本次 `values()` 检查。宿主已复制的值、引用和已作出的授权决定不会被自动撤回；不要跨请求缓存。

```rust,ignore
match actor.groups()? {
    VerifiedGroups::Available(groups) => {
        product_mapping.check(actor.account(), groups.source(), groups.values()?)?;
    }
    VerifiedGroups::Unavailable(_) | VerifiedGroups::Expired => return Err(GroupsRequired),
}
```

期限从锁与 provider 复核后的数据库微秒采样推导，单调时钟锚点在查询发送前；查询、续期和事务返回耗时均消耗预算。管理策略还受传入证明的原期限约束。`NotYetValid` 在本次证明内保持不可用，需要下次权威读取重新投影。公开 API 直接替换旧 unchecked getter，无兼容别名，schema v9/HTTP v2 不变。

## 可选 OIDC

`Federation` 单独接收 Authority、UpstreamOidc、StateSigner、CredentialKeys、GroupFactsMaxAge、固定 HTTPS callback 和 return-target 白名单。`rss-identity-oidc::HttpOidc` 是具体上游适配器；本地消费者闭包中没有它、openidconnect 或 reqwest。上游 client_id 是 IdP 协议配置，不是中央服务客户端注册。

callback 必须为 `<宿主 origin>/api/v2/oidc/callback`。begin/complete 持久化并原子消费 state、nonce、PKCE 和浏览器绑定；JIT、显式关联、step-up、凭据加密和组来源验证保持单一入口。禁用 provider 推进撤销 epoch，重新启用不复活旧会话。

```rust,ignore
let routes = rss_identity_http_axum::router(authority, http.clone())?
    .merge(rss_identity_http_axum::federated_router(federation, http)?);
```

本地 Router 和联邦 Router 分别挂载；宿主拥有 TLS listener、可信代理边界、连接来源、日志脱敏和 graceful drain。HTTP DTO 是适配器私有实现。不要用通用同截止点 timeout 丢弃数据库写 future；让组件/RSS 返回精确 settlement 分类。

宿主必须在进入路由前注入 `ClientAddress`。仅有 Axum `ConnectInfo` 不会自动转换，缺少此扩展的登录请求返回 503。直接终止 TLS 的宿主可使用下面的中间件，并让 accepted listener 通过 `into_make_service_with_connect_info::<SocketAddr>()` 提供真实 peer：

```rust,ignore
async fn client_address(
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    request.extensions_mut().insert(rss_identity_http_axum::ClientAddress(peer.ip()));
    next.run(request).await
}
let routes = routes.layer(axum::middleware::from_fn(client_address));
```

该中间件忽略请求中的 forwarded headers。反向代理部署须由宿主先验证真实 peer 是否为配置的可信网关，再读取其覆盖的来源头；参考宿主的 transport 模块实现该边界。[独立本地消费者](../../tests/consumers/local/lib.rs) 实际发送登录请求，验证缺少扩展的失败、正确注入后的 cookie 和 camelCase JSON。

宿主诊断以 `AuthorityError::Configuration` 区分无效配置，以 `InvalidInput` 表示操作输入错误，以 `DeadlineElapsed` 表示事务开始前截止期耗尽。已经进入数据库事务的错误仍保留 `NotStarted` / `RolledBack` / `RollbackFailed` / `CommitUnknown` 及其原因，禁止据 503 推断是否可重试。HTTP 对输入错误返回 400，对配置/截止期错误返回脱敏的 503；完整分类仅通过响应扩展 `HttpFailure` 提供给宿主。

安全事件版本为 account v3、federation v2、session v1。事件不含密码、cookie、code、verifier、上游 token；消费者须按新事件 schema 更新，旧事件定义不再作为活动协议。

`authenticate_session` 验证并延长 idle，不改变原 absolute deadline；宿主须先实施请求/CSRF 与用户活动策略，不能让后台心跳无限续期。`inspect_session` 只读验证，用于登录替换前检查、浏览器 GET session 和不应续期的被动查询。HTTP POST refresh 显式续期并旋转凭据；两种验证入口都重新检查权威状态。认证与 refresh 在最后一次会话查询/写入后共用单调期限复核，取会话期限与调用预算的较早值；数据库等待已耗尽期限时拒绝并回滚续期、凭据轮换与安全事件，不签发成功 cookie。

HTTP 宿主资源可调用 `rss_identity_http_axum::inspect_session(&authority, tenant, headers, deadline)`，返回 `AuthenticatedSession` 或已安全投影的 HTTP response，不暴露 bearer/CSRF、不延长 idle。宿主仍持有资源授权、成功响应 no-store 与预算；该只读入口不代替写请求 CSRF。

部署 owner 轮换凭据时调用 `CredentialKeys::reencrypt_tenant(&mut tx, instance, tenant)`；组件持有 guard、AAD、密文和 SQL，宿主先绑定 storage fence 与 SQL 预算，最后提交或回滚。逐值重加密不是公开接口，runtime/maintenance 角色不会因轮换扩权。


固定 Git 消费验证：`make test-consumers IDENTITY_CONSUMER_REVISION=<完整 SHA> IDENTITY_CONSUMER_OUTPUT=<仓库祖先之外的新目录>`。OIDC 独立 workspace 默认构建不启用 `test-support`，执行生产 `HttpOidc::new` 拒绝 loopback 的用例；显式 `loopback-fixture` 仅映射依赖的 `rss-identity-oidc/test-support`，通过 `for_loopback_test` 跑真实 PG＋Keycloak。报告分别保存两种模式的解析闭包与实际 compiler features。fixture 成功不表示生产出口已连通，生产出口限制保持不变。
