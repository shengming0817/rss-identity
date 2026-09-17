# 嵌入认证组件

宿主以同一仓库 URL、同一完整 Git SHA 消费四个公开能力包，提交自己的 Cargo.lock；不引用本机跨仓 path，不依赖参考应用。可执行样例在 [独立消费者](../../tests/consumers/)；[验证入口](../../hack/check_consumer.py) 将两种宿主放在仓库祖先之外，各自解析依赖、编译和运行真实 provider 测试。

## 本地认证

1. 宿主提供已有、绑定 StorageIdentity/ExecutionBinding 的 `Arc<PgRuntime>`，共享有界 `Arc<PasswordKdf>`，以及显式 `InstanceId`、租户列表、`SessionPolicy` 和事件预算。Identity 不创建、更换、关闭宿主连接池，不自动发现租户。
2. 宿主预建数据库角色，数据库 owner 先安装 RSS 消息 schema，再调用 `install(connection, instance)` 和 `grant_profile(connection, role, profile)`。Identity 只接受全新 v9 schema；v8/旧配置失败关闭，不升级、不双读。结构签名和有效权限检查独立于角色名称。
3. Maintenance authority 仅用于一次性 `initialize` 与 `recover_local_password`。恢复只更换本地密码并推进 epoch，不自动启用账户或成员、不授予宿主权限。
4. `Authority::connect_runtime` 必须提供 `ManagementPolicy`。调用 `login_local` 完成密码验证及原子签发；外部不能构造 AuthenticationCandidate 或调用底层签发函数。
5. 每个业务请求调用 `inspect_session` 获得不可反序列化、不可克隆的 `AuthenticatedSession`。不要将前端 JSON 当作认证证明，也不要跨请求缓存该值。

```rust,ignore
let authority = Authority::connect_runtime(
    runtime.clone(), kdf, config, host_policy, deadline,
).await?;
let issued = authority.login_local(
    tenant, login, password, source, None, request_deadline,
).await?;
let actor = authority.inspect_session(tenant, session_secret, request_deadline).await?;
let account = actor.account();
let groups = actor.groups()?;
```

`SessionPolicy` 显式指定 idle/absolute 秒数，须为正且 idle ≤ absolute。参考宿主为 900/14400。会话持久化原始策略，refresh 旋转凭据并保留 auth_time、absolute deadline 和组快照期限；`reauthenticate_local` 绑定当前账户并重新认证，不能切换为请求指定的其他账户。撤销、密码变化、账户或成员禁用在下一次权威读取时生效。数据库不可用时拒绝认证；提交不确定不释放成功凭据。

## 宿主管理策略

每次管理操作均在事务内重新检查当前会话、实例、租户、账户、成员和 epoch，再调用宿主 `ManagementPolicy::authorize`。Context 只能由组件生成，包含 actor、target、操作、当前 assurance 和当前组投影；策略是有界同步回调，不能阻塞 I/O。宿主返回拒绝或 `None` / `Recent(Duration)` / `RecentMfa(Duration)`，组件落实重新认证要求。

Identity 不存储 administrator、emergency 或平台角色。宿主维护管理角色、防锁死和授权映射，并负责其并发一致性。参考宿主用显式 bootstrap AccountKey 管理，禁止其自我禁用/移除成员，并要求 300 秒内重新认证；这只是参考产品策略。

`actor.groups()?` 返回 `VerifiedGroups::Available`、`Unavailable` 或 `Expired`。Available 包装器只能借自本次认证结果；每次访问重新检查剩余有效期，不能由请求 JSON 构造。空组、缺失组、过期组语义不同。组是有来源和期限的认证事实，资源授权由宿主决定。观察时间取已验签 ID token 的 iat，期限为 min(iat + 1–300 秒策略, exp)；普通刷新不延长。provider/账户/session 撤销使整次验证失败，组独立过期只移除组事实。

## 可选 OIDC

`Federation` 单独接收 Authority、UpstreamOidc、StateSigner、CredentialKeys、GroupFactsMaxAge、固定 HTTPS callback 和 return-target 白名单。`rss-identity-oidc::HttpOidc` 是具体上游适配器；本地消费者闭包中没有它、openidconnect 或 reqwest。上游 client_id 是 IdP 协议配置，不是中央服务客户端注册。

callback 必须为 `<宿主 origin>/api/v2/oidc/callback`。begin/complete 持久化并原子消费 state、nonce、PKCE 和浏览器绑定；JIT、显式关联、step-up、凭据加密和组来源验证保持单一入口。禁用 provider 推进撤销 epoch，重新启用不复活旧会话。

```rust,ignore
let routes = rss_identity_http_axum::router(authority, http.clone())?
    .merge(rss_identity_http_axum::federated_router(federation, http)?);
```

本地 Router 和联邦 Router 分别挂载；宿主拥有 TLS listener、可信代理边界、连接来源、日志脱敏和 graceful drain。HTTP DTO 是适配器私有实现。不要用通用同截止点 timeout 丢弃数据库写 future；让组件/RSS 返回精确 settlement 分类。

安全事件版本为 account v3、federation v2、session v1。事件不含密码、cookie、code、verifier、上游 token；消费者须按新事件 schema 更新，旧事件定义不再作为活动协议。
