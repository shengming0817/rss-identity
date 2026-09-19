# #2438：嵌入式可信组访问与固定期限

状态：已实施，依赖 #2435 嵌入架构。MDM 业务映射由消费产品持有。

## 决定与原则复核

- 彻底：会话 getter、保留的组 wrapper 和管理 Context 三条路径共用私有 `GroupFacts`；每次读值检查请求证明与 signed snapshot 的独立截止点。锁后采样同时生成整数秒与微秒期限，查询开始前的 Instant 计入全部后续延迟。
- 不向后兼容：`groups()` 与 `TrustedGroups::values()` 返回闭集 `GroupAccessError`；删除管理 Context 的原始 Groups 出口，不提供 unchecked getter、旧 alias 或 Deserialize。保持 schema v9/HTTP v2，因为本次没有持久化或 wire 变化。
- 优雅简洁：复用 core 的唯一 Groups 模型、既有事务与既有 loopback fixture 入口；只增加私有时间样本与借用视图，不建立时钟框架、权限平台或另一套公开组模型。

数据库样本采用 `floor(epoch(clock_timestamp()) * 1_000_000)`；有效期为 `query_start + max(0, expires_seconds*1_000_000 - sampled_micros - 1)` 微秒。checked 宽整数和 Instant 转换拒绝溢出。额外减去 1 微秒防止截断延长有效期；网络延迟只缩短预算。宿主需维持可信数据库时钟，本机制不解决数据库墙钟本身的偏差。

证明到期优先报 `ProofExpired`。快照到期保留基础身份，新视图为 Expired，已保留 wrapper 读值为 SnapshotExpired。未来观察保持 NotYetValid，到下次请求才重新投影。管理策略使用当前数据库事实，并受原始传入证明上界约束。复制出的值、借出的原始引用与已经产生的业务授权效果由宿主负责，本组件不提供事后撤回机制。

## 事务截止与测试清理

认证与显式 refresh 共用结束前 `checked_expiry`，截止点取持久会话期限与入口操作预算之最小值；refresh 在 token UPDATE 返回后、构造事件和签发结果前拒绝跨期结果，原子回滚 idle/token 与事件。真实 PG 的 idle UPDATE 和 token UPDATE 延迟分别覆盖 idle 与 absolute 到期。

共享 Keycloak 测试在修改前保存成员关系，捕获测试主体普通错误和 unwind panic，显式 await 恢复并读回原值后才传播原失败；恢复与主体同时失败时保留主体错误并附恢复诊断。Docker pause guard 显式检查 unpause，失败保留清理责任，Drop 只作有界兜底并输出受控状态诊断。测试验证 panic、普通错误、原本非成员、失败 unpause 与真实容器 unwind 恢复。进程被杀或 abort 时由外层 disposable provider runner 销毁容器，不承诺析构能恢复被终止的进程。

验证范围为事务行为和真实 provider 的 T2，不替代产品 T3。producer T2 覆盖完整生命周期，独立消费者验证公开 API 与构建来源。

## 消费与范围

独立 local/OIDC workspace 使用同一固定完整 Git SHA，各自 lock/target，位于所有仓库祖先之外。OIDC 默认模式验证生产拒绝 loopback；显式 loopback-fixture 模式复用公开测试入口执行真实 TLS Keycloak。报告分别绑定 metadata 和 compiler features。变更有效实现/fixture/runner 输入须重新固定和验证。

不恢复中央 client/Hydra，不修改 MDM 资源授权，不加入目录同步、生产 egress 放宽、旧库升级或产品 T3。

来源：PostgreSQL 17 `clock_timestamp` 文档与 Rust `std::time::Instant::checked_add` 源码，定位见 [来源索引](../../reference/sources.md)。

## #2435 差异与 ASP 对照

| 项目 | 最新基线结论 | 本次处置 |
| --- | --- | --- |
| core 唯一组模型、签名采集、来源/epoch、TTL 1–300 秒、未来偏差上限 30 秒 | 已交付；沿用 `auth_facts` / `federation_storage` / OIDC verifier | 保持语义，不复制模型 |
| 实例/租户/主体/会话隔离、组不等于 MDM 授权 | 已交付 | 沿用公开 facade 与原有 T1/T2 |
| 请求内保留 wrapper 的跨期读值 | 确认偏差，原 getter 不检查期限 | 统一 checked values |
| SQL 查询后才设单调锚点、整秒截断 | 确认偏差，可延长快照窗口 | 查询前锚点与微秒样本 |
| 管理 Context 的原始 Groups | 确认偏差，无访问时检查 | 与会话共用视图 |
| 独立 OIDC fixture 仍走生产 loopback 构造 | 生产 egress 收紧后失效 | 显式测试 feature；生产拒绝独立证明 |
| 历史真实撤组/多 session/断网用例随中央协议移除 | 有效行为证明缺失 | 用当前嵌入 API 恢复 producer T2 |

ASP.NET Core Identity v10.0.0 的 `UserClaimsPrincipalFactory` 通过 UserManager/RoleManager 构造用户、角色和 claims；`SecurityStampValidatorOptions.ValidationInterval` 默认 30 分钟。这是框架的身份构造和 stamp 复查机制，不是企业 IdP 组刷新时效。RSS 的签名来源绑定、1–300 秒 snapshot、最多 30 秒未来偏差与每次请求数据库复核是自己的保证；组到设备范围/危险动作/角色映射及组合撤权承诺属于消费产品。不会将 ASP 的默认角色能力引入组件，也不宣称实时撤组。
