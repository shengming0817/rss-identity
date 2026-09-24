# #2438：嵌入式可信组访问与固定期限

状态：已实施，依赖 #2435 嵌入架构。MDM 业务映射由消费产品持有。

## 决定与原则复核

- 彻底：会话 getter、保留的组 wrapper 和管理 Context 三条路径共用私有 `GroupFacts`；每次读值检查请求证明与 signed snapshot 的独立截止点。锁后采样同时生成整数秒与微秒期限，查询开始前的 Instant 计入全部后续延迟。
- 不向后兼容：`groups()` 与 `TrustedGroups::values()` 返回闭集 `GroupAccessError`；删除管理 Context 的原始 Groups 出口，不提供 unchecked getter、旧 alias 或 Deserialize。该决定只改变可信读取，不引入持久化或 HTTP 迁移。
- 优雅简洁：复用 core 的唯一 Groups 模型、既有事务与既有 loopback fixture 入口；只增加私有时间样本与借用视图，不建立时钟框架、权限平台或另一套公开组模型。

数据库样本采用 `floor(epoch(clock_timestamp()) * 1_000_000)`；有效期为 `query_start + max(0, expires_seconds*1_000_000 - sampled_micros - 1)` 微秒。checked 宽整数和 Instant 转换拒绝溢出。额外减去 1 微秒防止截断延长有效期；网络延迟只缩短预算。宿主需维持可信数据库时钟，本机制不解决数据库墙钟本身的偏差。

证明到期优先报 `ProofExpired`。快照到期保留基础身份，新视图为 Expired，已保留 wrapper 读值为 SnapshotExpired。未来观察保持 NotYetValid，到下次请求才重新投影。管理策略使用当前数据库事实，并受原始传入证明上界约束。复制出的值、借出的原始引用与已经产生的业务授权效果由宿主负责，本组件不提供事后撤回机制。

## 事务截止与适用范围

认证与显式 refresh 在最后一次会话写入后复核单调期限；跨期结果回滚凭据、续期和事件，不签发成功凭据。请求内保留 wrapper 的读值仍须检查两种期限，元数据和先前读取不能替代当前检查。

组来自签名观察，不保证 IdP 变更实时推送，也不回收宿主已复制的值或已产生的业务效果。资源授权与组合撤权承诺由消费产品持有。此决定不引入时钟框架、目录同步或成功身份缓存。

来源见[截止点与时钟](../../reference/sources.md#2438-截止点与嵌入式验证)。ASP.NET 的 claims 构造与 stamp 周期复核不是企业组刷新时效；本组件采用自己的来源、期限和每请求权威复核边界。
