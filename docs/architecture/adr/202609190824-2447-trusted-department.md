# #2447：可选可信部门事实

状态：已实现于本变更；实际验证结果以对应 PR 的固定 revision 记录为准。

## 原则与边界

彻底：部门从已验签 ID Token 进入唯一 AuthenticationFacts codec，覆盖登录、step-up、来源重新认证、会话读取与管理 Context。租户/provider 配置版本、epoch、账户与 session 撤销复用既有事务边界。

不向后兼容：只接受 fresh schema v10 与 auth_facts format v2；部门持久状态必填，拒绝旧库、旧事实、缺字段和未知分支，无旧格式转换、双读、默认事实或旧输出投影。HTTP v2 新增可选配置，未启用输出 department:null；参考宿主配置结构仍是 v3。

优雅简洁：每个 provider 的可选 DepartmentClaim 同时持有 claim 与 1–300 秒 maxAgeSeconds，受控构造/反序列化拒绝不完整配置。不增加全局部门策略、crate、feature、目录表、通用 claims 框架或授权平台；共享来源、不可用原因和观察时间规则由中性 `identity-core::facts` 唯一拥有；组与部门直接依赖 `FactSource`、`FactUnavailableReason`，旧 groups 类型路径和 fact_time 模块删除，无 alias/re-export。共用已有数据库采样。内部快照和请求事实以 Box 持有，避免扩大嵌套异步状态体。

Identity 提供事实，宿主持有资源权限。部门不编码成安全组；MDM 规则、用户组、权限申请审批、Web、组织树和目录同步不属于本项。部门可选，不阻塞 #2363 的安全组授权路径。

## 输入与配置

provider HTTP settings 的 claims.department 为 null/省略（禁用）或 {"claim":"department_id","maxAgeSeconds":120}。期限无默认；名称为 1–64 字节 ASCII 字母数字/下划线，禁止标准身份字段及现有 email/groups 映射键。

部门是企业维护的单个受控编码：1–256 UTF-8 字节、区分大小写，无首尾空白/控制字符，不 trim、不折叠、不推断。企业保证在实例/tenant/provider 来源范围内唯一稳定；Identity 不验证企业目录的稳定性，不提供显示名、改名映射或同名隔离补救。

已验签 claim 的字符串表示部门 ID；显式 JSON null 才断言无部门。缺键是 ClaimMissing，未配置是 NotConfigured，本地账户是 LocalIdentity；空串及其它 JSON 类型拒绝认证。普通 Keycloak 属性 mapper 省略空值，因此产生 ClaimMissing；不能当作明确无部门。签名 token fixture 覆盖 null，真实 Keycloak 覆盖编码与缺失；连接测试仅证明 discovery/JWKS 接缝，不能证明用户 claim。

更新部门 claim 或 TTL 走现有完整 provider update（含 expectedVersion 和重新提交 credentials），推进配置/凭据版本与撤销 epoch，旧会话和在途流程失败；无独立 JSON/TTL 更新旁路。

## 事实、来源与期限

上游 adapter 验证 issuer/audience/signature/expiry/nonce 后映射；宿主注入的 UpstreamOidc 是受信实现，浏览器不能提交它的输出。PG 仅从精确复核后的同版本 provider settings 取 TTL。登录/step-up 及 link source 重新认证是两个采集入口；link target 只建立关联，当前 session 仍继承 source 快照。

观察时间取 signed iat，截止固定 min(iat + maxAgeSeconds, exp)，允许最多 30 秒未来偏差；偏差内未来事实保持 NotYetValid，下一次权威读取才重新投影。已有过期事实不撤销基础身份，也不重新采集。refresh、活动请求、重建组件及本地重认证均不能延长旧部门快照。

明确无部门使用带 snapshot ID/时间的闭集持久 assignment，与字段缺失分开；它也会过期。会话 getter、管理 Context 及保留 wrapper 共享私有 DepartmentFacts。每次 value() 检查 proof 与 snapshot 截止，proof 到期优先。查询发送前的 Instant 和锁后数据库微秒采样扣除所有查询/返回耗时；时钟信任边界沿用 #2438。

wrapper 的实例、AccountKey、provider、issuer、配置版本由同一权威会话派生，不新增可写来源记录。FactSource 字段私有，构造与反序列化共用非 nil provider/合法 issuer 校验；该类型只验证元数据结构，不自行证明上游认证。公开值本身不是认证证明；TrustedDepartment 无公开构造、Clone 或 Deserialize。复制出的值、借出的原始引用和已产生的业务效果由宿主负责；新请求和管理事务重新检查权威状态。

callback 的内部错误先生成含 HttpFailure 的响应，再通过唯一的 callback_error_response 转为安全重定向；handler 与请求 boundary 共用 Axum Extensions 响应组合，保留宿主诊断及其它扩展，丢弃内部错误 body/headers。诊断仅在进程内传递，不进入浏览器重定向 URL 或 body。

## 验证与来源

T1 覆盖配置/输入、签名验证、持久闭集、期限及不可伪造边界；T2 覆盖真实 PG/Keycloak、隔离撤销、来源关联和原子提交。独立 local/OIDC consumer 使用固定完整 Git SHA、各自 lock/target。新增数据遵守 auth_facts 32 KiB 总预算；install/probe/rekey/backup 一并切换 v10。

组件证明不表示 MDM 已接入、registry 已发布或产品 T3 完成。运行证据、未覆盖项及 SHA/lock/schema 绑定保存在 PR。

来源见 [#2447 来源索引](../../reference/sources.md#2447-部门事实)，复用已选 openidconnect 4.0.1 与 Keycloak 26.7.3，不复制上游实现。
