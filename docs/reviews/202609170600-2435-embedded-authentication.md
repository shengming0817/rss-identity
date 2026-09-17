# #2435 内嵌认证实施与验收记录

关联：[PR #1028](https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1028)；[实施 ADR](../architecture/adr/202609170001-2435-embedded-authentication.md)。

基线：`fa7019922162158704cc47c6ac7ad36a67c8ae5a`。实现固定 revision A：`62ff53cc49cdc95ce7e0b9de6be071a30a9b56fb`。证据提交 B 只修改 docs，不改变 A 的生产源码、配置或消费者输入。

## 原则与计划落实

- 彻底：只保留 core/postgres/oidc/http-axum，删除中央 contracts/client/Hydra、下游授权、平台租户和 CLI SSO 运行路径。宿主负责管理权限与防锁死，组件不持有替代角色。
- 不向后兼容：HTTP v2、配置格式 3、全新 schema v9；旧 schema/config 被拒绝，不建立兼容入口、升级器或双读。未操作已有数据、密钥、历史候选与旧验收证据。
- 优雅简洁：Authority 提供完整本地认证流程，借用宿主 PgRuntime；Federation 单独装配，HTTP 私有 DTO 只在边界映射。会话可信身份不能通过反序列化构造。
- 原 DAG 已执行：领域 → PG/schema/策略 → HTTP/参考宿主 → T1/T2/独立消费者 → 内置六维审查与修复。实现、测试和修复均由主 agent 执行。

本次保证组件公开能力及最小参考宿主可构建。完整部署/UI/运维及独立产品 T3 由 [#2436](https://dev.azure.com/shengming0923/rss/_workitems/edit/2436) 承接；MDM 接入 [#2437](https://dev.azure.com/shengming0923/rss/_workitems/edit/2437)，Web [#2368](https://dev.azure.com/shengming0923/rss/_workitems/edit/2368)。没有声称这些消费者、生产部署或产品 T3 已完成。

## 实际验证

工作目录为本次隔离 worktree。workspace 构建使用产品仓共享 target；独立消费者各有新 target，不复用 workspace 构建。

| 验证 | 实际结果 |
| --- | --- |
| 新领域能力 TDD | 旧 API 缺 InstanceId/SessionPolicy 等时 RED，实现后 GREEN。 |
| 所有租户 fence 构造检查 | 第二租户缺绑定或 epoch 漂移先 RED，修复后真实 PG GREEN。 |
| 联邦账户不适用改密 | 实际 HTTP 先返回 401 导致 RED，保留领域 reason 后 400/code 且账户无本地密码，GREEN。 |
| settlement 优先级 | 领域原因只在确认回滚时恢复；RollbackFailed/CommitUnknown/Fenced 保持原错误，GREEN。 |
| workspace | cargo test --locked --workspace；61 passed，59 个 provider 用例在此层按设计 ignored，由下列强制 runner 实跑。 |
| 真实 PostgreSQL 17.6 | python3 hack/providers.py pg；53 个 canonical 用例全部通过，无跳过。 |
| 真实 Keycloak HTTPS 联邦 HTTP | python3 hack/providers.py federated；6 个 canonical 用例全部通过。 |
| clippy | cargo clippy --locked --workspace --all-targets --all-features -- -D warnings 通过。 |
| 测试设施与依赖守卫 | Python unittest discover、check_dependencies.py 通过。 |
| 两个固定 Git 独立消费者 | 见下面的逐项执行证据、各自 Cargo.lock 与完整 package ID 闭包。 |

交接 label 之后还必须执行 `make -C <worktree> ci CI_BASE=origin/develop`，它包含以上 workspace/PG/OIDC/federated 及许可证门。该最终命令结果以 PR 交接后追加的运行记录为准，本文件不提前宣称已执行。当前仓库没有 benchmark target，本次不作性能提升声明。

## 独立消费者证据

[report.json](202609170600-2435-consumers/report.json) 记录 A、RSS 固定 revision、provider digest、源码 SHA-256、每个消费者的输入 hash、完整依赖节点及实跑结果。

- [local Cargo.toml](202609170600-2435-consumers/local/Cargo.toml) / [Cargo.lock](202609170600-2435-consumers/local/Cargo.lock) / [deny.toml](202609170600-2435-consumers/local/deny.toml)
- [OIDC Cargo.toml](202609170600-2435-consumers/oidc/Cargo.toml) / [Cargo.lock](202609170600-2435-consumers/oidc/Cargo.lock) / [deny.toml](202609170600-2435-consumers/oidc/deny.toml)

这些 manifest/lock 是已执行消费者的不可变证据，不是文档目录下的新运行工作区。重现时先 checkout A，在仓库与任何 Cargo 配置祖先之外选择不存在的新输出目录：

```sh
python3 hack/check_consumer.py \
  --revision 62ff53cc49cdc95ce7e0b9de6be071a30a9b56fb \
  --output /tmp/identity-2435-fresh-proof
```

runner 从 Git 获取组件，不复制组件源码、不使用跨仓 path/patch。两种消费者独立锁定依赖、目标目录、PostgreSQL；OIDC 使用真实 Keycloak TLS/code/PKCE 浏览器流程。仅复制已提交的公开 API 宿主 fixture。每种消费者执行 fmt、clippy -D warnings、cargo deny（advisories/licenses/sources）和一个完整集成场景。local 闭包排除 openidconnect/reqwest/rsa；OIDC 的既有 RUSTSEC-2023-0071 例外只容许固定公开令牌验证链，跟踪 #2357。

local 覆盖新安装/宿主角色、完整登录、业务认证与被动检查 idle 区别、公开管理、禁用、旋转/退出/恢复、宿主关闭 runtime 和 Router 组合。OIDC 覆盖配置/启用 IdP、真实登录、可信组、停用 provider 的撤销以及本地模式独立性。两个测试均 passed=1/failed=0/ignored=0；不是 reference app 或既有 T3 的替代证明。

## 内置 review 与 findings 处置

按基线 diff 规模由 6 名只读 reviewer 分别检查架构、安全、测试、运维、DX、产品。聚类后共 7 项：P1 2 / P2 5；Cx1 3 / Cx2 3 / Cx3 1。全部 IN_SCOPE 并已修复，无 defer/OOS。

原位置绑定被审提交；当前修复位置及回归测试随各项列出。运维与 DX reviewer 针对各自发现复核 LGTM，DX 对最后的事务错误补充修复再次复核 LGTM。静态复核与主 agent 的实际执行结果分别记录。

### F1 [P2 · Cx1 · 测试] hack/check_consumer.py:51

范围：IN_SCOPE。根因：消费者依赖闭包按 package name 索引，同名不同版本互相覆盖。

证据：Cargo metadata 节点可能同时有多个同名 package；原返回字典会只保留最后一项，实际依赖与证据不一致。

建议与实际修复：改用完整 Cargo package ID，记录 name/version/source/features；增加同名双版本回归。

验证定位：hack/test_consumer.py。处置：已修，commit 025ad7e。

### F2 [P1 · Cx2 · 运维／隔离] crates/identity-postgres/src/lib.rs:128

范围：IN_SCOPE。根因：构造 Authority 仅检查声明租户列表中的第一个 fence。

证据：第二租户未绑定或运行代次过期时仍能完成构造，导致宿主接到不完整的可用实例。

建议与实际修复：在同一总预算内检查所有显式租户的 runtime fence 和 instance；首租户额外校验 schema/权限，后续复用相同 read_bundle 接缝。

验证定位：crates/identity-postgres/tests/embedded.rs::construction_verifies_every_declared_tenant_fence。处置：已修，commit 025ad7e。

### F3 [P2 · Cx1 · 运维／结算] app/identity/src/migration.rs:52

范围：IN_SCOPE。根因：迁移已确认结果可能被后续连接池关闭失败覆盖。

证据：已确认安装成功与清理失败属于不同事实；原返回路径把关闭错误冒充安装失败，并缺少独立关闭时限。

建议与实际修复：冻结安装结果，关闭使用五秒预算；关闭未确认输出封闭诊断，始终保留原安装结果，包括未知提交。

验证定位：app/identity/src/migration.rs::tests。处置：已修，commit 025ad7e。

### F4 [P2 · Cx2 · 运维／诊断] app/identity/src/lifecycle.rs:176

范围：IN_SCOPE。根因：参考宿主丢弃 HttpFailure 诊断扩展。

证据：多个存储/结算错误统一输出 503，但服务端没有保留可区分的安全分类。

建议与实际修复：响应 middleware 只消费封闭 HttpFailure 枚举写诊断；不记录请求、cookie、body 或秘密，不改响应语义。

验证定位：app/identity/src/lifecycle.rs::tests。处置：已修，commit 025ad7e。

### F5 [P2 · Cx2 · DX／产品] docs/guides/embedding.md:11

范围：IN_SCOPE。根因：文档与独立宿主把被动 inspect_session 用作活动业务认证。

证据：被动检查不会延长 idle，持续业务访问仍可能过早失效；原 host.rs::actor 复现此调用。

建议与实际修复：活动请求先执行宿主请求/CSRF 策略，再 authenticate_session；被动查询使用 inspect_session；消费者验证 idle 延长且 absolute 不变。

验证定位：tests/consumers/host.rs:182; tests/consumers/local/lib.rs:17。处置：已修，commit 025ad7e。

### F6 [P1 · Cx3 · DX／架构] crates/identity-http-axum/src/provider_management.rs:94

范围：IN_SCOPE。根因：HTTP 直接序列化领域结果、复用持久化输入模型，违背私有 DTO 边界。

证据：ProviderView/ConnectionReport/AccountPage/SessionPage 等直接进入 Json；PG 账户 ID/cursor 为 String，wire 需求反向污染领域。

建议与实际修复：HTTP 私有 DTO 显式映射账户、会话、provider、登录选项与诊断；恢复 typed ID，移除仅为 HTTP 存在的 Serialize，保留必要持久化 codec。

验证定位：crates/identity-http-axum/src/dto.rs; crates/identity-postgres/src/operations.rs; crates/identity-postgres/src/sessions.rs; crates/identity-core/src/federation.rs。处置：已修，commit 025ad7e。

三级方案种子：最小仅包 Provider DTO；彻底完成所有当前 HTTP 边界并恢复领域类型；重构引入公共 wire 包。选定彻底方案，范围属于已批准架构，公共 wire 包会重新引入被本次删除的耦合。

批量处置请求 Q-1f0bd941bf7c47bc8e52293601029ebc 经飞书/Codex 发出，120 秒后 expired、answers=[]。按本次用户 AGENTS 的“两分钟无响应，按推荐选项继续”授权执行当前 PR 修复；没有把超时记为用户主动回答。

### F7 [P2 · Cx1 · HTTP 语义] crates/identity-http-axum/src/management.rs:31

范围：IN_SCOPE。根因：联邦专用账户的本地改密拒绝未保留准确领域错误。

证据：原 management 错误表缺少 RuleRejected(Rejected)；补充实际 HTTP 回归又发现 transaction.rs::domain_result 将其压平为 invalid_credential（401）。

建议与实际修复：确认回滚后保留领域 reason，管理适配层映射为 400 malformed_request；未知提交/回滚失败/fenced 仍优先。

验证定位：crates/identity-http-axum/tests/management_http.rs:755; crates/identity-postgres/src/transaction.rs:401。处置：已修，commit 025ad7e + 62ff53c。
