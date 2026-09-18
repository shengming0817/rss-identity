# #2438 可信组到期修复与独立消费证明

关联 [PR #1034](https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1034)。基线 `98bf29ec4b1efb454ccf9f081dbc469c64e9b5ca`；实现与消费者输入固定 A：`24467273bceca491dca3e1879308ac0cc07a0f8f`。本证据提交仅变更 docs；源码、fixture、runner、部署输入的 SHA-256 均与 A 相同。原则、差异分类与 ASP 对照见 [ADR](../architecture/adr/202609180001-2438-trusted-group-expiry.md)。

## 实际执行

| 检查 | 结果 |
| --- | --- |
| TDD：慢续期 | 旧实现 TTL2 / pg_sleep3 后返回 Available，目标测试失败；新实现串行 PG 用例通过，基础 assurance 仍有效。 |
| TDD：保留 wrapper | 新 values Result / SnapshotExpired 断言在旧 API 编译失败；改动后真实 PG 与公开消费者均通过。 |
| 截止点 T1 | 恰好到期、微秒相位、无效/溢出时间、proof 优先级、空数组与各 unavailable 状态通过。 |
| make check | fmt、全 workspace all-targets/all-features clippy -D warnings、普通 lib/bin check 通过。 |
| make test-pg | 全部 canonical 场景通过，含 7 个 embedded 场景：管理组授权到期拒绝/无新增事件与 SQL 延迟回归。 |
| make test-federated | 7 个真实 PG＋HTTPS Keycloak 场景通过，含撤组、两个旧 session、快照到期、刷新不变、重新登录、provider 断网、配置撤销、禁用再启用不复活。 |
| consumer runner 单测 | 5 passed；包含声明 feature 与实际 compiler feature 不一致时拒绝。 |
| 固定 Git local | 独立 workspace/lock/target，1 passed / 0 failed / 0 ignored；无 OIDC/reqwest/rsa。 |
| 固定 Git OIDC 默认 | 1 passed / 0 failed / 0 ignored；生产构造拒绝 loopback，OIDC 实际 compiler features 为 []。 |
| 固定 Git OIDC loopback-fixture | 1 passed / 0 failed / 0 ignored；真实 TLS Keycloak 登录、checked groups、保留 wrapper 到期拒绝且身份有效、provider 撤销；实际 OIDC compiler features 仅 test-support。 |

首次自定义 PG 命令未指定 test-threads=1，夹具并发建角色冲突；规范 make test-pg 串行通过。新增生命周期首次将六次登录放在同一浏览器，正常触发五次限流；已改为独立浏览器绑定并重跑七个规范用例通过，未放松生产限流。

## 固定输入与恢复

完整 [report.json](202609180100-2438-consumers/report.json) 包含两个宿主各模式的完整 package ID、版本、Git source、metadata feature、实际 compiler feature、provider artifact digest 和输入 hash。同目录保存 [local lock](202609180100-2438-consumers/local/Cargo.lock)、[OIDC lock](202609180100-2438-consumers/oidc/Cargo.lock)、manifest 与 deny 配置。

- Identity Git SHA：`24467273bceca491dca3e1879308ac0cc07a0f8f`；RSS：`93ce6848b7c78753df9947bd08abfb37e5799838`。
- producer Cargo.lock SHA-256：`d73f1736a9f8480f6d3dd858c852318506f791c9b3a577cbd65b9d2bbee71c1e`。
- local Cargo.lock SHA-256：`cb5da4519fd029569e8d30868d425575dbc772f10fd7edf8625269ab69f113c2`。
- OIDC Cargo.lock SHA-256：`b8446122ee0f11eeb329fa70cb7983369f974f3a68d6b9f21e94db588abc7d07`。
- report SHA-256：`c7cba256f96b318995c186521cd308cfb0561bf6948a472efb97494f4e05a2d9`。
- fresh schema v9 / HTTP v2；schema 和生产 Cargo.lock 未改变。PostgreSQL 17.6、Keycloak 26.7.3，digest 见 report。

复现：checkout 实现 A，在仓库/Cargo 配置祖先之外选择新目录，运行 `python3 hack/check_consumer.py --revision 24467273bceca491dca3e1879308ac0cc07a0f8f --output /tmp/identity-2438-reproduce`。需要复用本次精确依赖闭包时，使用已保存 manifest/lock 与 A 中的 tests/consumers 输入，执行 locked 命令；本次记录的独立目录为 `/tmp/identity-2438-consumers-2446727`。

公开 API 消费没有读取 Identity 私表；完整 producer T2 在自有 fixture 中检查持久化快照。默认生产模式只证明构造/出口拒绝与构建闭包，未宣称生产网络连通。没有 MDM 接入、设备授权、产品 binary/image T3 或实时目录撤组承诺；已复制的组值和已作授权效果仍由宿主负责。

最终产品 `make ci CI_BASE=origin/develop` 按 ship 在 findings 处置、pm:ship 与交接 label 后执行，实际结果追加 PR 评论；本记录不提前宣称该步骤通过。
