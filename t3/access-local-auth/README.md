# ACCESS-T32：本地认证候选验收（#2341）

本目录持有 Identity 的独立产品 T3。独立必要性是浏览器、实际 gateway/server/operator 镜像、
正式 TLS/配置/PG/Hydra、中央与产品 cookie、逐请求身份复核和持久 Outbox 的跨进程接缝。
现有源码 Router/PG/OIDC/UI T1/T2 不能观察这一组合；这里不重复哈希算法或 PG conformance。

## 执行

需要 Docker Compose（支持 volume subpath）、Python 3.11+、Node/pnpm。Docker Desktop ARM 主机
通过 Docker 的 amd64 支持运行候选；测试控制器使用固定 Playwright 多架构镜像及独立 lock。

```sh
make check-t3-local-auth
make test-t3-local-auth IDENTITY_T3_CANDIDATE=/absolute/candidate IDENTITY_T3_RECORD=/absolute/new-record.json
```

入口只接受当前 candidate.json format_version=1、linux/amd64 和完整 server/operator/gateway
OCI 归档及 binaries。源提交必须在本仓 Git object database 中；候选部署脚本/模板绑定该提交，
运行镜像与候选摘要一致。缺输入、格式错配、摘要错配及未执行场景均失败；不构建替代产品。
候选构建及恢复方法见产品部署目录的 candidate.md。

每次创建独占 Compose project、网络和卷。秘密在私有卷中生成，按正式 UID/0600 规则逐文件挂载；
不写入宿主环境变量或命令行。部署 renderer/operator 均来自候选。附加 TCP 入口保持产品 TLS
和 HTTP 路由不变；浏览器只接入口网络，控制器的 CA 信任仅存在于容器。产品各服务的网络与
配置保留正式约束。PG 查询只使用控制面只读事务。

## 消费者边界

Node consumer 是可丢弃测试程序，仅有登录、标准 callback 和受保护测试接口。openid-client
负责 Code/PKCE、state/nonce、签名/issuer/audience 校验；state/verifier 一次性领取，凭据只存于
服务端内存。`/internal/v1/identity/validate` 每请求调用；不提供认证缓存、离线模式、通用 SDK
或产品权限。独立产品 cookie 使用 host-only/Secure/HttpOnly/SameSite=Lax。

仅测试控制面可通过私有 Unix socket 再次验证保留的同一凭据，输出状态/关联 ID/剩余期限，
不返回凭据。恢复后必须同时证明旧凭据在线拒绝且未过期、有效对照凭据成功；清 cookie 和
全局断网均不能冒充撤销证明。

## 证据与退出

场景覆盖登录/交接、Origin/CSRF/权限/绑定拒绝、中央刷新、当前/全部退出、密码变化、禁用与
重新启用、PG 故障、Hydra 清理故障及恢复。安全事件按动作、主体/session/grant 与序号关联，
拒绝行为不能产生对应成功事件。事件连通终点是持久 Outbox，不宣称 broker delivery。

record 绑定候选 manifest、OCI、Git/lock、控制器镜像、实际 provider/platform、配置身份、
测试源码摘要、阶段结果和清理结果。秘密及原始浏览器 trace 不进入 record。未覆盖项包括真实
MDM/ABAC、联合 IdP/MFA/恢复、生命周期全矩阵、长期会话时间边界及生产容量/SLO。

产品问题必须另开修复 PR，保留本项失败记录；新固定候选全量复验通过后才能关闭 #2341。
测试实现、候选构建成功与实际验收通过是不同事实。正式结果由 PR 附带的记录持有。

上游参考（只调用公共接口，未复制源码）：
- panva/openid-client `src/index.ts`、`examples/oidc.ts` @ v6.8.8（MIT）。
- microsoft/playwright `packages/playwright-core/src/server/browserType.ts` @ v1.60.0（Apache-2.0）。
