> 历史验收载体说明，所列旧候选入口已删除。新架构 T3 由独立任务持有，不按下列旧命令执行。

> 历史中央模式文档（基线 fa7019922162158704cc47c6ac7ad36a67c8ae5a），不适用于 #2435 的嵌入式组件。旧运行器已退役；保留验收/候选记录，不重标为本次成功。当前入口为 docs/guides/embedding.md，完整部署后续为 #2436。

# ACCESS-T32：本地认证候选验收（#2341）

本目录持有 Identity 的独立产品 T3。独立必要性是浏览器、实际 gateway/server/operator 镜像、
正式 TLS/配置/PG/Hydra、中央与产品 cookie、逐请求身份复核和持久 Outbox 的跨进程接缝。
现有源码 Router/PG/OIDC/UI T1/T2 不能观察这一组合；这里不重复哈希算法或 PG conformance。

## 执行

需要 Docker Compose（支持 volume subpath）、Python 3.11+、Node/pnpm。Docker Desktop ARM 主机
通过 Docker 的 amd64 支持运行候选；测试控制器使用固定 Playwright 多架构镜像及独立 lock。系统工具从签名校验的 Ubuntu
`20260912T000000Z` 快照按精确版本安装；pnpm 11.4.0 分发物经仓内 SHA-512 校验后才执行。
最小检查解析全部 Python/JS 载体（含 bounded_process），ESLint `no-undef` 覆盖全部 `.mjs`。

```sh
make check-t3-local-auth
make test-t3-local-auth IDENTITY_T3_CANDIDATE=/absolute/candidate IDENTITY_T3_RECORD=/absolute/new-record.json
```

入口只接受当前 candidate.json format_version=1、linux/amd64 和完整 server/operator/gateway
OCI 归档及 binaries。源提交必须在本仓 Git object database 中；候选部署脚本/模板绑定该提交，
运行镜像与候选摘要一致。缺输入、格式错配、摘要错配及未执行场景均失败；不构建替代产品。
候选构建及恢复方法见[固定历史源码的 candidate.md](https://dev.azure.com/shengming0923/rss/_git/rss-identity?path=/docs/deployment/candidate.md&version=GC06d4e85498281a874eff9898a3b77fc19705e8b1)。入口要求 #2419 修复后的 443:443
拓扑；旧候选的安装失败保留为证据，不提供旧端口或 Compose 插值补丁。

每次创建独占 Compose project、网络和卷。Docker network create 原子占用 backend/protocol
子网，第二个创建失败时回滚第一个；冲突才重试下一对子网。将候选网络改成 external 引用前，
严格核对候选原有 internal/IPAM 与实际占用网络，不匹配则失败；服务固定地址及网络成员不改写。秘密在私有卷中生成，按正式 UID/0600 规则逐文件挂载；
不写入宿主环境变量或命令行。部署 renderer/operator 均来自候选，入口统一使用标准 HTTPS 443；浏览器只接候选公开 gateway
的隔离网络，控制器的 CA 信任仅存在于容器。产品各服务的网络与
配置保留正式约束。PG 查询只使用控制面只读事务。

## 消费者边界

Node consumer 是可丢弃测试程序，仅有登录、标准 callback 和受保护测试接口。openid-client
负责 Code/PKCE、state/nonce、签名/issuer/audience 校验；state/verifier 一次性领取，凭据只存于
服务端内存。`/internal/v1/identity/validate` 每请求调用；不提供认证缓存、离线模式、通用 SDK
或产品权限。`/app` 与 `/api/protected` 共用会话验证：401/403 清会话，429/503
拒绝当前访问并保留会话，返回 Retry-After 和重试入口。PG 故障/恢复经过同一浏览器的
真实页面/API，断言 cookie、handle 与 session ID 未变；不以私有探针代替恢复路径。独立产品 cookie 使用 host-only/Secure/HttpOnly/SameSite=Lax。

仅测试控制面可通过私有 Unix socket 再次验证保留的同一凭据，输出状态/关联 ID/剩余期限，
不返回凭据。恢复后必须同时证明旧凭据在线拒绝且未过期、有效对照凭据成功；清 cookie 和
全局断网均不能冒充撤销证明。

## 证据与退出

场景覆盖登录/交接、Origin/CSRF/权限/绑定拒绝、中央刷新、当前/全部退出、密码变化、禁用与
重新启用、PG 故障、Hydra 清理故障及恢复。安全事件按动作、主体/session/grant 与序号关联，
拒绝行为不能产生对应成功事件。事件连通终点是持久 Outbox，不宣称 broker delivery。

候选 v1 顶层与所有嵌套对象均校验闭合字段和类型；额外字段直接拒绝。公开候选记录只由
验证后的结构字段构造，原始 toolchain 文本不输出。

record 绑定候选 manifest、OCI、Git/lock、控制器镜像、实际 provider/platform、配置身份、
测试源码摘要（含执行 helper）、阶段结果和逐资源清理结果。测试镜像按 image ID 使用，避免并发构建替换。
前置校验失败和中断同样生成失败记录；退出码与固定诊断分类可定位准备步骤，原始命令日志不进入记录。
秘密及原始浏览器 trace 不进入 record。未覆盖项包括真实
MDM/ABAC、联合 IdP/MFA/恢复、生命周期全矩阵、长期会话时间边界及生产容量/SLO。

产品问题必须另开修复 PR，保留本项失败记录；新固定候选全量复验通过后才能关闭 #2341。
测试实现、候选构建成功与实际验收通过是不同事实。正式结果由 PR 附带的记录持有。

上游参考（只调用公共接口，未复制源码）：
- panva/openid-client `src/index.ts`、`examples/oidc.ts` @ v6.8.8（MIT）。
- microsoft/playwright `packages/playwright-core/src/server/browserType.ts` @ v1.60.0（Apache-2.0）。

- Ubuntu Snapshot Service：<https://snapshot.ubuntu.com/>（签名快照与包摘要链）。
- Docker Compose networks：<https://docs.docker.com/reference/compose-file/networks/>（external/IPAM/internal）。
- oauth2-proxy `pkg/middleware/stored_session.go`（在线验证失败边界，MIT；未复制代码）。
- ESLint no-undef：<https://eslint.org/docs/latest/rules/no-undef>。
