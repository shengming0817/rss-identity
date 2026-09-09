# I08：唯一产品装配与固定候选

本决定替代旧开发安装与应用入口布局。实现证据与候选摘要由本项 PR 持有；不是 T31–T33 生产验收。

## Owner 与退出

`app/identity` 是唯一可执行装配 package，输出 identity-server、identity-migrate、identity-admin。三个入口共享安全文件读取和数据库配置，部署分别授予 runtime、migration owner、maintenance 凭据。没有兼容应用目录、日常管理 CLI、配置别名或 provider registry。

RSS managed listener 提供标准 accepted TCP ConnectInfo；Identity 根据真实 peer 和固定网关地址解释单值 X-Forwarded-For，再提供 ClientAddress 给限流。原始 peer 保留。NGINX 覆盖来源头，公网和私网使用独立网络地址；backend 不发布宿主端口。Hydra admin 使用既有私有 TLS + service credential。

## 身份与迁移

Identity 新初始 schema 为 v6；原 v5 是可丢弃开发库，不提供升级兼容、自动清库或原地修复。schema/version、结构签名、权限探测和测试 fixture 同步替换。

现有 deployment singleton 唯一持有 environment_id、identity_config_version、两个 HTTPS origin；owner 首次安装时写入，之后触发器禁止原地改变。Authority::connect 必填期望 DeploymentIdentity，启动时在同一探测事务中核对。首版不支持同库 origin/environment 迁移，修改后明确拒绝；不得用重启绕过 I01 的身份迁移规则。需要保留数据的域名迁移须另行实现并验收。

JSON format_version 只表示文件结构；schema version 只表示数据库结构；identity_origin.config_version 只表示 origin 身份代际。二进制、Cargo.lock、UI 与 OCI 摘要属于构建记录，不参与数据库身份判断，因此同配置正常换二进制不会夺取或重建 authority。

产品安装任务持有专用 owner 连接，使用会话 advisory lock。首次安装按 RSS 导出 bundle → Identity SQL → 登录角色/grants → storage/环境身份在一个本地事务提交。重复执行仅核验结构、身份和两种真实登录权限，不重新授权或改密码；不确定提交返回失败并要求先检查。Hydra 自己迁移独立数据库，Keycloak 自己管理其 schema；不存在跨服务原子回滚。

## 生命周期与故障

一个 LifecycleScope 登记 PG、共享 KDF、deferred cleanup worker、critical listener，最后开放 admission。请求 permit 覆盖 response body。关闭先停止准入并排空请求/连接，再停止 worker、等待真实 KDF closure、关闭 PG；资源和总期限保持独立。关闭失败非零退出，避免 Tokio Drop 再次无限等待 blocking work。KDF 的 token 和容量许可都由实际 closure 持有；取消调用方不释放运行中的容量。

/livez 只报告进程存活；/readyz 在 admission 开放时检查 PG/schema/身份/权限和 Hydra，最多一个并发探测。它不是认证授权证明，失败不会全局关闭本地 API。PG 故障拒绝业务；Hydra 故障拒绝产品交接/在线验证，本地账户与管理仍可操作；Keycloak 故障阻断其登录/test，不自动降级或按 email 关联。清理任务按已配置 tenant 有界轮询，provider 失败退避，任务意外退出触发进程关闭。

初版 Compose 单副本，PrepareAdmission 是每进程共享入口配额；不承诺跨副本限额。安全事件落 PG Outbox，不在本项新增 broker relay。

## 候选与来源

部署 provider 和 builder/runtime 镜像的唯一锁为 deployment/providers.lock.json；测试引用相同锁。候选构建要求干净 Identity HEAD 和固定、干净 rss-web SHA + lock + dist identity。Git 凭据仅进入 BuildKit fetch secret，编译 RUN 离线；最终镜像只包含所需 binaries/静态 UI。Linux amd64 候选输出 server/operator/gateway OCI archives、独立 binaries 及实际编译 RSS feature 证据；不是 registry 发布或产品 T3。

#2357 的 owner 已在本项确认继续限定接受 RSA 公钥验签路径，必须以最终生产依赖图和用途复核为准，不扩大私钥操作或其它公告例外。

参考：Axum axum/src/extract/connect_info.rs @ axum-v0.8.9；Tokio tokio-util/src/task/task_tracker.rs；NGINX ngx_http_proxy_module.c @ release-1.30.4；Hydra cmd/migrate_sql.go @ 0b84568fffccf151dc5e6c7955fdfb738555bf4b。RSS 消费的唯一完整 revision 由 Cargo.toml/Cargo.lock 持有。
