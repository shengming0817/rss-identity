# 首次安装与运维

## 准备

使用候选中的三份 OCI archives 和 candidate.json，通过 `docker load -i <archive>` 装入本地镜像存储，核对配置使用 candidate.json 的 digest 引用。参考拓扑只支持标准 HTTPS 443、专用 PostgreSQL、一个 Keycloak hostname（可有多个 realm/client）、单 Identity 副本。部署前评估实际 provider 版本，版本/摘要统一来自 deployment/providers.lock.json。

复制 deployment/example.json 为私有部署输入，替换 environment_id、origin、tenant、随机 storage target/lineage、epoch 和全部路径。两个产品 origin 不同；IdP hostname 也独立。域名均由 owner 配置 DNS；不得从请求 Host/Forwarded 推导。

准备 CA 及独立服务端证书：public 证书 SAN 覆盖 Identity 与 Keycloak 外部 hostname；postgres 证书 SAN 含 postgres；Hydra admin 证书 SAN 含 hydra-admin；Keycloak 服务端证书 SAN 含 keycloak。数据库、Hydra、OIDC 各自 ca_file 必须信任对应证书；不关闭 VerifyFull。

所有秘密为普通 0600 文件，无尾部换行：runtime/maintenance PG 密码彼此独立且至少32字节；每个产品的 validation secret、OIDC secret独立且至少32字节；OIDC state_key_file 是64位十六进制（32字节、非零）；Hydra gateway service secret和Keycloak DB密码使用32–256字符 base64url；Hydra system secret至少32字节。秘密不得传命令行值或提交到Git。

Identity、NGINX、Hydra、PG容器以10001:10001运行；Keycloak保留锁定上游镜像的1000:0，以支持其启动时augmentation。渲染器由root执行，按唯一服务owner交付配置并核验权限；其它调用者明确拒绝。私钥和秘密按消费服务UID/GID准备（Keycloak私钥1000:0，其它容器秘密10001:10001），均0600；公共CA/证书须对消费用户可读；仅给各服务挂载其所需文件。安装前执行下文volume-init任务，为空卷固定目录设置10001所有权；有内容且属主不匹配的旧卷明确拒绝，不递归修改。维护秘密只在维护任务中挂载，日常服务无 owner/maintenance mount。

准备独立 consumer Docker network，与 MDM 所在网络连接。private-gateway 在此网络以 Identity hostname 提供 TLS 443；容器专属网络命名空间允许非root绑定该端口，消费方保持同一个 Identity origin，不能改 issuer。公网只发布 public-gateway 的443。后端网段和协议网段必须是不冲突的独立 /24，网关地址与输入精确一致。

## 渲染和安装

在仓库使用 `python3 hack/deploy.py --input /private/deployment.json --output /private/rendered --candidate /artifacts/candidate.json`；候选目录可直接使用其中 deploy.py。输出目录必须尚不存在，包含秘密的生成配置，权限700；运行时宜位于受控私有磁盘或tmpfs，不进入日志/备份通用收集器。

0. `docker compose -f /private/rendered/compose.json run --rm volume-init`。仅初始化空卷固定目录权限：PG为10001:10001、Keycloak为1000:0；nocopy防止镜像copy-up覆盖属主。
1. `docker compose -f /private/rendered/compose.json up -d postgres`。首次 PG 初始化建立独立 hydra/keycloak数据库；已有卷不会重放初始化 SQL。
2. `docker compose -f /private/rendered/compose.json run --rm migrate`。该命令内嵌 RSS/Identity SQL，执行单库安装并核验实际 runtime/maintenance 权限；旧版本、身份错配、角色碰撞和权限漂移拒绝。
3. `docker compose -f /private/rendered/compose.json run --rm hydra-migrate`。Hydra 独立执行官方迁移，不受 Identity 事务回滚保护。
4. 启动 Hydra、hydra-admin和Keycloak，按 clients.json 用受控私有 admin API静态注册下游 client（authorization_code/code/openid/client_secret_basic、精确redirect、S256、opaque token）；必须与 hydra.json期限一致。初次Keycloak导入批准realm/client，既有realm变化须经其管理员显式更新，不通过重复导入修复漂移。
5. 通过独立维护任务初始化首个管理员：`docker compose ... run --rm -v /private/new-password:/run/input/new-password:ro maintenance initialize <principal-uuid> <login> /run/input/new-password`。tenant来自维护配置；初始化只能成功一次，重启不能再次夺取authority。
6. 启动 Identity；使用 `docker compose ... exec identity identity-server --probe 127.0.0.1:8080` 执行固定内部探针，Compose healthcheck使用同一命令。公私网网关依赖Identity healthy后才启动并开放端口；不存在启动即自动DDL或自动初始化管理员。

默认维护配置选择声明的第一个tenant；其它tenant维护必须用显式、受审查的维护配置，不根据浏览器输入切换。Keycloak 本身管理员建立/用户生命周期由其部署 owner 负责，本参考不提供默认管理员或密码。

## 故障、停止与回退

| 故障 | 允许操作 |
| --- | --- |
| PG/schema/环境身份不匹配 | 拒绝启动或业务；不返回可信身份 |
| Hydra不可用 | /readyz失败；本地登录、中央会话与管理可继续；产品交接和在线验证拒绝 |
| Keycloak不可用 | 本地登录与管理继续；相关SSO/test失败，必须重新开始登录 |
| worker/listener意外退出 | 同一scope排空，非零退出，Compose重启 |
| 排空超时 | 非零退出；不得解释为数据库已回滚或远端效果不存在 |

SIGTERM关闭admission并有界等待请求/响应、worker、实际KDF和PG。Compose stop_grace_period大于内部总预算。协议清理持久记录保存在PG，重启继续cleanup_once；应用不盲重试未知提交或远程接受。

回退仅限支持同一schema和同一身份配置的应用artifact；不得回退DB撤销状态。v5开发库只能由owner确认可丢弃后重建；不自动down migration。首版禁止同库改变environment/origin/config代际，修改配置会明确拒绝；需要保留数据的origin迁移属于后续专门交付。

维护恢复继续使用 identity-admin recover，详见[维护指南](../guides/local-maintenance.md)。MFA、备份恢复、凭据轮换演练属于 I09。

Hydra admin实际仅监听其网络命名空间的127.0.0.1:4445，认证TLS侧车共享该命名空间；其它protocol网络成员不能直连4445。provider版本始终从candidate.json的providers读取，不随执行脚本旁的新checkout改变。
