> 历史中央模式文档（基线 fa7019922162158704cc47c6ac7ad36a67c8ae5a），不适用于 #2435 的嵌入式组件。旧运行器已退役；保留验收/候选记录，不重标为本次成功。当前入口为 docs/guides/embedding.md，完整部署后续为 #2436。

# #2342 Identity 联合 SSO T3

本 carrier 验证固定产品候选的正式网关、Identity binary、平台 API/CLI、Keycloak、Hydra、独立消费端、撤销调度与 Outbox 的部署连接。源码及测试实现不等于运行通过；实际结果由对应 PR 的同 HEAD 运行记录持有。

2026-09-13 范围校正：租户开通、IdP 管理与 Hydra login/consent 使用正式后端接口；第二个业务租户经候选中的 identity-platform CLI 开通。#2368 管理网页与本 PR 无依赖关系。浏览器执行真实 Keycloak 登录；取得其授权重定向后，由共享 cookie 的 HTTP context 请求唯一 callback 并检查响应。Hydra 交接逐跳检查真实 HTTP 重定向，禁止加载 Identity 落地页触发网页脚本重复提交；不替换 API、callback 或认证响应，不声明网页或浏览器 SameSite 策略验收通过。

## 固定输入与入口

先完成并提交本仓改动。Identity candidate、测试消费端和 carrier 必须来自同一干净 Git HEAD。正式 gateway 的静态打包输入固定为 rss-web `37b7fb356aa7e436cc708caa1593427e6d553d30`，按其正式入口构建 apps/identity；候选构建验证 UI SHA/lock/dist。此摘要只记录打包身份，不要求该网页支持新平台或 IdP 协议。输出目录必须不存在；两个 CLI 的所有路径参数拒绝空字符串或纯空白，错误会指出对应参数（Make 的 T33_ARTIFACTS、IDENTITY_UI_SOURCE、IDENTITY_UI_DIST、T33_OUTPUT）。

```sh
make prepare-t33 T33_ARTIFACTS=/absolute/t33-artifacts \
  IDENTITY_UI_SOURCE=/absolute/fixed-rss-web \
  IDENTITY_UI_DIST=/absolute/fixed-rss-web/apps/identity/dist
make test-t33 T33_ARTIFACTS=/absolute/t33-artifacts \
  T33_ARTIFACTS_SHA256="准备阶段输出并固定的64位摘要" T33_OUTPUT=/absolute/new-t33-run
```

准备阶段全部外部命令统一使用有限预算：Git/credential/inspect 默认 30 秒，candidate/buildx 默认 3600 秒，load/pull/save 默认 600 秒；分别由正整数环境变量 `T33_COMMAND_TIMEOUT_SECONDS`、`T33_BUILD_TIMEOUT_SECONDS`、`T33_TRANSFER_TIMEOUT_SECONDS` 覆盖。失败只报告 operation、超时预算或退出码，不输出命令参数和子进程原文。

准备阶段调用正式 candidate builder；测试消费端从 Git archive 中以独立 Cargo.lock 构建 Linux amd64 binary，浏览器工具从固定 Playwright 1.60.0 镜像与 npm lock 构建。准备记录二进制、OCI、源码、UI、锁和工具链身份，并导出全部五个运行 provider 的 Docker 归档。provider 归档按准备时核实的 registry digest→image ID/平台映射加载，Compose 只消费固定 image ID 且 pull_policy=never。准备输出的 T33_ARTIFACTS_SHA256 由调用方独立固定，运行前校验；不能在执行时从待验清单重新计算期望值。运行只加载这些产物，不动态构建、下载源码、回退旧格式或猜选候选。

所需环境为 Docker Engine/Compose/buildx、Python >=3.11、Git、openssl、Cargo，以及候选构建需要的只读 RSS Git 凭据。秘密只提供给正式 BuildKit fetch。Linux amd64 产品与消费端可在 ARM Docker 主机仿真运行；实际架构记录在结果中，不据此宣称原生性能或容量。provider digest 只来自候选；浏览器工具锁与产品 provider 锁分开。

## 最小消费端与部署边界

唯一测试消费 workspace 为 tests/consumer。既有 T2 和 T33 共享标准 OIDC 准备、兑换、ID Token 验证和 IdentityClient；T2 provider/路由编排与 T33 浏览器编排分别拥有自己的场景。

测试 binary 仅提供 POST /auth/login、GET /auth/callback、GET /session，保存有界的临时事务及会话。每次 /session 都在线复核，协议凭据不进入浏览器。/session 的可选 client_id 仅选择另一个预注册测试 client，供跨租户/client 拒绝断言使用。它不是生产 BFF，不替代 MDM 或发布 SDK 验证。

候选原始 deploy.py 在隔离 Linux 容器中执行，维持服务 UID、私有文件和网关路径。Docker Desktop 使用按服务、按挂载目标分组的只读 volume 交付渲染器声明的同一文件内容，不把全部部署秘密交给应用或浏览器。测试公共入口将外部 443 映射到真实 public-gateway；Identity API 始终经过候选网关。OIDC 公共解析与 private validation 分开，保留 TLS/SNI 校验。临时 CA 只进入隔离浏览器的 NSS 信任库及客户端，不修改宿主信任。浏览器固定 UID 10001，控制通道采用专用 volume，文件系统只读、移除 capabilities 并禁止提权。

## 运行场景与结果

初始化通过 `docker compose run --rm --no-deps maintenance` 继承候选服务的只读根文件系统、cap_drop、no-new-privileges、tmpfs、用户、网络和挂载，不重新拼装安全参数。部署只初始化一次显式系统域与平台管理员；业务租户分别通过平台 API 和 CLI 创建并立即登录，验证普通租户管理员不能开通或接管其它租户，系统域与业务会话不能串用。IdP 凭据通过租户管理 API 加密持久化，部署只持有外部 keyring；真实 Keycloak 的 realm 与 client 由独立 provider 配置输入创建。

两真实租户分别配置 provider 和 downstream client。保留原 20 项场景，并新增 4 项平台初始化、API/CLI 开通和权限隔离场景：独立租户 SSO、consumer 发起的 SSO/Hydra 继续、错误浏览器/租户/重放/回跳、在途配置变化或停用、JIT 开关、同邮箱不合并、本人再认证关联与冲突、下游绑定、中央退出、provider 撤销及重启用不复活、Keycloak/Hydra/private validation 故障与恢复。配置/凭据更新按当前产品语义撤销旧会话，停用与清理另用更新后新建的有效 grant，防止既有撤销掩盖被测行为。

撤销场景读取实际 grant horizon。只读观察产品 cleanup worker，在 horizon +120 秒以内确认 grant 删除及同一 grant 的 cleaned 事件；不修改业务记录、时间或直接调用内部清理接口。撤销提交后开始的在线复核必须拒绝，已验证的在途业务不追溯取消。上游退出、中央退出和产品会话退出不是全局退出承诺。

Hydra 故障按同仓生命周期 carrier 的既有方式操作：停止 hydra-admin 与 hydra，恢复时一起重新创建，使管理代理加入恢复后的共享网络命名空间。消费者固定使用候选 server 的 amd64 运行层，避免 ARM 宿主 provider 镜像缺少 amd64 加载器。结果必须确认 Identity 网页请求数为 0。

唯一机器判定集合为 proof.py 的 SCENARIOS。缺少、重复、跳过或失败的场景不允许报告成功；浏览器异常退出或资源清理失败同样失败。SIGTERM/SIGINT 转为受控失败并执行清理；不承诺捕获 SIGKILL。Docker 故障仍生成最低失败回执，诊断保留有界脱敏摘要。公开 result.json 只记录固定身份、配置版本、HTTP 状态、安全错误类别、实际关联 ID 与断言。口令、cookie、code、verifier、token、callback query 和上游原文不进入结果。私有控制通道、证书及秘密在成功清理后删除。

T3 只证明事件连通及装配使用实际事务 owner；JWT 算法、完整 PG/CommitUnknown、并发 linking、完整清理重试矩阵引用原有 T1/T2。真实 MDM #2364、MFA #2366、恢复 #2367 保持独立。产品实现缺陷退回独立 owner PR 修复，更新候选后重验，不能缩减 T33 退出条件。

## 最小回归与交付

`python3 -B -m unittest discover -s hack -p test_t33_federated.py` 验证产物身份、断言完整性、敏感材料和异常清理；`python3 hack/check_consumer.py` 与 `make test-downstream` 验证共用消费端。最终统一运行一次 `make -k ci CI_BASE=origin/develop`，集中处理失败。T33 独立运行，不加入常规 CI。

运行记录保存在 PR 评论/附件并绑定最终受测 SHA。修改提交后重新准备并重跑，避免把旧 HEAD 记录作为新交付证明。新增入口无历史格式兼容路径，旧 T2 保留其独有风险证明。

来源：Axum axum-v0.8.9 axum/src/serve/mod.rs；openidconnect 4.0.1 client.rs 和 verification/mod.rs；Playwright v1.60.0 browser.ts 和 browserContext.ts。
