# 独立镜像构建

后端只产出一个 Linux 镜像，包含 identity-server、identity-migrate、identity-admin，默认入口为服务。标准入口不传平台参数，由当前 Docker context 的 BuildKit daemon 选择默认平台，并从 providers.lock 固定的多架构索引摘要选择对应变体；不从 macOS 等客户端系统名推导平台。正式入口要求干净 HEAD，以 git archive 固定构建上下文；revision 和基础镜像从该提交与 providers.lock 派生，不接受外部覆盖。构建仅使用本仓源码和固定 Cargo.lock；Rust 使用镜像原生工具链与普通 target/release 产物，不读取 rss-web 或静态目录，不需要 Node。生产 release compiler artifacts 由现有 check_dependencies.check_artifacts/check_features 验证，私有 Git 凭据仅提供给 cargo fetch 的 BuildKit secret。

```sh
make image IDENTITY_IMAGE=rss-identity:my-version
# 私有 Git：设置 IDENTITY_GIT_AUTH_HEADER_FILE（0600 的 Authorization header 文件）
# 或 SYSTEM_ACCESSTOKEN；不要将秘密放进 build-arg。
```

前端在 rss-web 通过 `pnpm image:identity --tag rss-identity-web:my-version` 独立构建。该薄入口也使用干净 HEAD 的源码归档并派生 Web revision。它拥有 Node 构建、静态检查、Web revision 和 Nginx 镜像；后端和前端版本独立。交付镜像的 revision 必须对应构建源码，正式联合验证使用各仓最终提交。

在目标 Docker daemon 上准备镜像；跨主机时在目标 context 从选定来源执行普通 `docker pull <image>`，由该 daemon 选择变体。PostgreSQL 与 volume-init 的 Debian 镜像使用 deployment/providers.lock.json 中固定的多架构索引摘要，也须预先显式拉取。本轮不提供 registry 或发布流水线。

渲染只接受 `--identity-image` 与 `--web-image`：本地 inspect 验证 Linux 镜像、非 root 用户和各自 revision，再将不可变 image ID 写入 compose.json。Compose 不写平台字段，构建、预检、运行、迁移和维护统一使用当前 Docker context 的默认选择；identity、migrate、maintenance 共用同一个 ID，gateway 使用 Web ID，所有服务禁止隐式拉取。Compose 是生成的运行配置，无额外候选清单；切换本路径后重新渲染，不转换旧目录。缺失镜像或旧 `--candidate`、`make candidate` 参数失败。

不再生产/消费 candidate.json、强制 OCI tar 或裸二进制目录。历史候选与验收记录只作历史来源，不构成新部署前提。备份回执格式见[恢复](recovery.md)。

综合参考应用 T3 由 #2366 持有，唯一入口为 `make test-reference`。它使用当前 Docker context 的默认环境，由该入口先构建与 HEAD 绑定的测试工具镜像后，在 daemon 内一次性私有卷运行实际部署、真实 Chromium、TLS PG 和内网 Keycloak；不要求 macOS 宿主以 root 渲染文件。

```sh
make test-reference IDENTITY_IMAGE=rss-identity:revision WEB_IMAGE=rss-identity-web:revision REFERENCE_TOOLS_IMAGE=rss-identity-reference-tools:revision REFERENCE_WEB_REPO=/absolute/fixed/rss-web REFERENCE_RECORD=/absolute/private/new-result.json
```

运行器从干净 Git 提交归档源码，核对产品镜像 revision、两仓 lock、RSS revision、schema、provider/tool image ID、浏览器和真实资源。测试使用随机一次性秘密，通过正式 v4 `privateProviders` 接通内网 Keycloak；测试 loopback 不进入产品镜像。前端仍由 rss-web 构建，本仓不维护第二个 npm 工程。工具镜像的 Playwright 包摘要与固定 Web lock 对齐。

省略 `REFERENCE_TARGETS` 时，只生成 `measured` 基线，不能标记生产目标验收通过。owner 根据基线确认支持规模、SLO、RPO/RTO 后，提供新的私有 JSON：`subject` 为基线固定候选对象，`baselineSha256` 为完整 measured 基线文件摘要；`approvalReference` 为本项 PR #1057 的批准评论链接（固定组织/项目，仅允许 `discussionId` 参数），`limits` 明确包含 loginP95Ms、failedAttemptP95Ms、failedAttemptRequestsPerSecond、accountEventCommitP95Ms、accountEventCommitsPerSecond、sessionP95Ms、sessionRequestsPerSecond、unexpectedErrors、restoreSeconds、lostSecurityChanges、expiredAttemptsRemoved。耗时、错误和丢失数量为上限；吞吐和清理数量为下限。再次调用同一入口并设置 `REFERENCE_TARGETS=/absolute/approved-targets.json REFERENCE_BASELINE=/absolute/measured-result.json`，回读并验证原基线、候选、场景和清理完整，再使用全新输出和数据卷正式复测。审批评论是可审计的人类决定引用，运行器不把任意 URL 当作批准内容证明。

结果只保存本次实际观测、材料摘要、测量和通过/失败/未覆盖；任何必要步骤、目标或清理不满足都不能通过。源码树不保存逐次结果，完整脱敏结果归档为 T3 PR 附件并回读校验摘要。实际密码、cookie、CSRF、TOTP seed、code、verifier、client secret 与浏览器存储仅存在私有 fixture，退出后删除，不进入报告。恢复直接消费 operate 的备份回执，不新增候选协议、恢复 seal 或激活系统。

工具只支持内层 socket 与当前 context 可核验为相同 daemon ID 的环境；不一致在启动产品之前失败。Keycloak 在本次独立的 Docker internal 网络内使用 RFC1918 地址，不发布宿主端口；operator 与每次正式 open 后的身份服务加入该网络，浏览器、生产 resolver 与 TLS 仍完整执行。工具只清理本次精确随机 project/label 的容器、网络和卷。外层先保存 running，再停止 operator、清理并验证产品及私有卷，最后原子发布最终结果；失败和中断也保存失败结果并确认清理；未知写入只读核对，不自动重放。普通 `make ci` 保持组件 T1/T2；浏览器 T3 不进入普通 CI。

对标源码：[Moby ImageInspect](https://github.com/moby/moby/blob/v28.3.3/daemon/images/image_inspect.go)、[Playwright browser context](https://github.com/microsoft/playwright/blob/v1.60.0/packages/playwright-core/src/server/browserContext.ts)。
