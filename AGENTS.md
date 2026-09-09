# RSS Identity 协作说明

rss-identity 是本地认证、租户联合身份接入与服务端会话产品仓。产品需求由 [PRD](docs/product/rss-identity-prd.md) 持有；当前具有 I01/I02 协议与工程接缝及 I03 本地账户/本机管理机制；I04 提供中央会话；I05 提供租户 IdP、持久 OIDC/JIT/关联及可挂载 HTTP Router；I06 提供 Hydra 下游 bridge、在线验证与最小 client；I07 的日常管理仅使用中央会话 API，UI 源码由 rss-web apps/identity 持有；I08 提供产品装配，I09 提供可信 assurance、显式 step-up、原生恢复/轮换 T2 与测量入口；生产目标及新增候选 T3 独立验收。

## 工作方式

- 默认中文沟通；使用系统 Git `/usr/bin/git`。默认集成分支 `develop`，后续实施使用任务分支与 PR。
- 修改前读取目标文件、相关 `docs/rules/*.md`，用 `rg` 核查已有实现。提交采用 Conventional Commits。
- 只改需要的内容，行为变化同步更新所属文档。历史能力、产品目标、当前实现、验证结果分别标识。
- 需求默认考虑多租户、MDM、零信任边界；Identity 的租户身份隔离不等于 MDM 已支持 MSP。
- 本地目录、历史快照、worktree 和临时产物使用 `.git/info/exclude`，不为这些本地路径修改 `.gitignore`，不强制添加忽略文件。
- 工具权限遵循运行环境的原生审批；不通过外部消息代替权限批准。

## 产品边界

遵循 [范围规则](docs/rules/project-scope.md)。Identity 拥有 AuthN、联合身份关联、登录会话和自身管理权限；产品资源 ABAC、设备证书、posture、attestation 属于 MDM/ZT。

RSS 通过同一仓库 URL 与固定完整 Git commit 消费，提交独立 Cargo.lock；不使用浮动 branch/tag、消费方跨仓 path、submodule 或旧内部包。RSS 固定 checkout 内的包间 path 依赖属于同一源码闭包。编译期消费者仅依赖稳定 contracts/client 或采用标准 wire 协议。不得恢复全局 diport、vocab、generated 或 provider 汇总 adapter。

## 历史与上游参考

- 阅读 [参考入口](reference/README.md) 和 [证据索引](docs/reference/sources.md)。历史快照内部规则不成为本仓规则。
- RSS 历史唯一基线为 `baseline/pre-community-core-20260902`，commit `5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`。
- 提取规则和测试，按当前 API 重建边界，不整体复制旧工程。引用具体路径、revision 和证据限制。
- 新建/重构模块阅读对应 primary upstream 源码；Rust 机制优先成熟 Rust 项目，产品体验可参考 Plane 等。提交注明 `ref: {project} {file}`。复制代码前核对许可证及署名义务。

## 验证与交付

遵循 [验证规则](docs/rules/verification-scope.md)。文档变更检查链接、来源、diff、忽略范围；工程验证运行本仓 `make ci`，不执行父仓检查代替产品证明。

产品 T3 必须独立 Issue、独立 PR、独立必要性评估，不混入实现 PR。已登记 Issue 索引在 [实施计划](docs/architecture/implementation-plan.md)；本地编号映射到真实 Azure work item ID，实时状态以看板为准。

文档维护遵循 [文档规则](docs/rules/documentation.md)。

## I07 管理边界

日常管理仅接受 AuthenticatedSession 并在事务内重检；AuthenticationCandidate 只用于登录发会话与密码再认证。identity-admin 仅持有 Maintenance initialize/recover。唯一协议 callback 为 /api/v1/oidc/callback，不新增兼容入口。当前决定见 docs/architecture/adr/202609090801-2337-central-management-ui.md。
