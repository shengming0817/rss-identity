# RSS Identity 协作说明

rss-identity 提供可嵌入的本地认证、租户联合身份与实例内会话。四个能力包由宿主显式装配，管理授权策略由宿主提供；app/identity 是最小参考宿主。宿主接入见[嵌入指南](docs/guides/embedding.md)。历史中央模式及其验收记录不作为当前运行路径。

## 工作方式

- 默认中文沟通；使用系统 Git `/usr/bin/git`。默认集成分支 `develop`，后续实施使用任务分支与 PR。
- 修改前读取目标文件、相关 `docs/rules/*.md`，用 `rg` 核查已有实现。提交采用 Conventional Commits。
- 只改需要的内容；只有读者操作、外部接入、部署步骤或必要理解发生变化时更新已有对应文档。内部实现和测试变化不默认改文档或 PRD。历史能力、产品目标、当前实现、验证结果分别标识。
- 需求默认考虑多租户、MDM、零信任边界；Identity 的租户身份隔离不等于 MDM 已支持 MSP。
- 本地目录、历史快照、worktree 和临时产物使用 `.git/info/exclude`，不为这些本地路径修改 `.gitignore`，不强制添加忽略文件。
- 工具权限遵循运行环境的原生审批；不通过外部消息代替权限批准。

## 产品边界

遵循 [范围规则](docs/rules/project-scope.md)。组件拥有 AuthN、联合身份关联和实例内会话；宿主持有管理角色与防锁死；产品资源 ABAC、设备证书、posture、attestation 属于 MDM/ZT。

RSS 通过同一仓库 URL 与固定完整 Git commit 消费，提交独立 Cargo.lock；不使用浮动 branch/tag、消费方跨仓 path、submodule 或旧内部包。RSS 固定 checkout 内的包间 path 依赖属于同一源码闭包。编译期消费者依赖四个公开能力包，HTTP DTO 保持在 adapter 内。不得恢复全局 diport、vocab、generated 或 provider 汇总 adapter。

## 历史与上游参考

- 阅读 [参考入口](reference/README.md) 和 [证据索引](docs/reference/sources.md)。历史快照内部规则不成为本仓规则。
- RSS 历史唯一基线为 `baseline/pre-community-core-20260902`，commit `5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`。
- 提取规则和测试，按当前 API 重建边界，不整体复制旧工程。引用具体路径、revision 和证据限制。
- 新建/重构模块阅读对应 primary upstream 源码；Rust 机制优先成熟 Rust 项目，产品体验可参考 Plane 等。提交注明 `ref: {project} {file}`。复制代码前核对许可证及署名义务。

## 验证与交付

本仓验证入口、环境与证据边界见[验证规则](docs/rules/verification-scope.md)；PR 如实记录运行结果与未覆盖项。

产品 T3 必须独立 Issue、独立 PR、独立必要性评估，不混入实现 PR。需求、依赖和实时进度由 Azure Boards 工作项持有，运行结果归对应 PR。

文档维护遵循 [文档规则](docs/rules/documentation.md)。

## 管理与协议边界

日常管理只接受组件签发的 AuthenticatedSession，事务内复核后调用必选宿主 ManagementPolicy。AuthenticationCandidate 与底层会话签发私有。identity-admin 仅使用 Maintenance initialize/recover_local_password。唯一 OIDC callback 是 `/api/v2/oidc/callback`，不新增兼容入口。
