# 验证范围

- 文档：内容、导航和链接、来源与许可证、Git diff；必要操作示例按其实际风险验证。
- T1：身份与租户隔离、账户/会话状态机、防重放、资源上限和错误语义。
- T2：真实 PG 事务、OIDC/token 校验、Outbox 和产品 HTTP/adapter 接缝，随对应行为变更验证。
- T3：实际 binary/image/config/provider 的装配与恢复风险，单独评估必要性、登记 Issue 和 PR；组件结果不替代产品结果。

日常开发和交付只执行受影响构建、静态检查、业务测试及必要集成。`make ci` 保留完整工程入口，托管 CI 继续使用它；不要求每个 ship/fix 阶段重复全量运行。复用有效结果，修复后仅复验失败项与受影响行为。所选真实 provider 不可用时明确失败，不静默跳过。

不为产品内部拆包建立模拟 consumer、独立 workspace/target、packed artifact 或源码/commit 证明，不要求先提交再测试或干净 checkout 冷构建。正常 Git、manifest/lock、locked 构建、实际依赖 feature、许可证与安全公告检查保留。复用本仓 worktree 的 Cargo target 和可选缓存；配置入口见 [Makefile](../../Makefile) 与 [Cargo 配置](../../.cargo/config.toml)。

普通开发、CI 和收尾不运行容量、压力或长跑测试。有明确批准目标的未来性能需求单独立项；旧候选测量不外推为当前 SLO。限流、缓存清理、分页和资源上限的短小功能边界测试保留。

实际接入按认证授权、API/协议、事务和恢复行为验收；MDM 持有自身资源授权和接入证据。记录实际运行环境、结果及未覆盖项，不以历史记录或 RSS 主仓验证代替 Identity 的行为证明。

本地长命令返回 session 后对同一 session 空输入续等；不通过 sleep 后轮询日志、进程或制品判断进度。
