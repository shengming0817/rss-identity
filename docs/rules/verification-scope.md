# 验证范围

- 文档：内容、导航、链接、来源与许可证对应实际交付。
- T1：身份与租户隔离、账户/会话状态机、防重放、资源上限和错误语义。
- T2：真实 PG 事务、OIDC/token 校验、Outbox 和产品 HTTP/adapter 接缝。
- T3：实际 binary/image/config/provider 的装配与恢复风险，单独评估必要性、登记 Issue 和 PR；组件结果不替代产品结果。

`make ci` 是本仓完整工程入口，托管 CI 使用同一入口；专项命令见[开发指南](../guides/development.md)。真实 provider 不可用或测试未实际执行时，结果不能记为通过。

Make 入口复用本仓 worktree 的 Cargo target 和可选缓存；配置入口见 [Makefile](../../Makefile) 与 [Cargo 配置](../../.cargo/config.toml)。

性能证据对应明确批准的目标与运行场景，旧候选测量不外推为当前 SLO。

实际接入按认证授权、API/协议、事务和恢复行为验收；MDM 持有自身资源授权和接入证据。记录实际运行环境、结果及未覆盖项，不以历史记录或 RSS 主仓验证代替 Identity 的行为证明。
