# 验证范围

- 文档/配置：内容、链接、来源、Git diff、忽略范围与远端分支；不把初始化当作产品完成。
- T1：租户/身份边界、账户与会话状态机、登录事务、防重放和错误语义。
- T2：真实 PG 事务、登录事务原子消费、OIDC provider 交互、token 校验、Outbox 和产品 adapter 接缝。按风险附在所属实现 Issue 中。
- T3：真实产品 binary/image/config/provider 的装配闭环；每项独立 Issue、独立 PR、独立必要性评估。只验证低层看不到的 join hazard。

当前没有产品代码或 CI。建立工程时提供本仓实际检查入口，并同步 AGENTS.md；不得使用 RSS CI 或历史测试记录代替 Access 测试。

生产验收绑定版本、artifact、配置身份、provider 版本、实际行为、故障和未覆盖项。预发布冻结会话期限、撤销最大延迟、登录限流、容量、RPO/RTO、支持 IdP 矩阵，不凭经验数字宣称 SLO。

MDM 接入证明自己的身份消费和资源授权，不重复 Access 全套 SSO T3。模拟消费者可以证明 Access 端行为，不能替代真实 MDM 接入证据。
