# 验证范围

- 文档/配置：内容、链接、来源、Git diff、忽略范围与远端分支；不把初始化当作产品完成。
- T1：租户/身份边界、账户与会话状态机、登录事务、防重放和错误语义。
- T2：真实 PG 事务、登录事务原子消费、OIDC provider 交互、token 校验、Outbox 和产品 adapter 接缝。按风险附在所属实现 Issue 中。
- T3：真实产品 binary/image/config/provider 的装配闭环；每项独立 Issue、独立 PR、独立必要性评估。只验证低层看不到的 join hazard。

本仓检查入口为 `make ci`：locked 构建、fmt、clippy、T1、真实 PG/OIDC T2、依赖来源、生产/测试 feature 精确集合、许可证与安全公告检查。缺少 Docker/provider 时失败，不静默跳过。不得使用 RSS CI 或历史测试记录代替 Identity 测试。

Make 入口通过 Git common directory 将所有本仓 worktree 的 Cargo 产物统一写入主 checkout 的
`target/`；可选 sccache 位于主 checkout 的 `.cache/sccache/`，不与 RSS 或其它产品仓共享。
显式 `CARGO_TARGET_DIR`、`SCCACHE_DIR` 仍可覆盖本地默认值；独立 consumer 必须使用仓库祖先之外的 workspace、Cargo.lock 和独立 target，
不得继承本仓 Cargo 配置或共享本仓 target。

生产验收绑定版本、artifact、配置身份、provider 版本、实际行为、故障和未覆盖项。预发布冻结会话期限、撤销最大延迟、登录限流、容量、RPO/RTO、支持 IdP 矩阵，不凭经验数字宣称 SLO。

MDM 接入证明自己的身份消费和资源授权，不重复 Identity 全套 SSO T3。模拟消费者可以证明 Identity 端行为，不能替代真实 MDM 接入证据。

固定 Git 消费证明绑定仓库 URL、完整 SHA、package 版本、Cargo.lock 和实际 features。干净环境从 Git 获取源码，排除祖先 Cargo 配置；RSS Git checkout 内部 path 依赖允许，消费方本机跨仓 path 禁止。产品镜像/二进制以摘要绑定该构建身份；不伪称已发布 registry artifact。

可选缓存不可用（无 Git 元数据、目录无法创建、sccache 执行失败）时直接执行 rustc；
sccache 失败最多直接重试一次，最终保留 rustc 退出码，编译错误可能输出两次。
默认 socket 位于有效 `SCCACHE_DIR` 内；显式 `SCCACHE_SERVER_UDS` 覆盖时由调用方保证
服务与缓存配置一致，修改同一服务的缓存配置需重启该服务。
