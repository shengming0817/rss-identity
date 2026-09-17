# RSS Identity 产品需求

当前方向：2026-09-17，#2435 可嵌入认证组件。此版本替换中央认证服务产品形态；历史需求与中央模式验收可在 fa7019922162158704cc47c6ac7ad36a67c8ae5a 查询，不能作为当前能力证明。

## 能力与责任

Identity 为宿主 Rust 产品提供本地认证、租户 OIDC 联合身份、JIT/显式身份关联、实例内会话和安全事件。四个公开能力包是 core/postgres/oidc/http-axum。宿主拥有实例与租户配置、数据库 runtime、管理角色、防锁死、URL/TLS/listener 和产品资源授权。MDM 的设备权限、posture、证书、计费或 MSP 不进入认证组件。

| 需求 | 当前边界与验收 |
| --- | --- |
| ACC-01 身份契约 | InstanceId、TenantId、PrincipalId、SessionId 显式绑定；浏览器 JSON 不能构造可信请求身份。 |
| ACC-02 本地账户 | 初始化一次且原子；创建、启停、成员变更、密码更新/恢复；管理授权由宿主当前策略决定。 |
| ACC-03 密码认证 | 有界共享 KDF、来源和账户尝试限流；验证与原子会话签发由单一 login_local facade 完成。 |
| ACC-04 会话 | 不透明凭据、轮换、idle/absolute、重新认证、当前/全部撤销；失效状态和存储故障关闭认证。 |
| ACC-05 租户 IdP | provider/config/epoch 隔离，加密凭据、专用 CA、受控配置和连接测试。 |
| ACC-06 OIDC | Code + PKCE、state/nonce/浏览器绑定、一次消费、固定 callback 和回跳白名单。 |
| ACC-07 关联与组 | 不按邮箱自动合并；显式关联须重新认证；组携带来源、配置版本、快照和短有效期，授权映射归宿主。 |
| ACC-08 嵌入消费 | 本地与真实 OIDC 两个独立宿主从固定完整 Git SHA 使用公开 API，分别提交 lock/closure/实际验证证据。中央下游在线验证协议已退出。 |
| ACC-09 事务事件 | 账户/会话/联邦操作与事件同事务；提交不确定不释放成功 cookie。 |
| ACC-10 HTTP 交互 | 可分别挂载本地/OIDC Router，仅 v2；角色字段和中央管理/CLI 协议退出，浏览器与 UI 消费由宿主维护。 |
| ACC-11 装配 | 最小参考宿主保持构建；完整部署/UI/运维候选与 T3 为 #2436。 |
| ACC-12 产品接入 | MDM 接入与其业务授权为 #2437；前端调整为 #2368，各自提交产品证据。 |

## 不兼容策略

未部署产品直接替换：schema v9 只支持全新安装，旧 schema/config/API 不提供升级、别名、dual-read 或 feature 回退。旧数据库、凭据和已存验收记录不被自动修改或重标为成功。OIDC 为可选能力，本地认证不要求联邦密钥或中央控制面。

## 验证责任

本次使用 T1 状态机、真实 PG/OIDC T2、独立固定 Git 消费者验证核心边界。实际命令与结果由实施 PR 持有。[实施计划](../architecture/implementation-plan.md) 管理依赖顺序；[ADR](../architecture/adr/202609170001-2435-embedded-authentication.md) 管理已批准设计；生产部署能力必须由单独的 T3 证明。
