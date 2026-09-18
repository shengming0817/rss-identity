# 产品范围

rss-identity 拥有可嵌入的本地认证、租户成员身份、联合 IdP 登录/关联、实例内服务端会话和原子安全事件。core、postgres、oidc、http-axum 为公开能力包；app/identity 是参考宿主，不成为消费方的运行依赖。当前决定见 [#2435 ADR](../architecture/adr/202609170001-2435-embedded-authentication.md)。

宿主持有管理角色、防锁死、资源授权、配置、实例标识、租户 admission、数据库角色与 fenced PgRuntime；组件强制实例/租户/主体/epoch/会话绑定并在事务内调用宿主策略。组和 assurance 仅提供可信认证事实，不生成资源权限。MDM/ZT 持有设备 authority、attestation、posture 和业务授权。

仅支持 HTTP v2 和 fresh schema v9，无旧配置、旧库升级、v1 alias、legacy feature 或中央 downstream/client/Hydra 模式。旧候选与历史证据保留；重新部署及真实产品迁移须由其独立任务闭合。

RSS 公共 runtime、事务消息及必要基础库使用同一 Git URL/完整 SHA，独立 Cargo.lock 与实际 feature 闭包。禁止消费方跨仓 path、源码副本、浮动 branch/tag 或 Git/registry 双来源。固定 Git checkout 内的包间 path 属于同一源码闭包。源码消费不等于 registry 发布。

宿主注入既有连接池，业务变更与 Outbox 使用同一 PG 事务。组件不重建、替换或关闭宿主池；各 schema owner 导出 migration，宿主决定顺序、角色与 tenant fence。OIDC 配置可选，不引入统一 provider 总线。

不建设通用 IAM、OAuth 授权服务器、API proxy、中央 ABAC 或设备 authority。新增 SAML/LDAP/SCIM、M2M、自助注册、passkey 按独立需求接纳。参考部署/运维与独立前后端镜像属于 #2436，产品 T3 属于独立 #2366，MDM 迁移属于 #2437，Web UI 属于 #2368。
