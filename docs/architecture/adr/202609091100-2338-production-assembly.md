# #2338：生产装配与生命周期（历史决定）

适用时期：#2435 嵌入架构之前的中央模式。由 [#2435](202609170001-2435-embedded-authentication.md) 替代，不作为当前操作说明。

## 当时的决定与取舍

中央部署由产品持有配置、秘密、数据库角色、迁移次序、监听与关闭；基础库不替代生产装配。首次安装与日常运行分权，启动拒绝不完整配置，部分失败保留清理责任，未知写入不重试。

## 替代关系

Hydra 和中央客户端的部署拓扑已退出；当前部署操作归参考宿主，运行步骤见当前部署指南。旧候选、脚本摘要和验收结果仅属于原版本。

历史实现与当时的验证记录通过 [#2338 工作项](https://dev.azure.com/shengming0923/rss/_workitems/edit/2338) 和本文件 Git 历史追溯。历史结果不表示当前版本已验证；来源与许可证见[来源索引](../../reference/sources.md)。

- [Hydra v26.2.0 client handler](https://github.com/ory/hydra/blob/v26.2.0/client/handler.go)
- [Fosite access request](https://github.com/ory/hydra/blob/v26.2.0/fosite/access_request_handler.go)
