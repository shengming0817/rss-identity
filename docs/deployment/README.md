# 部署与候选

本目录描述 #2338 的单副本 Linux amd64 Compose 接口。真实产品启停、登录、SSO 的 T3 分别属于 #2340–#2342；本项 T1/T2 通过不表示生产环境已验收。

- [首次安装与运维](operations.md)
- [候选构建](candidate.md)
- [本地认证候选 T3（#2341）](../../t3/access-local-auth/README.md)

- [#2340 生命周期验收记录](202609120756-2340-lifecycle-acceptance.md)
- [固定候选生命周期 T3](../../t3/identity-lifecycle/README.md)：#2340 的执行入口、故障矩阵和证据边界。
- [停机备份、恢复、轮换与测量](recovery.md)
- [I08 架构决定](../architecture/adr/202609091100-2338-production-assembly.md)

生产输入必须由部署 owner 提供真实域名、证书、存储身份和秘密。deployment/example.json 是字段示例；其中 example.test、UUID 与字节数组均不是生产默认。禁止将渲染目录或秘密作为 artifact 发布。
