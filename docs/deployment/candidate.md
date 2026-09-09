# 固定候选构建

1. Identity 与 rss-web 都使用干净、固定完整 Git SHA。仅构建 rss-web/apps/identity：设置 RSS_IDENTITY_WEB_REVISION 为该仓 HEAD，运行 pnpm --filter @rss/identity-app build 和 pnpm check:identity-app:build。
2. 在 Identity 运行 make ci CI_BASE=origin/develop。构建工具链Rust1.96.0；生产和测试RSS feature分别验证。
3. `make candidate CANDIDATE_OUTPUT=/absolute/new-candidate IDENTITY_UI_SOURCE=/absolute/fixed-rss-web IDENTITY_UI_DIST=/absolute/fixed-rss-web/apps/identity/dist`。目标目录必须尚不存在。私有 RSS 获取使用 SYSTEM_ACCESSTOKEN，仅传递为BuildKit secret到fetch步骤；编译步骤无网络和Git认证。
4. 交付candidate.json、server/operator/gateway OCI archive、binaries目录与部署模板。记录实际命令、结果及未覆盖项。镜像/二进制版本与schema/config身份是不同轴，不把artifact digest写入deployment表。

candidate.json绑定Identity版本/SHA/lock、RSS Git来源与版本、实际Linux编译feature、UI源码/lock/dist摘要、迁移摘要、provider镜像摘要及OCI manifest/归档/二进制摘要。它证明候选构建身份，不表示registry已发布，也不证明生产T3。

azure-candidate.yml提供手动流水线：需要部署管理员配置只读GitHub service connection（默认名称rss-web-read），并允许job token读取RSS Git。该配置不是已运行流水线的证据。实际输出通过Pipeline Artifact发布，不要求镜像registry。

候选构建在原生 build platform 上交叉编译 linux/amd64；Dockerfile 显式安装目标 libc 开发头文件，避免 ARM 主机把宿主头文件用于 x86_64。release 的 Python 子进程使用当前解释器，最低 Python 3.11，避免 Make 的 PATH 改写选择旧解释器。#2377 仅修复构建入口，不改变应用与 SDK 契约。
非 root gateway 冒烟将全部 NGINX 临时目录指向可写 /tmp，包括 proxy_temp_path，保持与交付镜像 UID 10001 一致。
