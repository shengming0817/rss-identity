# 镜像构建

后端使用当前工作树构建，不要求干净 HEAD 或先提交。构建上下文受 [.dockerignore](../../.dockerignore) 限制，基础镜像由 [providers.lock.json](../../deployment/providers.lock.json) 固定。

```sh
make image IDENTITY_IMAGE=rss-identity:my-version
```

私有 Git 依赖使用 `IDENTITY_GIT_AUTH_HEADER_FILE=/private/header`（完整 Authorization header）或 `SYSTEM_ACCESSTOKEN`；凭据只通过 BuildKit secret 供 fetch，不能放入 build-arg。构建使用锁定依赖，随后离线编译并检查生产依赖。不要在源码允许的构建目录内放秘密或本地产物。

前端由 rss-web 的 `pnpm image:identity --tag rss-identity-web:my-version` 独立构建；其构建要求归 Web 仓库。后端不要求 Web checkout，也不核对两仓 commit 或 lock。

在目标 Docker context 准备后端、前端及 provider 镜像，必要时显式 `docker pull`。部署通过 daemon inspect 取得实际不可变 image ID；Identity、迁移、维护使用同一后端 ID，网关使用 Web ID。Compose 禁止隐式拉取，由当前 daemon 选择平台。无需 OCI tar、候选清单或源码 revision 标签。

## 功能验收

`make test-reference` 是独立按需的真实浏览器、认证、轮换与恢复入口，不进入普通 CI。它构建浏览器工具镜像，把当前必要脚本传入一次性私有卷，使用实际后端/Web 镜像、TLS PostgreSQL 和内网 Keycloak。

```sh
make test-reference IDENTITY_IMAGE=rss-identity:my-version WEB_IMAGE=rss-identity-web:my-version REFERENCE_RECORD=/absolute/private/new-result.json
```

结果路径必须是尚不存在的绝对路径。工具只清理本轮拥有的容器、网络和卷；失败、中断或清理未确认都不能报告通过。Docker socket 与所选 context 必须连接同一 daemon。实际密码、cookie、CSRF、TOTP、code、verifier 和 client secret 仅存在私有 fixture，不能进入结果。

结果记录实际环境、功能步骤、失败、清理及未覆盖范围；通过只表示本轮功能场景成功，不声明性能 SLO。无容量负载、基线或人工批准流程，也不读取旧报告。历史结果保留在原 PR/归档，不能替代当前运行。旧环境退役和消费产品验收不由此入口自动完成。
