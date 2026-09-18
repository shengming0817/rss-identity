# 独立镜像构建

后端只产出一个 linux/amd64 镜像，包含 identity-server、identity-migrate、identity-admin，默认入口为服务。正式入口要求干净 HEAD，以 git archive 固定构建上下文；revision 和基础镜像从该提交与 providers.lock 派生，不接受外部覆盖。构建仅使用本仓源码和固定 Cargo.lock；不读取 rss-web 或静态目录，不需要 Node。生产 release compiler artifacts 由现有 check_dependencies.check_artifacts/check_features 验证，私有 Git 凭据仅提供给 cargo fetch 的 BuildKit secret。

```sh
make image IDENTITY_IMAGE=rss-identity:my-version
# 私有 Git：设置 IDENTITY_GIT_AUTH_HEADER_FILE（0600 的 Authorization header 文件）
# 或 SYSTEM_ACCESSTOKEN；不要将秘密放进 build-arg。
```

前端在 rss-web 通过 `pnpm image:identity --tag rss-identity-web:my-version` 独立构建。该薄入口也使用干净 HEAD 的源码归档并派生 Web revision。它拥有 Node 构建、静态检查、Web revision 和 Nginx 镜像；后端和前端版本独立。交付镜像的 revision 必须对应构建源码，正式联合验证使用各仓最终提交。

在目标 Docker daemon 上准备镜像，跨主机可显式从选定来源 `docker pull --platform linux/amd64 <image>`。PostgreSQL 与 volume-init 的 Debian 镜像使用 deployment/providers.lock.json 中固定来源，也须预先显式拉取对应平台。本轮不提供 registry 或发布流水线。

渲染只接受 `--identity-image` 与 `--web-image`：本地 inspect 验证平台、非 root 用户和各自 revision，再将不可变 image ID 写入 compose.json。identity、migrate、maintenance 共用同一个 ID，gateway 使用 Web ID；所有服务禁止隐式拉取。Compose 是运行配置，无额外候选清单。缺失镜像、错误平台或旧 `--candidate`、`make candidate` 参数失败，不自动转换。

不再生产/消费 candidate.json、强制 OCI tar 或裸二进制目录。历史候选与验收记录只作历史来源，不构成新部署前提。备份回执格式见[恢复](recovery.md)。

显式接缝验证在隔离 Linux Docker 主机以 root 部署 owner 运行，提供 Python、openssl、Docker/Compose 与已准备的工具镜像（providers.lock 的 rust，仅作为 HTTP 测试客户端）：

```sh
make test-reference IDENTITY_IMAGE=rss-identity:my-version WEB_IMAGE=rss-identity-web:my-version PREVIOUS_WEB_IMAGE=rss-identity-web:previous-version REFERENCE_RECORD=/private/result.json REFERENCE_WORK=/private/new-fixture
```

PREVIOUS_WEB_IMAGE 仅是测试输入，需提供不同的已准备 Web image ID，以核验前端单独升级及旧备份继续可用。结果记录 image ID、双方 revision、真实步骤与清理结果，只记录验证结果，不成为部署输入。源码 HTTP/UI 联调仍可显式运行 `make test-ui`，不进入后端常规 CI 或镜像构建。独立产品 T3 仍归 #2366。

对标源码：[Moby v28.3.3 ImageInspect](https://github.com/moby/moby/blob/v28.3.3/daemon/images/image_inspect.go)、[NGINX release-1.30.0 proxy](https://github.com/nginx/nginx/blob/release-1.30.0/src/http/modules/ngx_http_proxy_module.c)。只复用公开 CLI/协议行为，未复制源码。
