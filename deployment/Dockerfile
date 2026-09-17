# syntax=docker/dockerfile:1
ARG RUST_IMAGE
ARG RUNTIME_IMAGE
ARG NGINX_IMAGE
FROM --platform=$BUILDPLATFORM ${RUST_IMAGE} AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu=4:12.2.0-3 libc6-dev-amd64-cross=2.36-8cross1 && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-gnu
ENV CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar
RUN rustc -vV > /toolchain.txt && x86_64-linux-gnu-gcc -dumpfullversion >> /toolchain.txt && dpkg-query -W libc6-dev-amd64-cross libc6-amd64-cross linux-libc-dev-amd64-cross >> /toolchain.txt
WORKDIR /build
# The pinned image already contains this compiler; release needs no rustfmt/clippy download.
ENV RUSTUP_TOOLCHAIN=1.96.0
COPY source/ .
# Git authentication is only available to fetch, never build scripts or runtime layers.
RUN --mount=type=secret,id=azure_token,required=false --mount=type=secret,id=azure_header,required=false \
    if [ -s /run/secrets/azure_header ]; then \
      GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.https://dev.azure.com/shengming0923/rss/_git/rss.extraheader \
      GIT_CONFIG_VALUE_0="$(cat /run/secrets/azure_header)" cargo fetch --locked; \
    elif [ -s /run/secrets/azure_token ]; then \
      GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.https://dev.azure.com/shengming0923/rss/_git/rss.extraheader \
      GIT_CONFIG_VALUE_0="AUTHORIZATION: bearer $(cat /run/secrets/azure_token)" cargo fetch --locked; \
    else cargo fetch --locked; fi
RUN --network=none cargo build --offline --locked --release -p rss-identity-app --bins --message-format=json > /build/artifacts.json
RUN --network=none cargo metadata --offline --locked --format-version=1 > /build/metadata.json
FROM ${RUNTIME_IMAGE} AS server
ARG IDENTITY_REVISION
LABEL org.opencontainers.image.revision=${IDENTITY_REVISION}
COPY --from=build /build/target/x86_64-unknown-linux-gnu/release/identity-server /usr/local/bin/identity-server
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/identity-server"]
FROM ${RUNTIME_IMAGE} AS operator
ARG IDENTITY_REVISION
LABEL org.opencontainers.image.revision=${IDENTITY_REVISION}
COPY --from=build /build/target/x86_64-unknown-linux-gnu/release/identity-admin /usr/local/bin/identity-admin
COPY --from=build /build/target/x86_64-unknown-linux-gnu/release/identity-migrate /usr/local/bin/identity-migrate
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/identity-migrate"]
FROM scratch AS evidence
COPY --from=build /toolchain.txt /toolchain.txt
COPY --from=build /build/artifacts.json /artifacts.json
COPY --from=build /build/metadata.json /metadata.json
COPY --from=build /build/target/x86_64-unknown-linux-gnu/release/identity-server /identity-server
COPY --from=build /build/target/x86_64-unknown-linux-gnu/release/identity-admin /identity-admin
COPY --from=build /build/target/x86_64-unknown-linux-gnu/release/identity-migrate /identity-migrate
FROM ${NGINX_IMAGE} AS gateway
ARG IDENTITY_REVISION
LABEL org.opencontainers.image.revision=${IDENTITY_REVISION}
RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/*
COPY ui/ /usr/share/nginx/html/
USER 10001:10001
ENTRYPOINT ["nginx","-e","stderr","-g","daemon off;"]
