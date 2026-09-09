# syntax=docker/dockerfile:1
ARG RUST_IMAGE
ARG RUNTIME_IMAGE
ARG NGINX_IMAGE
FROM ${RUST_IMAGE} AS build
WORKDIR /build
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
COPY --from=build /build/target/release/identity-server /usr/local/bin/identity-server
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/identity-server"]
FROM ${RUNTIME_IMAGE} AS operator
ARG IDENTITY_REVISION
LABEL org.opencontainers.image.revision=${IDENTITY_REVISION}
COPY --from=build /build/target/release/identity-admin /usr/local/bin/identity-admin
COPY --from=build /build/target/release/identity-migrate /usr/local/bin/identity-migrate
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/identity-migrate"]
FROM scratch AS evidence
COPY --from=build /build/artifacts.json /artifacts.json
COPY --from=build /build/metadata.json /metadata.json
COPY --from=build /build/target/release/identity-server /identity-server
COPY --from=build /build/target/release/identity-admin /identity-admin
COPY --from=build /build/target/release/identity-migrate /identity-migrate
FROM ${NGINX_IMAGE} AS gateway
ARG IDENTITY_REVISION
LABEL org.opencontainers.image.revision=${IDENTITY_REVISION}
COPY ui/ /usr/share/nginx/html/
USER 10001:10001
ENTRYPOINT ["nginx","-g","daemon off;"]
