# syntax=docker/dockerfile:1
ARG RUST_IMAGE
ARG RUNTIME_IMAGE
FROM ${RUST_IMAGE} AS build
WORKDIR /build
# The pinned image already contains this compiler; release needs no rustfmt/clippy download.
ENV RUSTUP_TOOLCHAIN=1.96.0 CARGO_NET_GIT_FETCH_WITH_CLI=true
COPY . .
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
RUN --network=none python3 hack/check_dependencies.py --metadata /build/metadata.json --artifacts /build/artifacts.json
FROM ${RUNTIME_IMAGE} AS runtime
ARG IDENTITY_REVISION
LABEL org.opencontainers.image.revision=${IDENTITY_REVISION}
COPY --from=build /build/target/release/identity-server /usr/local/bin/identity-server
COPY --from=build /build/target/release/identity-admin /usr/local/bin/identity-admin
COPY --from=build /build/target/release/identity-migrate /usr/local/bin/identity-migrate
RUN test "${#IDENTITY_REVISION}" = 40 && test -z "$(printf '%s' "$IDENTITY_REVISION" | tr -d '0-9a-f')"
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/identity-server"]
