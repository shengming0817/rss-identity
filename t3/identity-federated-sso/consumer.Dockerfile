ARG RUST_IMAGE
FROM --platform=$BUILDPLATFORM ${RUST_IMAGE} AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu=4:12.2.0-3 libc6-dev-amd64-cross=2.36-8cross1 && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-gnu
ENV CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar RUSTC_WRAPPER="" CARGO_TARGET_DIR=/target
WORKDIR /source
COPY . .
RUN cargo fetch --locked --manifest-path tests/consumer/Cargo.toml
RUN --network=none cargo build --offline --locked --release --manifest-path tests/consumer/Cargo.toml --bin identity-federated-t3-consumer
RUN rustc -vV > /target/toolchain.txt
FROM scratch
COPY --from=build /target/x86_64-unknown-linux-gnu/release/identity-federated-t3-consumer /identity-federated-t3-consumer
COPY --from=build /target/toolchain.txt /toolchain.txt
