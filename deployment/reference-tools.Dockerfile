# Disposable test operator/browser tools; product images remain independent.
# ref: microsoft/playwright v1.60.0 packages/playwright-core/src/server/browserContext.ts
FROM docker:28-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d AS docker
FROM mcr.microsoft.com/playwright:v1.60.0-noble@sha256:9bd26ad900bb5e0f4dee75839e957a89ae89c2b7ab1e76050e559790e946b948
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
RUN apt-get update && apt-get install -y --no-install-recommends libnss3-tools \
    && rm -rf /var/lib/apt/lists/*
# Same package and integrity as the frozen Web lock; no second npm project.
RUN curl --fail --silent --show-error https://registry.npmjs.org/playwright-core/-/playwright-core-1.60.0.tgz -o /tmp/playwright.tgz \
    && python3 -c "import base64,hashlib; assert base64.b64encode(hashlib.sha512(open('/tmp/playwright.tgz','rb').read()).digest()).decode() == '9bW6zvX/m0lEbgTKJ6YppOKx8H3VOPBMOCFh2irXFOT4BbHgrx5hPjwJYLT40Lu+4qtD36qKc/Hn56StUW57IA=='" \
    && python3 -c "import base64,hashlib,pathlib;pathlib.Path('/opt/playwright-integrity').write_text('sha512-'+base64.b64encode(hashlib.sha512(open('/tmp/playwright.tgz','rb').read()).digest()).decode())" \
    && mkdir /opt/playwright-core && tar xzf /tmp/playwright.tgz -C /opt/playwright-core --strip-components=1 \
    && rm /tmp/playwright.tgz
ARG REFERENCE_REVISION
LABEL org.opencontainers.image.revision=${REFERENCE_REVISION}
