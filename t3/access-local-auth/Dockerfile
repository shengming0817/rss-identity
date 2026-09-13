FROM mcr.microsoft.com/playwright:v1.60.0-noble@sha256:9bd26ad900bb5e0f4dee75839e957a89ae89c2b7ab1e76050e559790e946b948
# Snapshot metadata is authenticated by Ubuntu's keyring; package indexes bind .deb SHA256.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* && \
    printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20260912T000000Z noble main universe\n\
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20260912T000000Z noble-updates main universe\n\
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20260912T000000Z noble-security main universe\n' > /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
      python3=3.12.3-0ubuntu2.1 openssl=3.0.13-0ubuntu3.15 libnss3-tools=2:3.98-1ubuntu0.2 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /carrier
COPY package.json pnpm-lock.yaml ./
# Verify the complete distribution before executing any pnpm code (including install hooks).
RUN curl --fail --silent --show-error --location https://registry.npmjs.org/pnpm/-/pnpm-11.4.0.tgz -o /tmp/pnpm.tgz && \
    node --input-type=module -e "import{readFileSync}from'node:fs';import{createHash}from'node:crypto';if(createHash('sha512').update(readFileSync('/tmp/pnpm.tgz')).digest('base64')!=='8P68fjdVKrSFSUqRQkGzOOCzWAuT1UzjHwCTMBWICGMSkDihtK5OQUoO5jrDW/IRl+mQFyxKaCVkULVjYxCWjw==')process.exit(1)" && \
    mkdir /opt/pnpm && tar -xzf /tmp/pnpm.tgz -C /opt/pnpm --strip-components=1 && \
    ln -s /opt/pnpm/bin/pnpm.mjs /usr/local/bin/pnpm && rm /tmp/pnpm.tgz && \
    pnpm install --frozen-lockfile --ignore-scripts
COPY *.py *.mjs ./
RUN mkdir -p /home/t32/.pki/nssdb && chown -R 10001:10001 /home/t32 && useradd -u 10001 -d /home/t32 t32
ENV NODE_NO_WARNINGS=1
USER 10001:10001
