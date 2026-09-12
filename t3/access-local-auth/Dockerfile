FROM mcr.microsoft.com/playwright:v1.60.0-noble@sha256:9bd26ad900bb5e0f4dee75839e957a89ae89c2b7ab1e76050e559790e946b948
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl libnss3-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /carrier
COPY package.json pnpm-lock.yaml ./
RUN npm install --global pnpm@11.4.0 && pnpm install --frozen-lockfile --ignore-scripts
COPY *.py *.mjs ./
RUN mkdir -p /home/t32/.pki/nssdb && chown -R 10001:10001 /home/t32 && useradd -u 10001 -d /home/t32 t32
ENV NODE_NO_WARNINGS=1
USER 10001:10001
