ARG BROWSER_IMAGE
FROM ${BROWSER_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends libnss3-tools python3 openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /runner
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts && npm cache clean --force
COPY browser.mjs ./
USER 10001:10001
ENTRYPOINT ["node", "/runner/browser.mjs"]
