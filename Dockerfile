FROM golang:1.22-alpine AS go-builder
RUN apk add --no-cache gcc musl-dev sqlite-dev
WORKDIR /app
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ .
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" GOOS=linux go build -o kubecommit-api .

FROM node:20-alpine AS node-builder
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend/ .
ENV NEXT_PUBLIC_API_URL=/api
RUN npm run build

# The external tools: Trivy for the scans, Helm and Kustomize for GitOps.
# Versions and checksums are pinned so a build can only ever install
# exactly these files. Trivy especially: v0.69.4 was a malicious release
# (CVE-2026-33634), and "whatever is latest at build time" is how such a
# release ends up inside an image without anyone choosing it.
FROM alpine:3.23 AS tools
ARG TARGETARCH=amd64
ARG TRIVY_VERSION=0.76.1
ARG HELM_VERSION=v3.22.1
ARG KUSTOMIZE_VERSION=v5.8.3
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) trivy_arch=64bit; \
             trivy_sha=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0; \
             helm_sha=896cf63684a42a723d61c980369d6e588330927deb13676ca0d85006dd6da0ea; \
             kust_sha=cb9e31198d3f63b44848bd0afc4c8efc56e6cfef9c93a4a39a211940e6decd61 ;; \
      arm64) trivy_arch=ARM64; \
             trivy_sha=e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f; \
             helm_sha=4c29e286b279d170fa048ddfc3e4e83dcd069ca9c52102766ba672d7149e694d; \
             kust_sha=9867b76482cfc6d25b546abc1d2b5a32bd137505aba640649b4b378f64f6d68f ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    wget -qO /tmp/trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz"; \
    echo "$trivy_sha  /tmp/trivy.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    chmod 0755 /usr/local/bin/trivy; \
    wget -qO /tmp/helm.tgz "https://get.helm.sh/helm-${HELM_VERSION}-linux-${TARGETARCH}.tar.gz"; \
    echo "$helm_sha  /tmp/helm.tgz" | sha256sum -c -; \
    tar -xzf /tmp/helm.tgz -C /tmp "linux-${TARGETARCH}/helm"; \
    install -m 0755 "/tmp/linux-${TARGETARCH}/helm" /usr/local/bin/helm; \
    wget -qO /tmp/kustomize.tgz "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2F${KUSTOMIZE_VERSION}/kustomize_${KUSTOMIZE_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    echo "$kust_sha  /tmp/kustomize.tgz" | sha256sum -c -; \
    tar -xzf /tmp/kustomize.tgz -C /usr/local/bin kustomize; \
    chmod 0755 /usr/local/bin/kustomize

FROM node:20-alpine
RUN apk add --no-cache ca-certificates sqlite wget git openssh-client
COPY --from=tools /usr/local/bin/trivy /usr/local/bin/helm /usr/local/bin/kustomize /usr/local/bin/

# nginx comes from nginx.org's own Alpine repository: Alpine's stable branch
# ships 1.28, which gets no fix for CVE-2026-15176 and friends. The version
# floor makes the build fail instead of quietly falling back to Alpine's.
RUN wget -qO /etc/apk/keys/nginx_signing.rsa.pub https://nginx.org/keys/nginx_signing.rsa.pub \
    && echo "https://nginx.org/packages/alpine/v$(cut -d. -f1,2 /etc/alpine-release)/main" >> /etc/apk/repositories \
    && apk add --no-cache 'nginx>=1.30.6'

WORKDIR /app

COPY --from=go-builder /app/kubecommit-api ./kubecommit-api
COPY --from=node-builder /app/public ./public
COPY --from=node-builder /app/.next/standalone ./
COPY --from=node-builder /app/.next/static ./.next/static
COPY nginx.conf /etc/nginx/nginx.conf
COPY start.sh ./start.sh
RUN chmod +x ./start.sh

EXPOSE 80

CMD ["./start.sh"]
