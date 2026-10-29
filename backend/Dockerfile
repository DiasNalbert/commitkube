# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" GOOS=linux go build -o kubecommit-api .

# Runtime stage
FROM alpine:3.20

# git and ssh clone repositories for scanning; Trivy runs the scans. The
# single-container image at the repository root carries the same tools, and
# without them every scan in a compose setup failed.
RUN apk add --no-cache ca-certificates sqlite wget git openssh-client \
    && wget -qO /tmp/trivy-install.sh https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    && chmod +x /tmp/trivy-install.sh \
    && /tmp/trivy-install.sh -b /usr/local/bin \
    && rm /tmp/trivy-install.sh

# Opengrep runs the static analysis, with the rules embedded in the API
# binary. Pinned by checksum, the same version as the root image.
ARG TARGETARCH=amd64
ARG OPENGREP_VERSION=v1.31.0
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) og_arch=x86;     og_sha=02c9fba481611aa0664bc79ccf7ce59e9e334b76af8921c80b2f738d17fabf9b ;; \
      arm64) og_arch=aarch64; og_sha=b7cbedab0b6c9953ea27ce3baa006ad8b6fa1c50ee7433638b63f7fc731519d9 ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    wget -qO /tmp/opengrep "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_musllinux_${og_arch}"; \
    echo "$og_sha  /tmp/opengrep" | sha256sum -c -; \
    install -m 0755 /tmp/opengrep /usr/local/bin/opengrep; \
    rm /tmp/opengrep

WORKDIR /app

COPY --from=builder /app/kubecommit-api .

EXPOSE 8080

CMD ["./kubecommit-api"]
