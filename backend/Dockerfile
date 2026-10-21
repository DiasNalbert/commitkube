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

WORKDIR /app

COPY --from=builder /app/kubecommit-api .

EXPOSE 8080

CMD ["./kubecommit-api"]
