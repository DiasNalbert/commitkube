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

FROM node:20-alpine
RUN apk add --no-cache ca-certificates sqlite wget git openssh-client

# nginx comes from nginx.org's own Alpine repository: Alpine's stable branch
# ships 1.28, which gets no fix for CVE-2026-15176 and friends. The version
# floor makes the build fail instead of quietly falling back to Alpine's.
RUN wget -qO /etc/apk/keys/nginx_signing.rsa.pub https://nginx.org/keys/nginx_signing.rsa.pub \
    && echo "https://nginx.org/packages/alpine/v$(cut -d. -f1,2 /etc/alpine-release)/main" >> /etc/apk/repositories \
    && apk add --no-cache 'nginx>=1.30.6'

# Install Trivy
RUN wget -qO /tmp/trivy-install.sh https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    && chmod +x /tmp/trivy-install.sh \
    && /tmp/trivy-install.sh -b /usr/local/bin \
    && rm /tmp/trivy-install.sh

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
