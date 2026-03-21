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
RUN apk add --no-cache ca-certificates sqlite nginx wget

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
