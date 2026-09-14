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

RUN apk add --no-cache ca-certificates sqlite

WORKDIR /app

COPY --from=builder /app/kubecommit-api .

EXPOSE 8080

CMD ["./kubecommit-api"]
