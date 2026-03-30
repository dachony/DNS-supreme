# Stage 1: Build frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/web/frontend
COPY web/frontend/package*.json ./
RUN npm install
COPY web/frontend/ ./
RUN npm run build

# Stage 2: Build Go backend
FROM golang:1.23-alpine AS backend-builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o /dns-supreme ./cmd/dns-supreme

# Stage 3: Final image
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=backend-builder /dns-supreme /app/dns-supreme
COPY --from=frontend-builder /app/web/frontend/dist /app/web/dist
COPY configs/default.json /app/configs/default.json

EXPOSE 53/udp 53/tcp 80 443 853/tcp 853/udp 8080

ENTRYPOINT ["/app/dns-supreme"]
