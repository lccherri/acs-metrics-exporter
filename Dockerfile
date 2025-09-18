# ================================
# Stage 1 - Build
# ================================
FROM docker.io/golang:1.25 AS builder

# Set working dir
WORKDIR /app

# Enable static build
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# Copy go mod and download deps
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .


# Build binary (main at cmd/exporter)
RUN go build -o acs-metrics-exporter ./cmd/exporter

# ================================
# Stage 2 - Minimal runtime
# ================================
FROM scratch

# Set working dir
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/acs-metrics-exporter /app/acs-metrics-exporter

# Copy GraphQL queries (required at runtime)
COPY --from=builder /app/graphql /app/graphql

# Expose Prometheus metrics port
EXPOSE 8080

# Entrypoint
ENTRYPOINT ["/app/acs-metrics-exporter"]
