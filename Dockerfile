# ================================
# Stage 1 - Build
# ================================
FROM docker.io/golang:1.25 AS builder

# Set working dir
WORKDIR /app

# Enable static build
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# Copy source code
COPY ./source .

# Download deps
RUN go mod download

# Build binary (main at cmd/exporter)
RUN go build -o acs-metrics-exporter ./cmd/exporter

# ================================
# Stage 2 - Minimal runtime
# ================================
FROM scratch

# Set working dir
WORKDIR /app

# Copy binary and GraphQL queries with correct ownership/permissions
COPY --from=builder --chown=1001:0 /app/acs-metrics-exporter /app/acs-metrics-exporter
COPY --from=builder --chown=1001:0 /app/graphql /app/graphql

# Drop root privileges
USER 1001

# Expose Prometheus metrics port
EXPOSE 8080

# Entrypoint
ENTRYPOINT ["/app/acs-metrics-exporter"]