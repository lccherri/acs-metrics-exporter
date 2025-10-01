DOCKER_CLI?=docker

# Variables
# MODULE_NAME=github.com/lccherri/acs-metrics-exporter
MODULE_NAME=acs-metrics-exporter
BINARY_NAME=acs-metrics-exporter
IMAGE_NAME=acs-metrics-exporter:latest

# Go version target
GO_VERSION=1.25
SRC_DIR=source

# Default target
all: tidy build

# Initialize go module (only first time)
init:
	cd $(SRC_DIR) && go mod init $(MODULE_NAME)
	cd $(SRC_DIR) && go get github.com/prometheus/client_golang@latest
	cd $(SRC_DIR) && go mod tidy

# Update dependencies
tidy:
	cd $(SRC_DIR) && go mod tidy

# Build local binary
build:
	cd $(SRC_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../$(BINARY_NAME) ./cmd/exporter

# Clean binary
clean:
	rm -f $(BINARY_NAME)

# Build container image with docker
image:
	$(DOCKER_CLI) build -t $(IMAGE_NAME) .

# Run container locally
run:
	$(DOCKER_CLI) run --rm -p 8080:8080 \
		-e ACS_ENDPOINT="https://central-stackrox.apps.cluster-drkdl.drkdl.sandbox2071.opentlc.com" \
		-e ACS_TOKEN="$(ACS_TOKEN)" \
		-e SCRAPE_INTERVAL="5m" \
		-e ACS_INSECURE_SKIP_TLS_VERIFY="true" \
		$(IMAGE_NAME)

.PHONY: all init tidy build clean image run
