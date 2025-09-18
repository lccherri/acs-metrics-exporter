DOCKER_CLI?=docker

# Variables
# MODULE_NAME=github.com/lccherri/acs-metrics-exporter
MODULE_NAME=acs-metrics-exporter
BINARY_NAME=acs-metrics-exporter
IMAGE_NAME=acs-metrics-exporter:latest

# Go version target
GO_VERSION=1.25

# Default target
all: tidy build

# Initialize go module (only first time)
init:
	go mod init $(MODULE_NAME)
	go get github.com/prometheus/client_golang@latest
	go mod tidy

# Update dependencies
tidy:
	go mod tidy

# Build local binary
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) main.go

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
		-e ACS_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6Imp3dGswIiwidHlwIjoiSldUIn0.eyJFeHBpcmVBdCI6IjIwMjUtMTEtMzBUMDM6MDA6MDBaIiwiYXVkIjoiaHR0cHM6Ly9zdGFja3JveC5pby9qd3Qtc291cmNlcyNhcGktdG9rZW5zIiwiZXhwIjoxNzY0NDcxNjAwLCJpYXQiOjE3NTgxNzIzMjMsImlzcyI6Imh0dHBzOi8vc3RhY2tyb3guaW8vand0IiwianRpIjoiY2QwZjA0NDItNjhiNS00OTM1LWEzYjQtOWRmZDExOTc2ZDk0IiwibmFtZSI6ImFwaS1yZWFkb25seSIsInJvbGVzIjpbIkFuYWx5c3QiXX0.SQxo7GHJ8KKyYGQUEAmCdOUmoMlOej-vOn0WZEaGOZoq9ZCQ9wP8AVYQTNqvc_XU-vKV6qogtpb7EWa7kbP71Bns85wUBTZTv9e0tUnE9L9Hk5hf7BIjVL8cU8SQ93D5OOFpJyn7SwZN9J-IiLeXt1d1FPdKwO5gunN4LSCTe_yRcSzsXQ_UaaVLheYG2BA2EGPhO3fD6YG0JjgNswhbJIJdsBRzws6L1TPogmZcmNlK25rDz1nKtsvfebmcYBNAlLJTOTrQR-s8dIZFUogU8c9e5xdY6AtSxshJYHIkjoQyB6rOBx2iVUnjkJbOgu24lfybvVjJn5rjN4C5ptM6xweqBCc3rPPJq6vQUGAmgszm6XnMrmtmm3jSUK-n1AOgFlYxWrfHS-Skq5VZD-zZAjzfy9MrliDdnuh1wEhp2ggZTkYSGgNhD2d3gQwZvoHKUaDoLEv8lZ3XTguU8d__KKLoQJv2MxIzX1GY6_Pb2wGCrqPjB_PLUJpZjJuTXtzfM-5qrWkZP0sH4OHYL7lwhT9t37qpnJhkYQIs0swFk5G3WPVBJlGHKULbHcAI9h7mbOVzC29VZiUnmJuE3D7hqlRB4QqLf8o4ueOtJ0_yqTEazcr2SF5-Ky9DncfSan9G8tSC9EgzNeWlnCWuvRtcFmRxHOGkQ7gbevFznJKPSC4" \
		-e SCRAPE_INTERVAL="600" \
		-e ACS_INSECURE_SKIP_TLS_VERIFY="true" \
		$(IMAGE_NAME)

.PHONY: all init tidy build clean image run
