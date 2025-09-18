
# ACS Metrics Exporter

The **ACS Metrics Exporter** is a Prometheus exporter designed to collect and expose vulnerability data from Red Hat Advanced Cluster Security (RHACS).  
It fetches information from multiple RHACS sources (clusters, nodes, and images) and provides structured Prometheus metrics for monitoring and alerting.

## Prerequisites
- Go 1.21+
- Docker or Podman
- Access to a running RHACS environment (Central API)
- Prometheus or another monitoring system to scrape the exporter

## Usage
The project includes a `Makefile` for common development and build tasks.

### Main Makefile Commands

| Command            | Description                                                                                                   |
|--------------------|---------------------------------------------------------------------------------------------------------------|
| `make init`        | Initializes the Go module and fetches dependencies (only required the first time).                           |
| `make tidy`        | Updates and cleans up Go module dependencies.                                                                 |
| `make build`       | Builds the local binary (`acs-metrics-exporter`) for Linux (amd64).                                           |
| `make clean`       | Removes the compiled binary.                                                                                  |
| `make image`       | Builds the container image using Docker/Podman. Image name defaults to `acs-metrics-exporter:latest`.         |
| `make run`         | Runs the exporter container locally, exposing port `8080` and using the provided environment variables.       |
| `make all`         | Runs `tidy` and `build` (default target).                                                                     |

**Environment variables for `make run`:**
- `ACS_ENDPOINT` – RHACS Central API endpoint (e.g., `https://central-stackrox.apps.cluster.example.com`)  
- `ACS_TOKEN` – API token with read access  
- `SCRAPE_INTERVAL` – Time between scrapes (default: `3600` seconds)  
- `ACS_INSECURE_SKIP_TLS_VERIFY` – Set `true` to skip TLS verification (not recommended for production)  


## Metrics
The exporter provides the following Prometheus metrics:

| Metric Name                               | Description                                                       | Labels                                                                 |
|-------------------------------------------|-------------------------------------------------------------------|------------------------------------------------------------------------|
| `acs_vulnerabilities_total`               | Number of vulnerabilities grouped by severity, cluster, and source | `cluster`, `severity`, `source`                                       |
| `acs_vulnerability_info`                  | Metadata about each vulnerability (non-numeric fields)             | `cluster`, `cluster_id`, `cve`, `severity`, `score_version`, `fixed_by`, `link`, `source` |
| `acs_vulnerability_cvss`                  | CVSS score of the vulnerability                                   | `cluster`, `cve`, `source`                                            |
| `acs_vulnerability_impact_score`          | Impact score of the vulnerability                                 | `cluster`, `cve`, `source`                                            |
| `acs_vulnerability_env_impact`            | Environmental impact score                                        | `cluster`, `cve`, `source`                                            |
| `acs_vulnerability_published_timestamp`   | Publication date of the CVE (Unix epoch seconds)                  | `cluster`, `cve`, `source`                                            |
| `acs_vulnerability_modified_timestamp`    | Last modification date of the CVE (Unix epoch seconds)            | `cluster`, `cve`, `source`                                            |
| `acs_vulnerability_scanned_timestamp`     | Last scan timestamp for the vulnerability (Unix epoch seconds)    | `cluster`, `cve`, `source`                                            |

## Notes
- Metrics are refreshed at each scrape by querying the RHACS Central API.  
- Time-related metrics are exposed as Unix epoch timestamps.  
- This exporter is designed to work in Kubernetes/OpenShift environments but can also run standalone.

