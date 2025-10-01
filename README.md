
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
- `SCRAPE_INTERVAL` – Time between scrapes (default: `1h`)
- `ACS_INSECURE_SKIP_TLS_VERIFY` – Set `true` to skip TLS verification (not recommended for production)
- `METRICS_PORT` – Port on which the exporter serves Prometheus metrics (default: `8080`)

## Metrics
The exporter provides the following Prometheus metrics:

| Metric                                                  | Explanation                                                                                     | Labels                                                                                                      |
|:--------------------------------------------------------|:------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------|
| acs_exporter_build_info                                 | Build information for the ACS Metrics Exporter.                                                 | go_version, version                                                                                         |
| acs_image_vulnerability_info                            | Detailed vulnerability info scoped to container images.                                         | cve, cve_link, fixed_by_version, is_fixable, is_suppressed, operating_system, severity, vulnerability_state |
| acs_node_vulnerability_info                             | Detailed vulnerability info scoped to cluster nodes.                                            | cve, cve_link, fixed_by_version, is_fixable, is_suppressed, severity                                        |
| acs_platform_vulnerability_info                         | Detailed vulnerability info scoped to platform (cluster-level).                                 | cve, cve_link, fixed_by_version, is_fixable, is_suppressed, severity, vulnerability_type                    |
| acs_scrape_duration_seconds                             | Duration of the data scrape for a scope.                                                        | scope                                                                                                       |
| acs_scrape_success                                      | Indicates success (1) or failure (0) of scraping data for a scope.                              | scope                                                                                                       |
| acs_secured_cluster_info                                | Information about the monitored clusters.                                                       | secured_cluster_id, secured_cluster_name, secured_cluster_type                                              |
| acs_vulnerability_created_at_timestamp_seconds          | The creation date of the CVE, in Unix Timestamp format.                                         | cve, scope                                                                                                  |
| acs_vulnerability_cvss                                  | The CVSS score of a vulnerability. The value of the metric is the score itself.                 | cve, scope, score_version                                                                                   |
| acs_vulnerability_discovered_at_image_timestamp_seconds | The date the CVE was discovered in an image, in Unix Timestamp format.                          | cve                                                                                                         |
| acs_vulnerability_env_impact                            | The environmental impact score of a vulnerability. The value of the metric is the score itself. | cve, scope, score_version                                                                                   |
| acs_vulnerability_impact_score                          | The impact score of a vulnerability. The value of the metric is the score itself.               | cve, scope, score_version                                                                                   |
| acs_vulnerability_last_modified_timestamp_seconds       | The modification date of the CVE, in Unix Timestamp format.                                     | cve, scope                                                                                                  |
| acs_vulnerability_last_scanned_timestamp_seconds        | The date the CVE was scanned, in Unix Timestamp format.                                         | cve, scope                                                                                                  |
| acs_vulnerability_published_timestamp_seconds           | The publication date of the CVE, in Unix Timestamp format.                                      | cve, scope                                                                                                  |
| acs_vulnerable_cluster_info                             | Indicates that a specific cluster is affected by a CVE. Value is always 1.                      | cve, secured_cluster_name, secured_cluster_type                                                             |
| acs_vulnerable_component_info                           | Indicates that a specific component is vulnerable to a CVE. Value is always 1.                  | component_name, component_version, cve, fixed_in, node_name, secured_cluster_name                           |
| acs_vulnerable_deployment_info                          | Associates a CVE to a specific running workload. Value is always 1.                             | cve, deployment_name, deployment_namespace, image_full_name, is_platform_component, secured_cluster_name    |
| acs_vulnerable_image_info                               | Associates a CVE to a specific container image. Value is always 1.                              | cve, image_full_name, image_registry, image_remote, image_tag                                               |
| acs_vulnerable_node_info                                | Associates a CVE to a specific cluster node. Value is always 1.                                 | cve, node_name, secured_cluster_name                                                                        |

## Using Helm Chart

To deploy the ACS Metrics Exporter using Helm, run:

```bash
helm install acs-metrics-exporter \
    --set fullnameOverride=acs-metrics-exporter \
    --set secret.acsToken=<your-acs-api-token> \
    -n stackrox \ # namespace where the central is expected to be running
    ./charts/acs-metrics-exporter/
```

**Replace `<your-acs-api-token>` with your actual RHACS API token.**  
Do not share or commit sensitive tokens.

You can customize other values using `--set` or by editing the `values.yaml` file.  
For a full list of configurable options, see the [Helm chart documentation](./charts/acs-metrics-exporter/README.md).

## Notes
- Metrics are refreshed at each scrape by querying the RHACS Central API.  
- Time-related metrics are exposed as Unix epoch timestamps.  
- This exporter is designed to work in Kubernetes/OpenShift environments but can also run standalone.

