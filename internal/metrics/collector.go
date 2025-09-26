// internal/collector/collector.go
package metrics

import (
	"context"
	"log"
	"time"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"acs-metrics-exporter/internal/models"
	"acs-metrics-exporter/internal/repository"
)

// Collector holds the repository and Prometheus metrics.
type Collector struct {
	repo repository.ACSRepository

	// Exporter Metrics
	scrapeSuccess         *prometheus.GaugeVec
	scrapeDuration        *prometheus.GaugeVec
	exporterBuildInfo     *prometheus.GaugeVec

	// Cluster Metrics
	clusterInfo           *prometheus.GaugeVec

	// Vulnerability Metrics
	// vulnerabilitiesTotal              	 *prometheus.GaugeVec
	// vulnerabilityInfo                 	 *prometheus.GaugeVec
	imageVulnerabilityInfo           		 *prometheus.GaugeVec
	nodeVulnerabilityInfo            		 *prometheus.GaugeVec
	platformVulnerabilityInfo        		 *prometheus.GaugeVec
	vulnerabilityCvss                 		 *prometheus.GaugeVec
	vulnerabilityEnvImpact           		 *prometheus.GaugeVec
	vulnerabilityImpactScore           	 	 *prometheus.GaugeVec
	vulnerabilityPublishedTimestamp   		 *prometheus.GaugeVec
	vulnerabilityLastModifiedTimestamp 		 *prometheus.GaugeVec
	vulnerabilityLastScannedTimestamp 		 *prometheus.GaugeVec
	vulnerabilitySuppressExpiryTimestamp	 *prometheus.GaugeVec
	vulnerabilitySuppressActivationTimestamp *prometheus.GaugeVec
	vulnerabilityCreatedAtTimestamp  		 *prometheus.GaugeVec
	vulnerabilityDiscoveredAtImageTimestamp	 *prometheus.GaugeVec
	vulnerableNodeInfo			   			 *prometheus.GaugeVec
	vulnerableClusterInfo             		 *prometheus.GaugeVec
	vulnerableDeploymentInfo    			 *prometheus.GaugeVec
	vulnerableImageInfo         			 *prometheus.GaugeVec
	vulnerableNodeComponentInfo          	 *prometheus.GaugeVec
}

// NewCollector creates a new collector with all metric definitions.
func NewCollector(repo repository.ACSRepository) *Collector {
	return &Collector{
		repo: repo,
		scrapeSuccess: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_scrape_success", Help: "Indicates success (1) or failure (0) of scraping data for a scope."},
			[]string{"scope"},
		),
		scrapeDuration: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_scrape_duration_seconds", Help: "Duration of the data scrape for a scope."},
			[]string{"scope"},
		),
		exporterBuildInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_exporter_build_info", Help: "Build information for the ACS Metrics Exporter."},
			[]string{"version", "go_version"},
		),
		clusterInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_secured_cluster_info", Help: "Information about the monitored clusters."},
			[]string{"secured_cluster_id", "secured_cluster_name", "secured_cluster_type"},
		),

		// Image specific CVE vulnerability metrics
		imageVulnerabilityInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_image_vulnerability_info", Help: "Detailed vulnerability info scoped to container images."},
			[]string{"cve", "severity", "is_fixable", "fixed_by_version", "cve_link", "is_suppressed", "vulnerability_state", "operating_system"},
		),
		vulnerabilityDiscoveredAtImageTimestamp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerability_discovered_at_image_timestamp_seconds", Help: "The date the CVE was discovered in an image, in Unix Timestamp format."},
			[]string{"cve"},
		),
		vulnerableImageInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerable_image_info", Help: "Associates a CVE to a specific container image. Value is always 1."},
			[]string{"cve", "image_full_name", "image_tag", "image_remote", "image_registry"},
		),
		vulnerableDeploymentInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerable_deployment_info", Help: "Associates a CVE to a specific running workload. Value is always 1."},
			[]string{"cve", "image_full_name", "secured_cluster_name", "deployment_name", "deployment_namespace", "is_platform_component"},
		),
		
		// Node specific CVE vulnerability metrics
		nodeVulnerabilityInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_node_vulnerability_info", Help: "Detailed vulnerability info scoped to cluster nodes."},
			[]string{"cve", "severity", "is_fixable", "fixed_by_version", "cve_link", "is_suppressed"},
		),
		vulnerableNodeInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerable_node_info", Help: "Associates a CVE to a specific cluster node. Value is always 1."},
			[]string{"cve", "node_name", "secured_cluster_name"},
		),
		vulnerableNodeComponentInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerable_component_info", Help: "Indicates that a specific component is vulnerable to a CVE. Value is always 1."},
			[]string{"cve", "node_name", "secured_cluster_name", "component_name", "component_version", "fixed_in"}, // TODO Verify if fixed_in is time or version
		),

		// Platform specific CVE vulnerability metrics
		platformVulnerabilityInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_platform_vulnerability_info", Help: "Detailed vulnerability info scoped to platform (cluster-level)."},
			[]string{"cve", "severity", "is_fixable", "fixed_by_version", "cve_link", "is_suppressed", "vulnerability_type"},
		),
		vulnerableClusterInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerable_cluster_info", Help: "Indicates that a specific cluster is affected by a CVE. Value is always 1."},
			[]string{"cve", "secured_cluster_name", "type"},
		),

		// General vulnerability metrics that apply to all scopes
		vulnerabilityCvss: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerability_cvss", Help: "The CVSS score of a vulnerability. The value of the metric is the score itself."},
			[]string{"cve", "score_version"},
		),
		vulnerabilityEnvImpact: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerability_env_impact", Help: "The environmental impact score of a vulnerability. The value of the metric is the score itself."},
			[]string{"cve", "score_version"},
		),
		vulnerabilityImpactScore: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerability_impact_score", Help: "The impact score of a vulnerability. The value of the metric is the score itself."},
			[]string{"cve", "score_version"},
		),
		vulnerabilityCreatedAtTimestamp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerability_created_at_timestamp_seconds", Help: "The creation date of the CVE, in Unix Timestamp format."},
			[]string{"cve", "scope"},
		),
		vulnerabilityPublishedTimestamp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerability_published_timestamp_seconds", Help: "The publication date of the CVE, in Unix Timestamp format."},
			[]string{"cve", "scope"},
		),
		vulnerabilityLastModifiedTimestamp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerability_last_modified_timestamp_seconds", Help: "The modification date of the CVE, in Unix Timestamp format."},
			[]string{"cve", "scope"},
		),
		vulnerabilityLastScannedTimestamp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerability_last_scanned_timestamp_seconds", Help: "The date the CVE was scanned, in Unix Timestamp format."},
			[]string{"cve", "scope"},
		),
		vulnerabilitySuppressExpiryTimestamp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerability_suppress_expiry_timestamp_seconds", Help: "The date the CVE suppression expires, in Unix Timestamp format."},
			[]string{"cve", "scope"},
		),
		vulnerabilitySuppressActivationTimestamp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "acs_vulnerability_suppress_activation_timestamp_seconds", Help: "The date the CVE suppression becomes active, in Unix Timestamp format."},
			[]string{"cve", "scope"},
		),

	}
}

// Register registers all metrics with the Prometheus registry.
func (c *Collector) Register(appVersion string, goVersion string) {
	// (O conteúdo desta função permanece o mesmo)
	c.exporterBuildInfo.WithLabelValues(appVersion, goVersion).Set(1)
	prometheus.MustRegister(
		c.scrapeSuccess,
		c.scrapeDuration,
		c.exporterBuildInfo,
		c.clusterInfo,
		c.imageVulnerabilityInfo,
		c.nodeVulnerabilityInfo,
		c.platformVulnerabilityInfo,
		c.vulnerabilityCvss,
		c.vulnerabilityEnvImpact,
		c.vulnerabilityImpactScore,
		c.vulnerabilityPublishedTimestamp,
		c.vulnerabilityLastModifiedTimestamp,
		c.vulnerabilityLastScannedTimestamp,
		c.vulnerabilitySuppressExpiryTimestamp,
		c.vulnerabilitySuppressActivationTimestamp,
		c.vulnerabilityCreatedAtTimestamp,
		c.vulnerabilityDiscoveredAtImageTimestamp,
		c.vulnerableNodeInfo,
		c.vulnerableNodeComponentInfo,
		c.vulnerableClusterInfo,
		c.vulnerableDeploymentInfo,
		c.vulnerableImageInfo,
		// c.vulnerabilitiesTotal,
		// c.vulnerabilityInfo,
	)
}

// parseTime safely parses a timestamp and returns epoch seconds
func parseTime(ts *string) (float64, bool) {
    if ts == nil || *ts == "" {
        return 0, false
    }
    t, err := time.Parse(time.RFC3339, *ts)
    if err != nil {
        log.Printf("Invalid time format: %s", *ts)
        return 0, false
    }
    return float64(t.Unix()), true
}

// Collect is the main method that fetches data and updates the Prometheus metrics.
func (c *Collector) Collect(ctx context.Context) {
	// --- Cluster Collection ---
	c.collectClusters(ctx)

	// --- Vulnerability Collection ---
	c.collectVulnerabilities(ctx)
}

// collectClusters fetches cluster data and updates cluster-related metrics.
func (c *Collector) collectClusters(ctx context.Context) {
	// (O conteúdo desta função permanece o mesmo)
	log.Println("Collecting cluster info...")
	start := time.Now()
	clusters, err := c.repo.ListClusters()
	duration := time.Since(start).Seconds()
	c.scrapeDuration.WithLabelValues("cluster").Set(duration)
	if err != nil {
		log.Printf("Error fetching cluster info: %v", err)
		c.scrapeSuccess.WithLabelValues("cluster").Set(0)
		return
	}
	c.scrapeSuccess.WithLabelValues("cluster").Set(1)
	c.clusterInfo.Reset()
	for _, cluster := range clusters {
		c.clusterInfo.WithLabelValues(cluster.ID, cluster.Name, cluster.Type).Set(1)
	}
}

// collectVulnerabilities orchestrates the collection of all vulnerability types.
func (c *Collector) collectVulnerabilities(ctx context.Context) {
	log.Println("Collecting vulnerabilities...")

	// Reset all vulnerability metrics before each scrape
	c.scrapeSuccess.Reset()
	c.scrapeDuration.Reset()
	c.clusterInfo.Reset()
	c.imageVulnerabilityInfo.Reset()
	c.nodeVulnerabilityInfo.Reset()
	c.platformVulnerabilityInfo.Reset()
	c.vulnerabilityCvss.Reset()
	c.vulnerabilityEnvImpact.Reset()
	c.vulnerabilityImpactScore.Reset()
	c.vulnerabilityPublishedTimestamp.Reset()
	c.vulnerabilityLastModifiedTimestamp.Reset()
	c.vulnerabilityLastScannedTimestamp.Reset()
	c.vulnerabilitySuppressExpiryTimestamp.Reset()
	c.vulnerabilitySuppressActivationTimestamp.Reset()
	c.vulnerabilityCreatedAtTimestamp.Reset()
	c.vulnerabilityDiscoveredAtImageTimestamp.Reset()
	c.vulnerableNodeInfo.Reset()
	c.vulnerableNodeComponentInfo.Reset()
	c.vulnerableClusterInfo.Reset()
	c.vulnerableDeploymentInfo.Reset()
	c.vulnerableImageInfo.Reset()

	// --- Image Vulnerabilities ---
	startImg := time.Now()
	imageVulns, err := c.repo.GetImageVulns()

	c.scrapeDuration.WithLabelValues("image_vulnerability").Set(time.Since(startImg).Seconds())
	if err != nil {
		log.Printf("Error fetching image vulnerabilities: %v", err)
		c.scrapeSuccess.WithLabelValues("image_vulnerability").Set(0)
	} else {
		log.Printf("Processing %d image vulnerabilities...", len(imageVulns))
		c.scrapeSuccess.WithLabelValues("image_vulnerability").Set(1)

		for _, v := range imageVulns {
			c.imageVulnerabilityInfo.WithLabelValues(
				v.CVE, v.Severity, strconv.FormatBool(v.IsFixable), v.FixedByVersion, v.Link, 
				strconv.FormatBool(v.Suppressed), v.VulnerabilityState, v.OperatingSystem,
				).Set(1)
			if ts, ok := parseTime(v.DiscoveredAtImage); ok {
				c.vulnerabilityDiscoveredAtImageTimestamp.WithLabelValues(v.CVE).Set(ts)
			}
			c.populateBaseVulnerabilityMetrics(v.BaseVulnerability, "image")
			for _, img := range v.Images {
				c.vulnerableImageInfo.WithLabelValues(
					v.CVE, img.Name.FullName, img.Name.Tag, img.Name.Remote, img.Name.Registry,
					).Set(1)
				for _, dep := range img.Deployments {
					c.vulnerableDeploymentInfo.WithLabelValues(
						v.CVE, img.Name.FullName, dep.Cluster.Name, dep.Name, dep.Namespace,
						strconv.FormatBool(dep.PlatformComponent),
						).Set(1)
				}
			}
		}
	}

	// --- Node Vulnerabilities ---
	startNode := time.Now()
	nodeVulns, err := c.repo.GetNodeVulns()
	c.scrapeDuration.WithLabelValues("node_vulnerability").Set(time.Since(startNode).Seconds())
	if err != nil {
		log.Printf("Error fetching node vulnerabilities: %v", err)
		c.scrapeSuccess.WithLabelValues("node_vulnerability").Set(0)
	} else {
		log.Printf("Processing %d node vulnerabilities...", len(nodeVulns))
		c.scrapeSuccess.WithLabelValues("node_vulnerability").Set(1)
		for _, v := range nodeVulns {
			c.nodeVulnerabilityInfo.WithLabelValues(
				v.CVE, v.Severity, strconv.FormatBool(v.IsFixable), 
				v.FixedByVersion, v.Link, strconv.FormatBool(v.Suppressed),
				).Set(1)
			c.populateBaseVulnerabilityMetrics(v.BaseVulnerability, "node")
			for _, node := range v.Nodes {
				c.vulnerableNodeInfo.WithLabelValues(
					v.CVE, node.Name, node.Cluster.Name,
				).Set(1)
				for _, comp := range node.NodeComponents {
					// Cluster name added to labels to avoid Node name collisions across clusters
					c.vulnerableNodeComponentInfo.WithLabelValues(
						v.CVE, node.Name, node.Cluster.Name, comp.Name, comp.Version, comp.FixedIn,
						).Set(1)
				}
			}
		}
	}

	// --- Cluster Vulnerabilities (Platform) ---
	startCluster := time.Now()
	clusterVulns, err := c.repo.GetClusterVulns()
	c.scrapeDuration.WithLabelValues("platform_vulnerability").Set(time.Since(startCluster).Seconds())
	if err != nil {
		log.Printf("Error fetching platform vulnerabilities: %v", err)
		c.scrapeSuccess.WithLabelValues("platform_vulnerability").Set(0)
	} else {
		log.Printf("Processing %d platform vulnerabilities...", len(clusterVulns))
		c.scrapeSuccess.WithLabelValues("platform_vulnerability").Set(1)
		for _, v := range clusterVulns {
			c.platformVulnerabilityInfo.WithLabelValues(
				v.CVE, v.Severity, strconv.FormatBool(v.IsFixable), v.FixedByVersion,
				v.Link, strconv.FormatBool(v.Suppressed), v.VulnerabilityType,
				).Set(1)
			c.populateBaseVulnerabilityMetrics(v.BaseVulnerability, "platform")
			for _, cluster := range v.Clusters {
				c.vulnerableClusterInfo.WithLabelValues(
					v.CVE, cluster.Name, cluster.Type,
					).Set(1)
			}
		}
	}

}

// populateBaseVulnerabilityMetrics sets the metrics that are common to all vulnerability types.
func (c *Collector) populateBaseVulnerabilityMetrics(v models.BaseVulnerability, scope string) {

	// Numeric metrics
	if v.CVSS != nil {
		c.vulnerabilityCvss.WithLabelValues(v.CVE, v.ScoreVersion).Set(*v.CVSS)
	}
	if v.EnvImpact != nil {
		c.vulnerabilityEnvImpact.WithLabelValues(v.CVE, v.ScoreVersion).Set(*v.EnvImpact)
	}
	if v.ImpactScore != nil {
		c.vulnerabilityImpactScore.WithLabelValues(v.CVE, v.ScoreVersion).Set(*v.ImpactScore)
	}
	
	// Timestamp Metrics
	if ts, ok := parseTime(v.CreatedAt); ok {
		c.vulnerabilityCreatedAtTimestamp.WithLabelValues(v.CVE, scope).Set(ts)
	}
	if ts, ok := parseTime(v.PublishedOn); ok {
		c.vulnerabilityPublishedTimestamp.WithLabelValues(v.CVE, scope).Set(ts)
	}
	if ts, ok := parseTime(v.LastModified); ok {
		c.vulnerabilityLastModifiedTimestamp.WithLabelValues(v.CVE, scope).Set(ts)
	}
	if ts, ok := parseTime(v.LastScanned); ok {
		c.vulnerabilityLastScannedTimestamp.WithLabelValues(v.CVE, scope).Set(ts)
	}
	if ts, ok := parseTime(v.SuppressExpiry); ok {
		c.vulnerabilitySuppressExpiryTimestamp.WithLabelValues(v.CVE, scope).Set(ts)
	}
	if ts, ok := parseTime(v.SuppressActivation); ok {
		c.vulnerabilitySuppressActivationTimestamp.WithLabelValues(v.CVE, scope).Set(ts)
	}

}