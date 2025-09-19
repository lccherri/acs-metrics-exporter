package metrics

import (
	"log"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"acs-metrics-exporter/internal/models"
	"acs-metrics-exporter/internal/repository"
)

type Collector struct {
	repo repository.ACSRepository

	clusterInfo         *prometheus.GaugeVec
	scrapeSuccess  		*prometheus.GaugeVec
	scrapeDuration		*prometheus.GaugeVec
	vulnCount           *prometheus.GaugeVec
	vulnInfo            *prometheus.GaugeVec
	vulnCVSS            *prometheus.GaugeVec
	vulnImpact          *prometheus.GaugeVec
	vulnEnvImpact       *prometheus.GaugeVec
	vulnPublished       *prometheus.GaugeVec
	vulnModified        *prometheus.GaugeVec
	vulnLastScanned     *prometheus.GaugeVec
	vulnOperationSystem *prometheus.GaugeVec
}

func NewCollector(repo repository.ACSRepository) *Collector {
	return &Collector{
		repo: repo,
		clusterInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_cluster_info",
				Help: "Static metadata about clusters",
			},
			[]string{"cluster", "cluster_id"},
		),
		scrapeSuccess: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_scrape_success",
				Help: "Indicates success (1) or failure (0) of scraping vulnerabilities for a cluster and source",
			},
			[]string{"cluster", "source"},
		),
		scrapeDuration: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_scrape_duration_seconds",
				Help: "Duration of vulnerability scrape per cluster and source (in seconds)",
			},
			[]string{"cluster", "source"},
		),
		vulnCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_vulnerabilities_total",
				Help: "Number of vulnerabilities by severity, cluster, and source",
			},
			[]string{"cluster", "severity", "source"},
		),
		vulnInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_vulnerability_info",
				Help: "Vulnerability metadata per cluster (non-numeric fields)",
			},
			[]string{"cluster", "cluster_id", "cve", "severity", "score_version", "fixed_by", "link", "source"},
		),
		vulnCVSS: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_vulnerability_cvss",
				Help: "CVSS score for each vulnerability",
			},
			[]string{"cluster", "cve", "source"},
		),
		vulnImpact: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_vulnerability_impact_score",
				Help: "Impact score of each vulnerability",
			},
			[]string{"cluster", "cve", "source"},
		),
		vulnEnvImpact: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_vulnerability_env_impact",
				Help: "Environmental impact of each vulnerability",
			},
			[]string{"cluster", "cve", "source"},
		),
		vulnPublished: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_vulnerability_published_timestamp",
				Help: "Publication date of the vulnerability (Unix epoch seconds)",
			},
			[]string{"cluster", "cve", "source"},
		),
		vulnModified: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_vulnerability_modified_timestamp",
				Help: "Last modified date of the vulnerability (Unix epoch seconds)",
			},
			[]string{"cluster", "cve", "source"},
		),
		vulnLastScanned: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_vulnerability_scanned_timestamp",
				Help: "Last scanned date for the vulnerability (Unix epoch seconds)",
			},
			[]string{"cluster", "cve", "source"},
		),
		vulnOperationSystem: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "acs_vulnerability_node_os_info",
				Help: "Operating system information for node vulnerabilities",
			},
			[]string{"cluster", "cve", "os"},
		),
	}
}

// Register registers metrics with Prometheus
func (c *Collector) Register() {
	prometheus.MustRegister(c.clusterInfo)
	prometheus.MustRegister(c.scrapeSuccess)
	prometheus.MustRegister(c.scrapeDuration)
	prometheus.MustRegister(c.vulnCount)
	prometheus.MustRegister(c.vulnInfo)
	prometheus.MustRegister(c.vulnCVSS)
	prometheus.MustRegister(c.vulnImpact)
	prometheus.MustRegister(c.vulnEnvImpact)
	prometheus.MustRegister(c.vulnPublished)
	prometheus.MustRegister(c.vulnModified)
	prometheus.MustRegister(c.vulnLastScanned)
	prometheus.MustRegister(c.vulnOperationSystem)
}

// parseTime safely parses a timestamp and returns epoch seconds
func parseTime(ts string) (float64, bool) {
	if ts == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		log.Printf("Invalid time format: %s", ts)
		return 0, false
	}
	return float64(t.Unix()), true
}

// helper to convert concrete slices to []VulnerabilityBase
func toBaseSlice[T models.VulnerabilityBase](in []T) []models.VulnerabilityBase {
	out := make([]models.VulnerabilityBase, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

// updateMetrics updates metrics from a vulnerability
func (c *Collector) updateMetrics(v models.VulnerabilityBase, clusterName, clusterID, source string) {
	// Info metric
	c.vulnInfo.WithLabelValues(
		clusterName,
		clusterID,
		v.GetCVE(),
		v.GetSeverity(),
		v.GetScoreVersion(),
		v.GetFixedBy(),
		v.GetLink(),
		source,
	).Set(1)

	// Numeric metrics
	c.vulnCVSS.WithLabelValues(clusterName, v.GetCVE(), source).Set(v.GetCVSS())
	c.vulnImpact.WithLabelValues(clusterName, v.GetCVE(), source).Set(v.GetImpactScore())
	c.vulnEnvImpact.WithLabelValues(clusterName, v.GetCVE(), source).Set(v.GetEnvImpact())

	// Time metrics
	if ts, ok := parseTime(v.GetPublishedOn()); ok {
		c.vulnPublished.WithLabelValues(clusterName, v.GetCVE(), source).Set(ts)
	}
	if ts, ok := parseTime(v.GetLastModified()); ok {
		c.vulnModified.WithLabelValues(clusterName, v.GetCVE(), source).Set(ts)
	}
	if ts, ok := parseTime(v.GetLastScanned()); ok {
		c.vulnLastScanned.WithLabelValues(clusterName, v.GetCVE(), source).Set(ts)
	}

	switch val := v.(type) {
    case models.NodeVulnerability:
		c.vulnOperationSystem.WithLabelValues(clusterName, v.GetCVE(), val.OperatingSystem).Set(1)
    }


}

// Collect fetches data and updates metrics
func (c *Collector) Collect() {
	clusters, err := c.repo.ListClusters()
	if err != nil {
		log.Printf("Error listing clusters: %v", err)
		return
	}

	for _, cluster := range clusters {
		// Reset metrics for this cluster
		c.clusterInfo.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.scrapeSuccess.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.scrapeDuration.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnCount.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnInfo.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnCVSS.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnImpact.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnEnvImpact.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnPublished.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnModified.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnLastScanned.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnOperationSystem.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})

		// Cluster info
		c.clusterInfo.WithLabelValues(cluster.Name, cluster.ID).Set(1)

		// Map to aggregate vuln counts
		counts := make(map[string]map[string]int)

		// Helper closure para scrape
		scrape := func(source string, fetch func(models.Cluster) ([]models.VulnerabilityBase, error)) {
			vulns, err := fetch(cluster)

			if err != nil {
				log.Printf("Error fetching %s vulns for %s: %v", source, cluster.Name, err)
				c.scrapeSuccess.WithLabelValues(cluster.Name, source).Set(0)
				return
			}

			for _, v := range vulns {
				c.updateMetrics(v, cluster.Name, cluster.ID, source)
				if _, ok := counts[v.GetSeverity()]; !ok {
					counts[v.GetSeverity()] = make(map[string]int)
				}
				counts[v.GetSeverity()][source]++
			}
			c.scrapeSuccess.WithLabelValues(cluster.Name, source).Set(1)
		}

		// Cluster CVEs
		scrape("cluster", func(cl models.Cluster) ([]models.VulnerabilityBase, error) {
			start := time.Now()
			v, err := c.repo.GetClusterVulns(cl)
			duration := time.Since(start).Seconds()
			c.scrapeDuration.WithLabelValues(cl.Name, "cluster").Set(duration)
			if err != nil {
				return nil, err
			}
			return toBaseSlice(v), nil
		})

		// Node CVEs
		scrape("node", func(cl models.Cluster) ([]models.VulnerabilityBase, error) {
			start := time.Now()
			v, err := c.repo.GetNodeVulns(cl)
			duration := time.Since(start).Seconds()
			c.scrapeDuration.WithLabelValues(cl.Name, "node").Set(duration)
			if err != nil {
				return nil, err
			}
			return toBaseSlice(v), nil
		})

		// Image CVEs
		scrape("image", func(cl models.Cluster) ([]models.VulnerabilityBase, error) {
			start := time.Now()
			v, err := c.repo.GetImageVulns(cl)
			duration := time.Since(start).Seconds()
			c.scrapeDuration.WithLabelValues(cl.Name, "image").Set(duration)
			if err != nil {
				return nil, err
			}
			return toBaseSlice(v), nil
		})

		// Set vulnCount with the aggregated values
		for severity, sources := range counts {
			for source, value := range sources {
				c.vulnCount.WithLabelValues(cluster.Name, severity, source).Set(float64(value))
			}
		}
	}
}
