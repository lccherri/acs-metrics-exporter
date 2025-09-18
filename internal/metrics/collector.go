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

	vulnCount       *prometheus.GaugeVec
	vulnInfo        *prometheus.GaugeVec
	vulnCVSS        *prometheus.GaugeVec
	vulnImpact      *prometheus.GaugeVec
	vulnEnvImpact   *prometheus.GaugeVec
	vulnPublished   *prometheus.GaugeVec
	vulnModified    *prometheus.GaugeVec
	vulnLastScanned *prometheus.GaugeVec
}

func NewCollector(repo repository.ACSRepository) *Collector {
	return &Collector{
		repo: repo,
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
	}
}

// Register registers metrics with Prometheus
func (c *Collector) Register() {
	prometheus.MustRegister(c.vulnCount)
	prometheus.MustRegister(c.vulnInfo)
	prometheus.MustRegister(c.vulnCVSS)
	prometheus.MustRegister(c.vulnImpact)
	prometheus.MustRegister(c.vulnEnvImpact)
	prometheus.MustRegister(c.vulnPublished)
	prometheus.MustRegister(c.vulnModified)
	prometheus.MustRegister(c.vulnLastScanned)
}

// parseTime safely parses a timestamp and returns epoch seconds
func parseTime(ts string) float64 {
	if ts == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		log.Printf("Invalid time format: %s", ts)
		return 0
	}
	return float64(t.Unix())
}

// updateMetrics atualiza métricas a partir de uma vulnerabilidade
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
	c.vulnPublished.WithLabelValues(clusterName, v.GetCVE(), source).Set(parseTime(v.GetPublishedOn()))
	c.vulnModified.WithLabelValues(clusterName, v.GetCVE(), source).Set(parseTime(v.GetLastModified()))
	c.vulnLastScanned.WithLabelValues(clusterName, v.GetCVE(), source).Set(parseTime(v.GetLastScanned()))
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
		c.vulnCount.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnInfo.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnCVSS.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnImpact.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnEnvImpact.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnPublished.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnModified.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})
		c.vulnLastScanned.DeletePartialMatch(prometheus.Labels{"cluster": cluster.Name})

		// Map to aggregate vuln counts
		counts := make(map[string]map[string]int)

		// Cluster CVEs
		if clusterVulns, err := c.repo.GetClusterVulns(cluster); err == nil {
			for _, v := range clusterVulns {
				c.updateMetrics(v, cluster.Name, cluster.ID, "cluster")
				if _, ok := counts[v.GetSeverity()]; !ok {
					counts[v.GetSeverity()] = make(map[string]int)
				}
				counts[v.GetSeverity()]["cluster"]++
			}
		}

		// Node CVEs
		if nodeVulns, err := c.repo.GetNodeVulns(cluster); err == nil {
			for _, v := range nodeVulns {
				c.updateMetrics(v, cluster.Name, cluster.ID, "node")
				if _, ok := counts[v.GetSeverity()]; !ok {
					counts[v.GetSeverity()] = make(map[string]int)
				}
				counts[v.GetSeverity()]["node"]++
			}
		}

		// Image CVEs
		if imageVulns, err := c.repo.GetImageVulns(cluster); err == nil {
			for _, v := range imageVulns {
				c.updateMetrics(v, cluster.Name, cluster.ID, "image")
				if _, ok := counts[v.GetSeverity()]; !ok {
					counts[v.GetSeverity()] = make(map[string]int)
				}
				counts[v.GetSeverity()]["image"]++
			}
		}

		// Set vulnCount with the aggregated values
		for severity, sources := range counts {
			for source, value := range sources {
				c.vulnCount.WithLabelValues(cluster.Name, severity, source).Set(float64(value))
			}
		}
	}
}
