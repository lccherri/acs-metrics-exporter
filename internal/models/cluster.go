package models

// Cluster represents a Kubernetes cluster managed by ACS
type Cluster struct {
	ID   string
	Name string
}

// Vulnerability represents a vulnerability detected by ACS
// type Vulnerability struct {
// 	CVE               string
// 	Severity          string
// 	CVSS              float64
// 	ImpactScore       float64
// 	EnvImpact         float64
// 	FixedBy           string
// 	Link              string
// 	ScoreVersion      string
// 	PublishedOn       string // stored as RFC3339 string, converted to epoch in collector
// 	LastModified      string // stored as RFC3339 string, converted to epoch in collector
// 	LastScanned       string // stored as RFC3339 string, converted to epoch in collector
// 	VulnerabilityType string
// }
