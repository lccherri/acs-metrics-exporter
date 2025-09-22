package models

// DeploymentInfo contains information about a deployment affected by a CVE.
type DeploymentInfo struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Namespace string      `json:"namespace"`
	Cluster   ClusterInfo `json:"cluster"`
}