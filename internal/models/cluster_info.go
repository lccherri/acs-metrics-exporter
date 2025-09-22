package models

// ClusterInfo contains basic information about a cluster.
type ClusterInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type,omitempty"` // omitempty because it's not present in all queries
}
