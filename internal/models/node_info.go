package models

// NodeInfo contains information about a node affected by a CVE.
type NodeInfo struct {
    ID              string      `json:"id"`
    Name            string      `json:"name"`
    OperatingSystem string      `json:"operatingSystem"`
    Cluster         ClusterInfo `json:"cluster"`
}