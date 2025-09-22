package models

type Cluster struct {
    ID   string `json:"id"`
    Name string `json:"name"`
    Type string `json:"type"`
}

type ClusterResponse struct {
    Data struct {
        Clusters []Cluster `json:"clusters"`
    } `json:"data"`
}
