package repository

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"acs-metrics-exporter/internal/models"
)

// Repository interface for ACS
type ACSRepository interface {
	ListClusters() ([]models.Cluster, error)
	GetClusterVulns(cluster models.Cluster) ([]models.ClusterVulnerability, error)
	GetNodeVulns(cluster models.Cluster) ([]models.NodeVulnerability, error)
	GetImageVulns(cluster models.Cluster) ([]models.ImageVulnerability, error)
}

// Implementation using GraphQL
type GraphQLACSRepository struct {
	endpoint string
	token    string

	queryListClusters string
	queryClusterCves  string
	queryNodeCves     string
	queryImageCves    string
}

// GraphQL request struct
type GraphQLRequest struct {
	OperationName string                 `json:"operationName"`
	Variables     map[string]interface{} `json:"variables"`
	Query         string                 `json:"query"`
}

// NewGraphQLACSRepository initializes repository
func NewGraphQLACSRepository(endpoint, token string) ACSRepository {
	return &GraphQLACSRepository{
		endpoint:          endpoint + "/api/graphql",
		token:             token,
		queryListClusters: loadQuery("list_clusters.graphql"),
		queryClusterCves:  loadQuery("getClusterCLUSTER_CVE.graphql"),
		queryNodeCves:     loadQuery("getClusterNODE_CVE.graphql"),
		queryImageCves:    loadQuery("getClusterIMAGE_CVE.graphql"),
	}
}

// Load query from file
func loadQuery(file string) string {
	path := filepath.Join("graphql", file)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read GraphQL query file %s: %v", path, err)
	}
	return string(data)
}

// helper to truncate logs
func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// Perform GraphQL request (with debug)
func (r *GraphQLACSRepository) gqlRequest(payload GraphQLRequest) ([]byte, error) {
	data, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", r.endpoint, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: os.Getenv("ACS_INSECURE_SKIP_TLS_VERIFY") == "true"},
	}
	client := &http.Client{Timeout: 60 * time.Second, Transport: tr}

	if os.Getenv("ACS_DEBUG") == "true" {
		log.Printf("[DEBUG] GraphQL endpoint: %s", r.endpoint)
		log.Printf("[DEBUG] Operation: %s", payload.OperationName)
		log.Printf("[DEBUG] Variables: %+v", payload.Variables)
		log.Printf("[DEBUG] Query (first 400 chars): %s", truncate(payload.Query, 400))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if os.Getenv("ACS_DEBUG") == "true" {
		log.Printf("[DEBUG] Response status: %s", resp.Status)
		log.Printf("[DEBUG] Response headers: %+v", resp.Header)
		log.Printf("[DEBUG] Response body (first 1000 chars): %s", truncate(string(body), 1000))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GraphQL request failed: status=%s, response=%s", resp.Status, truncate(string(body), 500))
	}

	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid JSON response from ACS: %q", string(body))
	}

	return body, nil
}

// ListClusters implements ACSRepository
func (r *GraphQLACSRepository) ListClusters() ([]models.Cluster, error) {
	payload := GraphQLRequest{
		OperationName: "listClusters",
		Variables:     map[string]interface{}{},
		Query:         r.queryListClusters,
	}

	body, err := r.gqlRequest(payload)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data struct {
			Clusters []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"clusters"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var clusters []models.Cluster
	for _, c := range resp.Data.Clusters {
		clusters = append(clusters, models.Cluster{ID: c.ID, Name: c.Name})
	}
	return clusters, nil
}

// GetClusterVulns implements ACSRepository: use ID-based query (cluster(id: $id) { ... })
func (r *GraphQLACSRepository) GetClusterVulns(cluster models.Cluster) ([]models.ClusterVulnerability, error) {
	payload := GraphQLRequest{
		OperationName: "getClusterCLUSTER_CVE",
		Variables: map[string]interface{}{
			"id":         cluster.ID,
			"query":      "", // keep empty (UI often sends it)
			"policyQuery": "",
			"scopeQuery": fmt.Sprintf("CLUSTER ID:\"%s\"", cluster.ID),
			// pagination omitted per your request (server may accept absent)
		},
		Query: r.queryClusterCves,
	}

	body, err := r.gqlRequest(payload)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data struct {
			Result struct {
				ClusterVulnerabilities []models.ClusterVulnerability `json:"clusterVulnerabilities"`
			} `json:"result"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal cluster response: %w", err)
	}

	if os.Getenv("ACS_DEBUG") == "true" {
		log.Printf("[DEBUG] getClusterCLUSTER_CVE: returned %d items", len(resp.Data.Result.ClusterVulnerabilities))
	}

	return resp.Data.Result.ClusterVulnerabilities, nil
}

// GetNodeVulns implements ACSRepository: use ID-based cluster query
func (r *GraphQLACSRepository) GetNodeVulns(cluster models.Cluster) ([]models.NodeVulnerability, error) {
	payload := GraphQLRequest{
		OperationName: "getClusterNODE_CVE",
		Variables: map[string]interface{}{
			"id":          cluster.ID,
			"query":       "",
			"policyQuery": "",
			"scopeQuery":  fmt.Sprintf("CLUSTER ID:\"%s\"", cluster.ID),
		},
		Query: r.queryNodeCves,
	}

	body, err := r.gqlRequest(payload)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data struct {
			Result struct {
				NodeVulnerabilities []models.NodeVulnerability `json:"nodeVulnerabilities"`
			} `json:"result"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal node response: %w", err)
	}

	if os.Getenv("ACS_DEBUG") == "true" {
		log.Printf("[DEBUG] getClusterNODE_CVE: returned %d items", len(resp.Data.Result.NodeVulnerabilities))
	}

	return resp.Data.Result.NodeVulnerabilities, nil
}

// GetImageVulns implements ACSRepository: use ID-based cluster query
func (r *GraphQLACSRepository) GetImageVulns(cluster models.Cluster) ([]models.ImageVulnerability, error) {
	payload := GraphQLRequest{
		OperationName: "getClusterIMAGE_CVE",
		Variables: map[string]interface{}{
			"id":          cluster.ID,
			"query":       "",
			"policyQuery": "",
			"scopeQuery":  fmt.Sprintf("CLUSTER ID:\"%s\"", cluster.ID),
		},
		Query: r.queryImageCves,
	}

	body, err := r.gqlRequest(payload)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data struct {
			Result struct {
				ImageVulnerabilities []models.ImageVulnerability `json:"imageVulnerabilities"`
			} `json:"result"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal image response: %w", err)
	}

	if os.Getenv("ACS_DEBUG") == "true" {
		log.Printf("[DEBUG] getClusterIMAGE_CVE: returned %d items", len(resp.Data.Result.ImageVulnerabilities))
	}

	return resp.Data.Result.ImageVulnerabilities, nil
}
