// internal/repository/graphql.go
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
	"strconv"
	"time"

	"acs-metrics-exporter/internal/models"
)

// ACSRepository defines the interface for fetching data from ACS.
type ACSRepository interface {
	ListClusters() ([]models.Cluster, error)
	GetClusterVulns() ([]models.ClusterVulnerability, error)
	GetNodeVulns() ([]models.NodeVulnerability, error)
	GetImageVulns() ([]models.ImageVulnerability, error)
}

// GraphQLACSRepository is the implementation of ACSRepository using GraphQL.
type GraphQLACSRepository struct {
	endpoint string
	token    string

	queryListClusters string
	queryClusterVulns string
	queryNodeVulns    string
	queryImageVulns   string
}

// GraphQLRequest represents the JSON payload for a GraphQL request.
type GraphQLRequest struct {
	OperationName string         `json:"operationName"`
	Variables     map[string]any `json:"variables"`
	Query         string         `json:"query"`
}

// GraphQLResponse is a generic structure to unmarshal the top-level GraphQL response.
type GraphQLResponse[T any] struct {
	Data   map[string]T   `json:"data"`
	Errors []GraphQLError `json:"errors,omitempty"`
}

// GraphQLError represents an error returned by the GraphQL API.
type GraphQLError struct {
	Message string `json:"message"`
}

// NewGraphQLACSRepository initializes the repository.
func NewGraphQLACSRepository(endpoint, token string) ACSRepository {
	return &GraphQLACSRepository{
		endpoint:          endpoint + "/api/graphql",
		token:             token,
		queryListClusters: loadQuery("clusters.graphql"),
		queryClusterVulns: loadQuery("cluster_vulns.graphql"),
		queryNodeVulns:    loadQuery("node_vulns.graphql"),
		queryImageVulns:   loadQuery("image_vulns.graphql"),
	}
}

// loadQuery loads a GraphQL query from a file.
func loadQuery(file string) string {
	path := filepath.Join("graphql", file)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read GraphQL query file %s: %v", path, err)
	}
	return string(data)
}

// --- Public Methods ---

func (r *GraphQLACSRepository) ListClusters() ([]models.Cluster, error) {
	log.Println("Fetching all clusters...")
	payload := GraphQLRequest{
		OperationName: "listClusters",
		Query:         r.queryListClusters,
		Variables:     make(map[string]any), // Empty variables
	}

	body, err := r.gqlRequest(payload)
	if err != nil {
		return nil, err
	}

	var resp GraphQLResponse[[]models.Cluster]
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal listClusters response: %w", err)
	}
	if len(resp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL API returned an error for ListClusters: %s", resp.Errors[0].Message)
	}

	results := resp.Data["clusters"]
	log.Printf("Successfully fetched %d clusters.\n", len(results))
	return results, nil
}

func (r *GraphQLACSRepository) GetImageVulns() ([]models.ImageVulnerability, error) {
	log.Println("Fetching image vulnerabilities with pagination...")
	return fetchWithPagination[models.ImageVulnerability](
		r,
		"getImageVulnerabilities",
		"imageVulnerabilities",
		r.queryImageVulns,
		map[string]any{"query": ""},
	)
}

func (r *GraphQLACSRepository) GetNodeVulns() ([]models.NodeVulnerability, error) {
	log.Println("Fetching node vulnerabilities with pagination...")
	return fetchWithPagination[models.NodeVulnerability](
		r,
		"getNodeVulnerabilities",
		"nodeVulnerabilities",
		r.queryNodeVulns,
		map[string]any{"query": ""},
	)
}

func (r *GraphQLACSRepository) GetClusterVulns() ([]models.ClusterVulnerability, error) {
	log.Println("Fetching cluster vulnerabilities with pagination...")
	return fetchWithPagination[models.ClusterVulnerability](
		r,
		"getClusterVulnerabilities",
		"clusterVulnerabilities",
		r.queryClusterVulns,
		map[string]any{"query": ""},
	)
}

// --- Private Helpers ---

// gqlRequest performs the actual HTTP request to the GraphQL endpoint.
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
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GraphQL request failed: status=%s, response: %s", resp.Status, string(body))
	}

	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid JSON response from ACS: %q", string(body))
	}

	return body, nil
}

// fetchWithPagination is a generic function to fetch paginated results.
func fetchWithPagination[T any](
	r *GraphQLACSRepository,
	operationName, queryKey, gqlQuery string,
	variables map[string]any,
) ([]T, error) {

	var allResults []T
	offset := 0
	limit := 200 // default page size

	// allow override via env
	if v := os.Getenv("ACS_PAGE_LIMIT"); v != "" {
		if l, err := strconv.Atoi(v); err == nil && l > 0 {
			limit = l
		}
	}

	previousCount := -1

	for {
		// copy base variables (e.g., "query")
		vars := make(map[string]any)
		for k, v := range variables {
			vars[k] = v
		}

		// always overwrite pagination
		vars["pagination"] = map[string]any{
			"limit":  limit,
			"offset": offset,
			"sortOptions": []map[string]any{
				{"field": "CVE", "reversed": false},
			},
		}

		payload := GraphQLRequest{
			OperationName: operationName,
			Query:         gqlQuery,
			Variables:     vars,
		}

		// DEBUG: log the full payload being sent
		// queryJSON, _ := json.MarshalIndent(payload, "", "  ")
		// log.Printf("GraphQL request (page offset=%d): %s", offset, string(queryJSON))

		body, err := r.gqlRequest(payload)
		if err != nil {
			return nil, err
		}

		var resp struct {
			Data map[string][]T `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		batch := resp.Data[queryKey]
		allResults = append(allResults, batch...)

		log.Printf("Fetched page with %d %s (offset=%d, total=%d)",
			len(batch), queryKey, offset, len(allResults))

		// stop if no new data or incomplete page
		if len(batch) == 0 || len(allResults) == previousCount || len(batch) < limit {
			break
		}

		previousCount = len(allResults)
		offset += limit
	}

	log.Printf("Fetched %d %s.\n", len(allResults), queryKey)
	return allResults, nil
}
