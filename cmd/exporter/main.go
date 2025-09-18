package main

import (
	"log"
	"net/http"
	"os"
	"time"
	"strconv"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"acs-metrics-exporter/internal/metrics"
	"acs-metrics-exporter/internal/repository"

)

func main() {
	// Load config from environment
	acsEndpoint := os.Getenv("ACS_ENDPOINT")
	acsToken := os.Getenv("ACS_TOKEN")

	// Scrape interval (default 3600 seconds)
	scrapeIntervalStr := os.Getenv("SCRAPE_INTERVAL")
	scrapeInterval := 3600 * time.Second
	if scrapeIntervalStr != "" {
		if val, err := strconv.Atoi(scrapeIntervalStr); err == nil && val > 0 {
			scrapeInterval = time.Duration(val) * time.Second
		} else {
			log.Printf("Invalid SCRAPE_INTERVAL=%s, using default 3600s", scrapeIntervalStr)
		}
	}

	if acsEndpoint == "" || acsToken == "" {
		log.Fatal("Environment variables ACS_ENDPOINT and ACS_TOKEN must be set")
	}

	// Init repository (data access layer)
	repo := repository.NewGraphQLACSRepository(acsEndpoint, acsToken)

	// Init metrics collector
	collector := metrics.NewCollector(repo)

	// Register Prometheus metrics
	collector.Register()

	// Start background collection
	go func() {
		for {
			collector.Collect()
			time.Sleep(scrapeInterval)
		}
	}()

	// Expose /metrics endpoint
	http.Handle("/metrics", promhttp.Handler())
	log.Println("Exporter running on port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
