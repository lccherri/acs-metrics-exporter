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
	scrapeInterval := time.Hour

	if scrapeIntervalStr := os.Getenv("SCRAPE_INTERVAL"); scrapeIntervalStr != "" {
		if d, err := time.ParseDuration(scrapeIntervalStr); err == nil && d > 0 {
			scrapeInterval = d
		} else {
			log.Printf("Invalid SCRAPE_INTERVAL=%s, using default 1h", scrapeIntervalStr)
		}
	}

	if acsEndpoint == "" || acsToken == "" {
		log.Fatal("Environment variables ACS_ENDPOINT and ACS_TOKEN must be set")
	}

	metricsPort := 8080
	metricsPortStr := os.Getenv("METRICS_PORT")
	if metricsPortStr != "" {
		if val, err := strconv.Atoi(metricsPortStr); err == nil && val > 0 {
			metricsPort = val
		} else {
			log.Printf("Invalid METRICS_PORT=%s, using default 8080", metricsPortStr)
		}
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
	log.Println("Exporter running on port", metricsPort)
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(metricsPort), nil))
}
