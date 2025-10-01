package main

import (
	"context" // Adicionado para passar para o Collect
	"log"
	"net/http"
	"os"
	"runtime" // Adicionado para obter a versão do Go
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	// Caminhos de import ajustados para a nova estrutura
	"acs-metrics-exporter/internal/metrics"
	"acs-metrics-exporter/internal/repository"
)

// AppVersion é a versão da aplicação, pode ser injetada durante o build.
var AppVersion = "v2.0.0" // Definido como uma variável global

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
	// O nome do pacote foi alterado de 'metrics' para 'collector'
	collector := metrics.NewCollector(repo)

	// Register Prometheus metrics
	// Agora passamos a versão da app e a versão do Go para a métrica de build info
	goVersion := runtime.Version()
	collector.Register(AppVersion, goVersion)

	// Start background collection
	go func() {
		// Criamos um contexto raiz para passar para as coletas
		ctx := context.Background()
		for {
			// A função Collect agora espera um contexto
			collector.Collect(ctx)
			log.Printf("Scrape finished. Next scrape in %v.", scrapeInterval)
			time.Sleep(scrapeInterval)
		}
	}()

	// Expose /metrics endpoint
	http.Handle("/metrics", promhttp.Handler())
	log.Printf("Exporter version %s running on port %d", AppVersion, metricsPort)
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(metricsPort), nil))
}


