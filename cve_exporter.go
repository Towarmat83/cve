package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

// Config represents the YAML configuration structure
type Config struct {
	Services map[string]Service `yaml:"services"`
}

type Service struct {
	Name string `yaml:"name"`
}

// CVEResponse represents the API response structure
type CVEResponse struct {
	Total   int       `json:"total"`
	Results []CVEData `json:"results"`
}

type CVEData struct {
	CVEID      string    `json:"cve_id"`
	DatePublic time.Time `json:"date_public"`
	Description string   `json:"description"`
}

type Exporter struct {
	apiURL string
	config Config
	metrics *ExporterMetrics
}

type ExporterMetrics struct {
	vulnerabilityCount    *prometheus.GaugeVec
	vulnerabilityBySeverity *prometheus.GaugeVec
	latestTimestamp      *prometheus.GaugeVec
}

func NewExporter(configPath, apiURL string) (*Exporter, error) {
	// Read configuration file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %v", err)
	}

	metrics := &ExporterMetrics{
		vulnerabilityCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cve_vulnerabilities_total",
				Help: "Number of CVEs found for a service",
			},
			[]string{"service_name"},
		),
		vulnerabilityBySeverity: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cve_vulnerabilities_by_severity",
				Help: "Number of CVEs by severity level",
			},
			[]string{"service_name", "severity"},
		),
		latestTimestamp: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cve_latest_vulnerability_timestamp",
				Help: "Timestamp of the most recent CVE",
			},
			[]string{"service_name"},
		),
	}

	// Register metrics
	prometheus.MustRegister(metrics.vulnerabilityCount)
	prometheus.MustRegister(metrics.vulnerabilityBySeverity)
	prometheus.MustRegister(metrics.latestTimestamp)

	return &Exporter{
		apiURL: apiURL,
		config: config,
		metrics: metrics,
	}, nil
}

func (e *Exporter) queryCVEs(serviceName string) (*CVEResponse, error) {
	params := url.Values{}
	params.Add("q", serviceName)
	params.Add("limit", "100")

	resp, err := http.Get(fmt.Sprintf("%s/api/v1/cves/search?%s", e.apiURL, params.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result CVEResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (e *Exporter) getSeverity(description string) string {
	switch {
	case contains(description, "critical"):
		return "critical"
	case contains(description, "high"):
		return "high"
	case contains(description, "medium"):
		return "medium"
	case contains(description, "low"):
		return "low"
	default:
		return "unknown"
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr
}

func (e *Exporter) updateMetrics() {
	for _, service := range e.config.Services {
		result, err := e.queryCVEs(service.Name)
		if err != nil {
			log.Printf("Error querying CVEs for %s: %v", service.Name, err)
			continue
		}

		// Update total count
		e.metrics.vulnerabilityCount.WithLabelValues(service.Name).Set(float64(result.Total))

		// Initialize severity counters
		severityCounts := map[string]int{
			"critical": 0,
			"high":    0,
			"medium":  0,
			"low":     0,
			"unknown": 0,
		}

		var latestTimestamp float64
		// Process each CVE
		for _, cve := range result.Results {
			severity := e.getSeverity(cve.Description)
			severityCounts[severity]++

			if !cve.DatePublic.IsZero() {
				timestamp := float64(cve.DatePublic.Unix())
				if timestamp > latestTimestamp {
					latestTimestamp = timestamp
				}
			}
		}

		// Update severity metrics
		for severity, count := range severityCounts {
			e.metrics.vulnerabilityBySeverity.WithLabelValues(
				service.Name,
				severity,
			).Set(float64(count))
		}

		// Update timestamp metric
		if latestTimestamp > 0 {
			e.metrics.latestTimestamp.WithLabelValues(service.Name).Set(latestTimestamp)
		}

		log.Printf("Updated metrics for %s: %d CVEs found", service.Name, result.Total)
	}
}

func main() {
	exporter, err := NewExporter("config.yaml", "http://localhost:8000")
	if err != nil {
		log.Fatalf("Error creating exporter: %v", err)
	}

	// Start the metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	// Start a goroutine to update metrics periodically
	go func() {
		for {
			exporter.updateMetrics()
			time.Sleep(5 * time.Minute)
		}
	}()

	log.Println("Starting CVE exporter on :9090")
	if err := http.ListenAndServe(":9090", nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
