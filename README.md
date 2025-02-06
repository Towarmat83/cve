# CVE List API

A FastAPI-based REST API for querying CVE (Common Vulnerabilities and Exposures) data, with a Prometheus exporter for monitoring.

## Setup

1. Download and extract the CVE database:
```bash
# Download the CVE database
wget https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip

# Unzip the database
unzip main.zip

# Move the API files into the extracted directory
cp -r api/* cvelistV5-main/
cd cvelistV5-main
```

2. Install dependencies:
```bash
# For the API
pip install -r requirements.txt

# For the Prometheus exporter
sudo apt-get install golang-go
```

3. Run the API server:
```bash
python main.py
```

The API will be available at http://localhost:8000

## Database Structure

The CVE database is organized in the following structure:
```
cvelistV5-main/
└── cves/
    └── YYYY/              # Year folders (e.g., 2023, 2022, etc.)
        └── xxxx/          # Subdivisions of CVE IDs
            └── CVE-YYYY-NNNNN.json  # Individual CVE files
```

## Prometheus Exporter

The project includes a Prometheus exporter that monitors CVEs for specified services.

### Configuration

1. Configure your services in `config.yaml`:
```yaml
services:
  gitlab:
    name: "gitlab-ce"
  nexus:
    name: "nexus-repository-manager"
  sql:
    name: "mysql-server"
```

2. Build and run the exporter:
```bash
# Build the exporter
go mod tidy
go build cve_exporter.go

# Run the exporter
./cve_exporter
```

The exporter will be available at http://localhost:9090/metrics

### Available Metrics

The exporter provides the following metrics:

1. `cve_vulnerabilities_total`: Total number of CVEs per service
   ```
   cve_vulnerabilities_total{service_name="gitlab-ce"} 42
   ```

2. `cve_vulnerabilities_by_severity`: Number of CVEs by severity level
   ```
   cve_vulnerabilities_by_severity{service_name="gitlab-ce",severity="critical"} 5
   cve_vulnerabilities_by_severity{service_name="gitlab-ce",severity="high"} 12
   ```

3. `cve_latest_vulnerability_timestamp`: Timestamp of the most recent CVE
   ```
   cve_latest_vulnerability_timestamp{service_name="gitlab-ce"} 1675697821
   ```

### Prometheus Configuration

Add this to your `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'cve_exporter'
    static_configs:
      - targets: ['localhost:9090']
```

### Example Prometheus Alert Rules

```yaml
groups:
- name: CVEAlerts
  rules:
  - alert: HighCriticalVulnerabilities
    expr: cve_vulnerabilities_by_severity{severity="critical"} > 5
    for: 1h
    labels:
      severity: critical
    annotations:
      summary: "Service {{ $labels.service_name }} has too many critical vulnerabilities"
```

## API Documentation

Once the server is running, you can access the interactive API documentation at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Available Endpoints

### 1. Get CVE by ID
```
GET /api/v1/cve/{cve_id}
```
Retrieves detailed information about a specific CVE.

Example:
```bash
curl http://localhost:8000/api/v1/cve/CVE-2007-0266
```

### 2. Search CVEs
```
GET /api/v1/cves/search
```
Search CVEs by keyword with optional filters.

Parameters:
- `q`: Search query (required)
- `year`: Filter by year (optional, format: YYYY)
- `limit`: Number of results to return (default: 10, max: 100)
- `offset`: Number of results to skip (default: 0)

Examples:
```bash
# Search for SQL injection vulnerabilities from 2007
curl "http://localhost:8000/api/v1/cves/search?q=sql+injection&year=2007&limit=10"
```

## Response Format

The API returns JSON responses with the following structure for individual CVEs:

```json
{
    "cve_id": "CVE-YYYY-XXXXX",
    "date_public": "YYYY-MM-DDTHH:MM:SS",
    "description": "Description text",
    "references": [
        {
            "name": "Reference name",
            "url": "Reference URL",
            "tags": ["tag1", "tag2"]
        }
    ],
    "affected_products": [
        {
            "product": "Product name",
            "vendor": "Vendor name",
            "versions": [
                {
                    "status": "affected",
                    "version": "version string"
                }
            ]
        }
    ]
}
```

For search results, the response includes pagination information:

```json
{
    "total": 100,
    "offset": 0,
    "limit": 10,
    "results": [
        // Array of CVE objects
    ]
}
```

## Error Handling

The API returns appropriate HTTP status codes:
- `200`: Successful request
- `404`: CVE not found
- `500`: Server error

Error responses include a detail message explaining the issue:
```json
{
    "detail": "Error message here"
}
