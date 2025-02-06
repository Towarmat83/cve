# CVE List API

A FastAPI-based REST API for querying CVE (Common Vulnerabilities and Exposures) data.

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
pip install -r requirements.txt
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
- `version`: Filter by specific version of affected products (optional)
- `limit`: Number of results to return (default: 10, max: 100)
- `offset`: Number of results to skip (default: 0)

Examples:
```bash
# Search for SQL injection vulnerabilities from 2007
curl "http://localhost:8000/api/v1/cves/search?q=sql+injection&year=2007&limit=10"

# Search for vulnerabilities affecting version 1.2.3
curl "http://localhost:8000/api/v1/cves/search?q=vulnerability&version=1.2.3"

# Combine year and version filters
curl "http://localhost:8000/api/v1/cves/search?q=vulnerability&year=2007&version=1.2.3"
```

## Response Format

The API returns JSON responses with the following structure for individual CVEs:

```json
{
    "cve_id": "CVE-YYYY-XXXXX",
    "date_public": "YYYY-MM-DDTHH:MM:SS",
    "descriptions": [
        {
            "lang": "en",
            "value": "Description text"
        }
    ],
    "references": [
        {
            "name": "Reference name",
            "url": "Reference URL",
            "tags": ["tag1", "tag2"]
        }
    ],
    "affected": [
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

## Features

1. **Full-Text Search**: Search through CVE descriptions using keywords
2. **Version Filtering**: Find vulnerabilities affecting specific software versions
3. **Year Filtering**: Filter CVEs by their publication year
4. **Pagination**: Control the number of results returned
5. **Interactive Documentation**: Explore the API using Swagger UI or ReDoc
6. **JSON Responses**: Clean, structured JSON responses for easy integration

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
