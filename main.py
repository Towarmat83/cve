from fastapi import FastAPI, HTTPException, Query, Path as PathParam
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
import json
import os
from pathlib import Path

app = FastAPI(
    title="CVE List API",
    description="""
    A REST API for querying CVE (Common Vulnerabilities and Exposures) data.
    
    ## Features
    
    * **Get CVE by ID** - Retrieve detailed information about a specific CVE
    * **Search CVEs** - Search through CVEs using keywords and filters
    * **Pagination Support** - Control the number of results returned
    * **Year Filtering** - Filter CVEs by their publication year
    
    ## Notes
    
    * All dates are returned in ISO 8601 format
    * Search is case-insensitive
    * Results are sorted by date (newest first)
    """,
    version="1.0.0",
    contact={
        "name": "API Support",
        "url": "https://github.com/CVEProject/cvelistV5"
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    }
)

class RawDict(dict):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if isinstance(v, dict):
            return v
        raise ValueError('must be a dict')

class SimplifiedCVE(BaseModel):
    cve_id: str
    date_public: Optional[str] = None
    description: str
    references: List[RawDict]
    affected_products: List[RawDict]

    class Config:
        json_schema_extra = {
            "example": {
                "cve_id": "CVE-2023-12345",
                "date_public": "2023-01-15T10:00:00Z",
                "description": "SQL injection vulnerability in ExampleProduct allows remote attackers to execute arbitrary SQL commands",
                "references": [
                    {
                        "name": "VENDOR-SA-2023-001",
                        "url": "https://example.com/advisory/2023-001",
                        "tags": ["vendor-advisory"]
                    }
                ],
                "affected_products": [
                    {
                        "product": "ExampleProduct",
                        "vendor": "ExampleVendor",
                        "versions": [
                            {
                                "status": "affected",
                                "version": "1.2.3"
                            }
                        ]
                    }
                ]
            }
        }

def get_cve_path(cve_id: str) -> Path:
    """Convert CVE ID to file path"""
    if not cve_id.startswith("CVE-"):
        raise ValueError("Invalid CVE ID format")
    
    year = cve_id.split("-")[1]
    sequence = cve_id.split("-")[2]
    xxx_dir = f"{sequence[:-3]}xxx" if len(sequence) >= 4 else "0xxx"
    
    base_path = Path("/home/caliendo/Téléchargements/cvelistV5-main/cves")
    return base_path / year / xxx_dir / f"{cve_id}.json"

def load_cve(cve_id: str) -> Dict[str, Any]:
    """Load CVE data from JSON file"""
    try:
        file_path = get_cve_path(cve_id)
        with open(file_path) as f:
            data = json.load(f)
            
        cna_container = data["containers"]["cna"]
        
        # Get the first English description or any description if no English one exists
        description = ""
        for desc in cna_container.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and cna_container.get("descriptions"):
            description = cna_container["descriptions"][0].get("value", "")

        return {
            "cve_id": cve_id,
            "date_public": cna_container.get("datePublic"),
            "description": description,
            "references": cna_container.get("references", []),
            "affected_products": cna_container.get("affected", [])
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def root():
    return {"message": "Welcome to CVE List API"}

@app.get("/api/v1/cve/{cve_id}")
async def get_cve(
    cve_id: str = PathParam(..., 
                      description="The CVE ID to retrieve", 
                      example="CVE-2023-12345",
                      pattern=r"^CVE-\d{4}-\d+$")
):
    """
    Get detailed information about a specific CVE by its ID.
    
    The CVE ID must be in the format CVE-YYYY-NNNNN, where:
    * YYYY is the year (e.g., 2023)
    * NNNNN is the sequence number (can vary in length)
    
    Returns all available information about the CVE, including:
    * Publication date
    * Description
    * External references
    * Affected products and versions
    """
    return JSONResponse(content=load_cve(cve_id))

@app.get("/api/v1/cves/search")
async def search_cves(
    q: str = Query(..., 
                  description="Search query - searches through CVE descriptions",
                  example="sql injection",
                  min_length=3),
    year: Optional[str] = Query(None, 
                              description="Filter by year (YYYY format)",
                              example="2023",
                              pattern=r"^\d{4}$"),
    limit: int = Query(10, 
                      description="Number of results to return",
                      ge=1,
                      le=100),
    offset: int = Query(0, 
                       description="Number of results to skip",
                       ge=0)
):
    """
    Search for CVEs using a keyword query and optional filters.
    
    The search is performed on CVE descriptions and is case-insensitive.
    Results can be filtered by year, and paginated using limit and offset parameters.
    
    Returns a paginated list of CVEs matching the search criteria, including:
    * Total number of matches
    * Current page information (offset and limit)
    * List of matching CVEs with their full details
    """
    results = []
    base_path = Path("/home/caliendo/Téléchargements/cvelistV5-main/cves")
    
    try:
        if year:
            if not os.path.exists(base_path / year):
                return JSONResponse(content={
                    "total": 0,
                    "offset": offset,
                    "limit": limit,
                    "results": []
                })
            years_to_search = [year]
        else:
            years_to_search = sorted([d.name for d in base_path.iterdir() if d.is_dir() and d.name.isdigit()], reverse=True)

        for year_dir in years_to_search:
            year_path = base_path / year_dir
            if not year_path.exists() or not year_path.is_dir():
                continue

            for xxx_dir in year_path.iterdir():
                if not xxx_dir.is_dir():
                    continue

                for file_path in xxx_dir.glob("*.json"):
                    try:
                        with open(file_path) as f:
                            data = json.load(f)
                            
                        cna_container = data.get("containers", {}).get("cna", {})
                        
                        # Search in descriptions
                        found = False
                        descriptions = cna_container.get("descriptions", [])
                        for desc in descriptions:
                            if isinstance(desc, dict) and q.lower() in desc.get("value", "").lower():
                                found = True
                                break
                                
                        if found:
                            cve_id = data.get("cveMetadata", {}).get("cveId")
                            if cve_id:
                                results.append(load_cve(cve_id))
                            
                        if len(results) >= offset + limit:
                            break
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")
                        continue

                if len(results) >= offset + limit:
                    break

            if len(results) >= offset + limit:
                break
                            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
    return JSONResponse(content={
        "total": len(results),
        "offset": offset,
        "limit": limit,
        "results": results[offset:min(offset + limit, len(results))]
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
