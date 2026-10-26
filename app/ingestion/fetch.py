"""
Ingestion clients for NVD (CVE data), FIRST.org EPSS (exploit probability),
and CISA KEV (known exploited vulnerabilities catalog).

All three are free public APIs, no auth required for basic use (NVD works
without a key but rate-limits harder -- get a free key for real use:
https://nvd.nist.gov/developers/request-an-api-key).
"""
import httpx
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def fetch_cves_by_keyword(keyword: str, api_key: str | None = None, results_per_page: int = 50) -> list[dict]:
    """
    Search NVD for CVEs matching a keyword (e.g. product/vendor name like
    'PAN-OS' or 'Cisco IOS XE'). Returns raw NVD CVE items.
    """
    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": keyword, "resultsPerPage": results_per_page}
    with httpx.Client(timeout=30) as client:
        resp = client.get(NVD_CVE_URL, params=params, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    return data.get("vulnerabilities", [])


def parse_nvd_item(item: dict) -> dict:
    """Extract the fields we care about from a raw NVD API response item."""
    cve = item["cve"]
    cve_id = cve["id"]

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    cvss_score = None
    cvss_vector = None
    metrics = cve.get("metrics", {})
    # Prefer CVSS v3.1, fall back to v3.0, then v2
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            break

    published = cve.get("published")
    published_date = datetime.fromisoformat(published) if published else None

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_base_score": cvss_score,
        "cvss_vector": cvss_vector,
        "published_date": published_date,
    }


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def fetch_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """
    Fetch EPSS (Exploit Prediction Scoring System) scores for a batch of CVEs.
    Returns {cve_id: {"epss": float, "percentile": float}}.
    """
    if not cve_ids:
        return {}
    results = {}
    # EPSS API accepts comma-separated CVE list, cap batches to be polite
    batch_size = 100
    with httpx.Client(timeout=30) as client:
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            resp = client.get(EPSS_URL, params={"cve": ",".join(batch)})
            resp.raise_for_status()
            data = resp.json()
            for row in data.get("data", []):
                results[row["cve"]] = {
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                }
    return results


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def fetch_kev_catalog() -> dict[str, dict]:
    """
    Fetch CISA's full Known Exploited Vulnerabilities catalog.
    Returns {cve_id: {"date_added": str, "vendor_project": str, ...}}.
    """
    with httpx.Client(timeout=30) as client:
        resp = client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
