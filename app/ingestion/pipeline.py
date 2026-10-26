"""
Ingestion pipeline: fetch CVEs for a vendor/product keyword, enrich with
EPSS + KEV, and upsert into the database.

Run standalone: python -m app.ingestion.pipeline
"""
import os
import logging
from datetime import datetime
from dotenv import load_dotenv

from app.db import SessionLocal, init_db
from app.models import Vulnerability
from app.ingestion.fetch import (
    fetch_cves_by_keyword, parse_nvd_item, fetch_epss_scores, fetch_kev_catalog,
)

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# Narrow, defensible scope: security/network devices, matching real
# vendor exposure from SPARK. Keep this list small to start -- it's
# easy to widen later once the pipeline works end to end.
VENDOR_KEYWORDS = {
    "cisco": ["Cisco IOS XE", "Cisco ASA"],
    "paloalto": ["PAN-OS"],
    "fortinet": ["FortiOS"],
    "juniper": ["Junos OS"],
}


def ingest_vendor(vendor: str, keywords: list[str], api_key: str | None = None) -> list[str]:
    """Fetch + parse CVEs for one vendor's keyword set. Returns list of CVE IDs found."""
    all_ids = []
    for kw in keywords:
        log.info(f"Fetching CVEs for keyword: {kw!r}")
        try:
            raw_items = fetch_cves_by_keyword(kw, api_key=api_key, results_per_page=50)
        except Exception as e:
            log.warning(f"Failed to fetch for {kw!r}: {e}")
            continue
        log.info(f"  -> {len(raw_items)} results")
        for item in raw_items:
            parsed = parse_nvd_item(item)
            parsed["vendor"] = vendor
            parsed["product"] = kw
            all_ids.append(parsed["cve_id"])
            _upsert_vulnerability(parsed)
    return all_ids


def _upsert_vulnerability(parsed: dict):
    db = SessionLocal()
    try:
        existing = db.get(Vulnerability, parsed["cve_id"])
        if existing:
            existing.description = parsed["description"]
            existing.cvss_base_score = parsed["cvss_base_score"]
            existing.cvss_vector = parsed["cvss_vector"]
            existing.vendor = parsed["vendor"]
            existing.product = parsed["product"]
            existing.published_date = parsed["published_date"]
            existing.last_ingested = datetime.utcnow()
        else:
            db.add(Vulnerability(
                cve_id=parsed["cve_id"],
                description=parsed["description"],
                cvss_base_score=parsed["cvss_base_score"],
                cvss_vector=parsed["cvss_vector"],
                vendor=parsed["vendor"],
                product=parsed["product"],
                published_date=parsed["published_date"],
            ))
        db.commit()
    finally:
        db.close()


def enrich_with_epss_and_kev():
    """Second pass: fill in EPSS scores and KEV flags for all stored CVEs."""
    db = SessionLocal()
    try:
        all_cve_ids = [row.cve_id for row in db.query(Vulnerability.cve_id).all()]
    finally:
        db.close()

    if not all_cve_ids:
        log.info("No CVEs in DB to enrich.")
        return

    log.info(f"Enriching {len(all_cve_ids)} CVEs with EPSS scores...")
    epss_map = fetch_epss_scores(all_cve_ids)

    log.info("Fetching CISA KEV catalog...")
    kev_map = fetch_kev_catalog()

    db = SessionLocal()
    try:
        for cve_id in all_cve_ids:
            vuln = db.get(Vulnerability, cve_id)
            if not vuln:
                continue
            if cve_id in epss_map:
                vuln.epss_score = epss_map[cve_id]["epss"]
                vuln.epss_percentile = epss_map[cve_id]["percentile"]
            if cve_id in kev_map:
                vuln.in_kev = True
                date_added = kev_map[cve_id].get("dateAdded")
                if date_added:
                    vuln.kev_date_added = datetime.fromisoformat(date_added)
        db.commit()
    finally:
        db.close()

    log.info(f"Enriched: {len(epss_map)} had EPSS scores, "
              f"{sum(1 for c in all_cve_ids if c in kev_map)} are in KEV.")


def run_full_ingestion():
    init_db()
    api_key = os.getenv("NVD_API_KEY") or None
    for vendor, keywords in VENDOR_KEYWORDS.items():
        ingest_vendor(vendor, keywords, api_key=api_key)
    enrich_with_epss_and_kev()
    log.info("Ingestion complete.")


if __name__ == "__main__":
    run_full_ingestion()
