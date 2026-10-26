"""
Generate Findings by matching each Asset to Vulnerabilities for its
vendor/product, then scoring each match with the risk engine.

This is intentionally simple version matching (vendor+product match =
"potentially affected") rather than precise version-range parsing (e.g.
CPE match strings), which real vuln scanners do. Documenting that
simplification honestly in the README is a good interview talking
point: you know the difference between this and production-grade
version matching, you just scoped it out deliberately.

Run: python -m app.risk.generate_findings
"""
import logging
from app.db import SessionLocal, init_db
from app.models import Asset, Vulnerability, Finding
from app.risk.scoring import score_finding, RiskInput, Criticality
from app.risk.version_match import assess_applicability

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def generate_findings():
    init_db()
    db = SessionLocal()
    try:
        assets = db.query(Asset).all()
        created = 0
        for asset in assets:
            matching_vulns = (
                db.query(Vulnerability)
                .filter(Vulnerability.vendor == asset.vendor)
                .filter(Vulnerability.product == asset.product)
                .all()
            )
            for vuln in matching_vulns:
                already_exists = (
                    db.query(Finding)
                    .filter(Finding.cve_id == vuln.cve_id, Finding.asset_id == asset.id)
                    .first()
                )
                if already_exists:
                    continue

                applicability = assess_applicability(vuln.description, asset.version)

                # Confirmed not-applicable (e.g. asset is on a far newer
                # version than the CVE's affected range): don't create a
                # finding at all. This is the fix for the false-positive
                # matches the eval harness caught -- filtering here means
                # the LLM never sees an inapplicable pairing to reason
                # (incorrectly) about in the first place.
                if applicability == "not_affected":
                    log.info(f"Skipping {vuln.cve_id} on {asset.name}: "
                             f"not applicable to version {asset.version}")
                    continue

                result = score_finding(RiskInput(
                    cvss_base_score=vuln.cvss_base_score,
                    epss_score=vuln.epss_score,
                    in_kev=vuln.in_kev,
                    internet_facing=asset.internet_facing,
                    asset_criticality=Criticality(asset.criticality),
                ))

                finding = Finding(
                    cve_id=vuln.cve_id,
                    asset_id=asset.id,
                    risk_score=result.score,
                    risk_tier=result.tier,
                    applicability=applicability,
                    status="open",
                )
                db.add(finding)
                created += 1
        db.commit()
        log.info(f"Generated {created} new findings.")
    finally:
        db.close()


if __name__ == "__main__":
    generate_findings()
