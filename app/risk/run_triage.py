"""
Batch-triage the highest-risk open findings: retrieve guidance, call the
LLM, and store the generated remediation back on the Finding record.

Run: python -m app.risk.run_triage [--limit N]
"""
import json
import logging
import argparse
from datetime import datetime

from app.db import SessionLocal, init_db
from app.models import Finding, Vulnerability, Asset
from app.risk.scoring import score_finding, RiskInput, Criticality
from app.rag.triage import generate_remediation

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def run_triage(limit: int = 10):
    init_db()
    db = SessionLocal()
    try:
        findings = (
            db.query(Finding)
            .filter(Finding.status == "open")
            .filter(Finding.remediation_text.is_(None))
            .order_by(Finding.risk_score.desc())
            .limit(limit)
            .all()
        )
        log.info(f"Triaging top {len(findings)} open findings...")

        for f in findings:
            vuln = db.get(Vulnerability, f.cve_id)
            asset = db.get(Asset, f.asset_id)

            # Recompute the explanation string (cheap, avoids storing it twice)
            result = score_finding(RiskInput(
                cvss_base_score=vuln.cvss_base_score,
                epss_score=vuln.epss_score,
                in_kev=vuln.in_kev,
                internet_facing=asset.internet_facing,
                asset_criticality=Criticality(asset.criticality),
            ))

            try:
                remediation = generate_remediation(f, vuln, asset, result.explanation)
            except Exception as e:
                log.error(f"Failed to triage {f.cve_id} on {asset.name}: {e}")
                continue

            f.remediation_text = remediation["remediation_text"]
            f.remediation_sources = json.dumps(remediation["sources"])
            f.status = "triaged"
            f.triaged_at = datetime.utcnow()
            db.commit()
            log.info(f"Triaged {f.cve_id} on {asset.name} (risk {f.risk_score})")

        log.info("Batch triage complete.")
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()
    run_triage(limit=args.limit)
