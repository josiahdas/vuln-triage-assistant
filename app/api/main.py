"""
FastAPI service exposing the vulnerability triage assistant.

Endpoints:
  GET  /findings              list findings, filterable by status/tier
  GET  /findings/{id}         single finding detail with full context
  POST /ingest                trigger ingestion pipeline (NVD/EPSS/KEV -> DB)
  POST /findings/generate     regenerate Finding rows from current assets+vulns
  POST /triage/run            run LLM triage on top N open findings
  GET  /stats                 summary counts for the dashboard

Run: uvicorn app.api.main:app --reload
"""
import time
import logging
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func

from app.db import SessionLocal, init_db
from app.models import Finding, Vulnerability, Asset
from app.risk.generate_findings import generate_findings
from app.risk.run_triage import run_triage
from app.ingestion.pipeline import run_full_ingestion
from app.eval.retrieval_eval import evaluate_retrieval
from app.eval.remediation_eval import run_eval as run_remediation_eval

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = FastAPI(title="AI Vulnerability Triage Assistant", version="0.1.0")


@app.on_event("startup")
def startup():
    init_db()


class FindingOut(BaseModel):
    id: int
    cve_id: str
    asset_name: str
    vendor: str
    cvss_base_score: float | None
    epss_score: float | None
    in_kev: bool
    risk_score: float | None
    risk_tier: str | None
    status: str
    remediation_text: str | None
    remediation_sources: list[str] | None

    class Config:
        from_attributes = True


def _serialize_finding(f: Finding, vuln: Vulnerability, asset: Asset) -> FindingOut:
    import json
    sources = json.loads(f.remediation_sources) if f.remediation_sources else None
    return FindingOut(
        id=f.id,
        cve_id=f.cve_id,
        asset_name=asset.name,
        vendor=asset.vendor,
        cvss_base_score=vuln.cvss_base_score,
        epss_score=vuln.epss_score,
        in_kev=vuln.in_kev,
        risk_score=f.risk_score,
        risk_tier=f.risk_tier,
        status=f.status,
        remediation_text=f.remediation_text,
        remediation_sources=sources,
    )


@app.get("/findings", response_model=list[FindingOut])
def list_findings(
    status: str | None = Query(None, description="Filter by status: open/triaged/remediated/accepted_risk"),
    tier: str | None = Query(None, description="Filter by risk tier: critical/high/medium/low"),
    limit: int = Query(50, le=500),
):
    db = SessionLocal()
    try:
        q = db.query(Finding).join(Vulnerability).join(Asset)
        if status:
            q = q.filter(Finding.status == status)
        if tier:
            q = q.filter(Finding.risk_tier == tier)
        q = q.order_by(Finding.risk_score.desc()).limit(limit)
        results = []
        for f in q.all():
            vuln = db.get(Vulnerability, f.cve_id)
            asset = db.get(Asset, f.asset_id)
            results.append(_serialize_finding(f, vuln, asset))
        return results
    finally:
        db.close()


@app.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int):
    db = SessionLocal()
    try:
        f = db.get(Finding, finding_id)
        if not f:
            raise HTTPException(status_code=404, detail="Finding not found")
        vuln = db.get(Vulnerability, f.cve_id)
        asset = db.get(Asset, f.asset_id)
        return _serialize_finding(f, vuln, asset)
    finally:
        db.close()


@app.post("/ingest")
def trigger_ingestion():
    start = time.time()
    run_full_ingestion()
    return {"status": "ok", "duration_seconds": round(time.time() - start, 1)}


@app.post("/findings/generate")
def trigger_generate_findings():
    generate_findings()
    return {"status": "ok"}


@app.post("/triage/run")
def trigger_triage(limit: int = Query(10, le=100)):
    start = time.time()
    run_triage(limit=limit)
    return {"status": "ok", "duration_seconds": round(time.time() - start, 1)}


@app.get("/eval/retrieval")
def get_retrieval_eval():
    return evaluate_retrieval(k=3)


@app.get("/eval/remediation")
def get_remediation_eval(limit: int = Query(10, le=50), structural_only: bool = False):
    return run_remediation_eval(limit=limit, structural_only=structural_only)


@app.get("/stats")
def get_stats():
    db = SessionLocal()
    try:
        total_findings = db.query(func.count(Finding.id)).scalar()
        by_tier = dict(
            db.query(Finding.risk_tier, func.count(Finding.id))
            .group_by(Finding.risk_tier).all()
        )
        by_status = dict(
            db.query(Finding.status, func.count(Finding.id))
            .group_by(Finding.status).all()
        )
        total_vulns = db.query(func.count(Vulnerability.cve_id)).scalar()
        total_assets = db.query(func.count(Asset.id)).scalar()
        kev_count = db.query(func.count(Vulnerability.cve_id)).filter(Vulnerability.in_kev == True).scalar()
        return {
            "total_findings": total_findings,
            "findings_by_tier": by_tier,
            "findings_by_status": by_status,
            "total_vulnerabilities": total_vulns,
            "total_assets": total_assets,
            "kev_vulnerabilities": kev_count,
        }
    finally:
        db.close()
