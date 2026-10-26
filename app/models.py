"""
Database models.

Design note: we separate the raw ingested vulnerability data (Vulnerability)
from the org-specific finding (Finding), which links a CVE to a specific
asset the org actually owns. This mirrors how real vuln-management tools
(e.g. what SPARK does) separate "what exists in the world" from
"what's on our network" -- the risk score only matters in the context
of a Finding, not the raw CVE.
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Float, Boolean, DateTime, Integer, ForeignKey, Text
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


class Vulnerability(Base):
    """A CVE enriched with CVSS, EPSS, and KEV data."""
    __tablename__ = "vulnerabilities"

    cve_id = Column(String, primary_key=True)  # e.g. CVE-2024-12345
    description = Column(Text, nullable=True)
    cvss_base_score = Column(Float, nullable=True)       # 0-10, from NVD
    cvss_vector = Column(String, nullable=True)
    epss_score = Column(Float, nullable=True)            # 0-1, exploit probability (30-day)
    epss_percentile = Column(Float, nullable=True)
    in_kev = Column(Boolean, default=False)               # is it in CISA's Known Exploited Vulns list
    kev_date_added = Column(DateTime, nullable=True)
    vendor = Column(String, nullable=True, index=True)     # e.g. "cisco", "paloalto", "fortinet"
    product = Column(String, nullable=True)
    published_date = Column(DateTime, nullable=True)
    last_ingested = Column(DateTime, default=utcnow)

    findings = relationship("Finding", back_populates="vulnerability")


class Asset(Base):
    """A device/system in the sample org's inventory."""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)          # e.g. "edge-fw-01"
    vendor = Column(String, nullable=False)         # "paloalto"
    product = Column(String, nullable=False)        # "PAN-OS"
    version = Column(String, nullable=True)
    criticality = Column(String, default="medium")  # low/medium/high/critical -- business context
    internet_facing = Column(Boolean, default=False)

    findings = relationship("Finding", back_populates="asset")


class Finding(Base):
    """A specific CVE affecting a specific asset -- this is what gets triaged."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String, ForeignKey("vulnerabilities.cve_id"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)

    risk_score = Column(Float, nullable=True)        # our composite score, 0-100
    risk_tier = Column(String, nullable=True)         # "critical"/"high"/"medium"/"low"
    applicability = Column(String, nullable=True)     # "affected"/"not_affected"/"unknown" -- see app/risk/version_match.py
    remediation_text = Column(Text, nullable=True)    # LLM-generated
    remediation_sources = Column(Text, nullable=True) # JSON list of source doc ids used in RAG
    status = Column(String, default="open")           # open/triaged/remediated/accepted_risk
    created_at = Column(DateTime, default=utcnow)
    triaged_at = Column(DateTime, nullable=True)

    vulnerability = relationship("Vulnerability", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
