"""
Seed a small sample asset inventory -- a fictional org's network devices.
This gives the Finding layer (CVE x Asset) something real to join against.

Run: python -m app.seed_assets
"""
from app.db import SessionLocal, init_db
from app.models import Asset

SAMPLE_ASSETS = [
    {"name": "edge-fw-01", "vendor": "paloalto", "product": "PAN-OS", "version": "10.1.0",
     "criticality": "critical", "internet_facing": True},
    {"name": "edge-fw-02", "vendor": "paloalto", "product": "PAN-OS", "version": "9.1.3",
     "criticality": "critical", "internet_facing": True},
    {"name": "core-sw-01", "vendor": "cisco", "product": "Cisco IOS XE", "version": "16.12.4",
     "criticality": "high", "internet_facing": False},
    {"name": "vpn-gw-01", "vendor": "cisco", "product": "Cisco ASA", "version": "9.16",
     "criticality": "critical", "internet_facing": True},
    {"name": "branch-fw-01", "vendor": "fortinet", "product": "FortiOS", "version": "7.0.5",
     "criticality": "medium", "internet_facing": True},
    {"name": "internal-router-01", "vendor": "juniper", "product": "Junos OS", "version": "20.4R3",
     "criticality": "medium", "internet_facing": False},
    {"name": "dmz-fw-01", "vendor": "paloalto", "product": "PAN-OS", "version": "10.2.1",
     "criticality": "high", "internet_facing": True},
]


def seed_assets():
    init_db()
    db = SessionLocal()
    try:
        existing_count = db.query(Asset).count()
        if existing_count > 0:
            print(f"Assets table already has {existing_count} rows -- skipping seed.")
            return
        for a in SAMPLE_ASSETS:
            db.add(Asset(**a))
        db.commit()
        print(f"Seeded {len(SAMPLE_ASSETS)} sample assets.")
    finally:
        db.close()


if __name__ == "__main__":
    seed_assets()
