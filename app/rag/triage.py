"""
LLM triage layer: given a Finding (CVE + Asset + risk score), retrieve
relevant hardening guidance and prompt Claude to produce a structured
remediation recommendation.

The prompt deliberately includes the risk score breakdown (not just the
raw CVE description) so the model's recommendation is grounded in *why*
this finding is prioritized the way it is, not just severity in isolation.
"""
import os
import json
import logging
from anthropic import Anthropic
from dotenv import load_dotenv

from app.rag.index import retrieve_guidance

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
MODEL = "claude-sonnet-4-5"

SYSTEM_PROMPT = """You are a security remediation assistant helping a small \
security team triage vulnerability findings on network infrastructure. \
Given a CVE, the asset it affects, a computed risk score with its \
explanation, and retrieved internal hardening guidance, produce a concise, \
actionable remediation recommendation.

Rules:
- Ground your recommendation in the retrieved guidance where it's relevant; \
don't invent vendor-specific advice not supported by the context provided.
- The finding context includes a pre-computed "Version applicability" verdict \
("affected" or "unknown"). Trust this verdict completely -- do not re-derive \
or second-guess version applicability yourself by comparing version numbers \
in the CVE description; that comparison has already been done deterministically \
upstream. If applicability is "unknown", say the exact affected version range \
should be confirmed against the vendor advisory before deprioritizing, but \
still address the finding as potentially applicable given it passed matching.
- Be concrete: name the specific action (patch, disable service, restrict \
access, compensating control), not generic advice like "review your security posture."
- If the retrieved guidance doesn't directly address this specific CVE, say so \
and give a general best-practice recommendation based on the CVE description instead.
- Keep the recommendation to 3-5 sentences.
- End with a one-line "Priority justification" that references the risk score \
components (CVSS, EPSS, KEV status, exposure) in one sentence.
"""


def build_finding_context(finding, vulnerability, asset, risk_explanation: str) -> str:
    applicability = getattr(finding, "applicability", None) or "unknown"
    return f"""
CVE: {finding.cve_id}
CVE description: {vulnerability.description}
CVSS base score: {vulnerability.cvss_base_score}
EPSS score: {vulnerability.epss_score}
In CISA KEV: {vulnerability.in_kev}

Affected asset: {asset.name} ({asset.vendor} {asset.product} {asset.version})
Asset criticality: {asset.criticality}
Internet-facing: {asset.internet_facing}
Version applicability (pre-computed, trust this): {applicability}

Computed risk score: {finding.risk_score}/100 (tier: {finding.risk_tier})
Risk score explanation: {risk_explanation}
""".strip()


def generate_remediation(finding, vulnerability, asset, risk_explanation: str) -> dict:
    """Returns {"remediation_text": str, "sources": [str]}."""
    guidance_hits = retrieve_guidance(
        vendor=asset.vendor,
        query_text=vulnerability.description or vulnerability.cve_id,
        n_results=3,
    )
    guidance_text = "\n\n".join(
        f"[Source: {h['source']}]\n{h['text']}" for h in guidance_hits
    ) or "(no relevant guidance retrieved)"

    finding_context = build_finding_context(finding, vulnerability, asset, risk_explanation)

    user_message = f"""Finding details:
{finding_context}

Retrieved hardening guidance:
{guidance_text}

Produce the remediation recommendation now."""

    response = client.messages.create(
        model=MODEL,
        max_tokens=500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )
    remediation_text = response.content[0].text

    sources = list({h["source"] for h in guidance_hits})
    return {
        "remediation_text": remediation_text,
        "sources": sources,
    }
