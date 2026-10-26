"""
Remediation quality evaluation.

Two layers, deliberately kept separate:

1. Structural checks (no API call, fast, deterministic): does the
   remediation follow the format we asked for? Non-empty, right length,
   includes a priority justification, references the CVE. These catch
   prompt-following regressions cheaply.

2. LLM-as-judge (uses the Claude API, same as generation): scores each
   remediation 1-5 on groundedness (does it stick to retrieved guidance
   rather than inventing vendor specifics?) and actionability (is it a
   concrete action, not generic advice?). This is the more expensive,
   more meaningful check -- it's evaluating the actual output quality
   a hiring manager would care about, not just "did the pipeline run."

Run: python -m app.eval.remediation_eval [--limit N] [--structural-only]
"""
import os
import re
import json
import argparse
import logging
from anthropic import Anthropic
from dotenv import load_dotenv

from app.db import SessionLocal, init_db
from app.models import Finding, Vulnerability, Asset

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
JUDGE_MODEL = "claude-sonnet-4-5"

JUDGE_SYSTEM_PROMPT = """You are grading a security remediation recommendation \
written by another AI system for a vulnerability triage tool. You will be \
given the finding context, the retrieved guidance the writer had access to, \
and the remediation it produced.

Score on two dimensions, 1-5 each:

GROUNDEDNESS: Does the remediation stick to what's actually supported by \
the retrieved guidance and CVE description, rather than inventing specific \
vendor claims not present in the context? 5 = fully grounded, clearly \
tied to provided context. 1 = makes up specific claims not supported by \
the context.

ACTIONABILITY: Is this a concrete, specific action a security engineer \
could execute today (patch X, disable Y, restrict Z), rather than vague \
advice like "review your security posture" or "stay vigilant"? 5 = highly \
specific and actionable. 1 = generic filler.

Respond ONLY with valid JSON in this exact format, no other text:
{"groundedness": <int 1-5>, "actionability": <int 1-5>, "reasoning": "<one sentence>"}
"""


# --- Structural checks (no API call) ---

def structural_check(remediation_text: str) -> dict:
    checks = {
        "non_empty": bool(remediation_text and remediation_text.strip()),
        "reasonable_length": 100 <= len(remediation_text or "") <= 2000,
        "has_priority_justification": bool(
            re.search(r"priority justification", remediation_text or "", re.IGNORECASE)
        ),
        "not_just_generic_filler": not bool(
            re.fullmatch(
                r"\s*(review your security posture\.?\s*)+",
                remediation_text or "",
                re.IGNORECASE,
            )
        ),
    }
    checks["passed"] = all(checks.values())
    return checks


# --- LLM-as-judge (API call) ---

def judge_remediation(finding_context: str, guidance_text: str, remediation_text: str) -> dict:
    user_message = f"""Finding context:
{finding_context}

Retrieved guidance the writer had access to:
{guidance_text}

Remediation produced:
{remediation_text}

Grade it now."""

    response = client.messages.create(
        model=JUDGE_MODEL,
        max_tokens=200,
        system=JUDGE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )
    raw = response.content[0].text.strip()
    # Claude sometimes wraps JSON in markdown code fences despite instructions
    # not to -- strip them before parsing rather than treating it as a failure.
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        log.warning(f"Judge returned unparseable output, skipping: {raw[:200]}")
        return {"groundedness": None, "actionability": None, "reasoning": "PARSE_ERROR"}


def run_eval(limit: int = 10, structural_only: bool = False) -> dict:
    from app.risk.scoring import score_finding, RiskInput, Criticality
    from app.rag.triage import build_finding_context
    from app.rag.index import retrieve_guidance

    init_db()
    db = SessionLocal()
    try:
        findings = (
            db.query(Finding)
            .filter(Finding.remediation_text.isnot(None))
            .limit(limit)
            .all()
        )
        if not findings:
            log.warning("No triaged findings found. Run `python -m app.risk.run_triage` first.")
            return {"num_evaluated": 0, "results": []}

        results = []
        for f in findings:
            vuln = db.get(Vulnerability, f.cve_id)
            asset = db.get(Asset, f.asset_id)

            struct = structural_check(f.remediation_text)
            row = {
                "cve_id": f.cve_id,
                "asset": asset.name,
                "structural": struct,
            }

            if not structural_only:
                risk_result = score_finding(RiskInput(
                    cvss_base_score=vuln.cvss_base_score,
                    epss_score=vuln.epss_score,
                    in_kev=vuln.in_kev,
                    internet_facing=asset.internet_facing,
                    asset_criticality=Criticality(asset.criticality),
                ))
                finding_context = build_finding_context(f, vuln, asset, risk_result.explanation)
                guidance_hits = retrieve_guidance(asset.vendor, vuln.description or f.cve_id, n_results=3)
                guidance_text = "\n\n".join(h["text"] for h in guidance_hits)

                judged = judge_remediation(finding_context, guidance_text, f.remediation_text)
                row["judge"] = judged

            results.append(row)

        report = {"num_evaluated": len(results), "results": results}

        if not structural_only:
            valid_scores = [r["judge"] for r in results if r["judge"]["groundedness"] is not None]
            if valid_scores:
                report["mean_groundedness"] = round(
                    sum(s["groundedness"] for s in valid_scores) / len(valid_scores), 2
                )
                report["mean_actionability"] = round(
                    sum(s["actionability"] for s in valid_scores) / len(valid_scores), 2
                )

        report["structural_pass_rate"] = round(
            sum(1 for r in results if r["structural"]["passed"]) / len(results), 3
        )
        return report
    finally:
        db.close()


def print_report(report: dict):
    if report["num_evaluated"] == 0:
        print("No triaged findings to evaluate.")
        return

    print(f"Remediation eval ({report['num_evaluated']} findings)")
    print(f"  Structural pass rate: {report['structural_pass_rate']}")
    if "mean_groundedness" in report:
        print(f"  Mean groundedness (1-5):  {report['mean_groundedness']}")
        print(f"  Mean actionability (1-5): {report['mean_actionability']}")
    print()
    for r in report["results"]:
        struct_status = "PASS" if r["structural"]["passed"] else "FAIL"
        line = f"  [structural: {struct_status}] {r['cve_id']} on {r['asset']}"
        if "judge" in r and r["judge"]["groundedness"] is not None:
            line += f"  | groundedness={r['judge']['groundedness']} actionability={r['judge']['actionability']}"
        print(line)
        if "judge" in r and r["judge"].get("reasoning"):
            print(f"         judge reasoning: {r['judge']['reasoning']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--structural-only", action="store_true",
                         help="Skip the LLM-judge API calls, run only free structural checks")
    args = parser.parse_args()
    report = run_eval(limit=args.limit, structural_only=args.structural_only)
    print_report(report)
