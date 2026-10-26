"""
Composite risk scoring.

Why not just use CVSS? CVSS measures theoretical severity, not real-world
risk. A 9.8 CVSS vuln that's never been exploited and requires local
access is often less urgent than a 7.5 that's in CISA's KEV list and
sitting on an internet-facing firewall. This mirrors the "risk-based
prioritization" approach used in real vuln-management practice (and in
SPARK): severity x exploitability x exposure.

Formula (0-100 scale):
    base        = cvss_base_score * 10                      (0-100)
    exploit_adj = epss_score * 100                            (0-100)
    kev_bonus   = +25 if in_kev else 0                        (flat bump -- known exploitation
                                                                 is a stronger signal than a
                                                                 probability estimate)
    exposure_mult = 1.3 if internet_facing else 1.0
    criticality_mult = {low: 0.8, medium: 1.0, high: 1.2, critical: 1.4}

    raw_score = (0.5 * base + 0.5 * exploit_adj + kev_bonus) * exposure_mult * criticality_mult
    final_score = min(raw_score, 100)

These weights (0.5/0.5 split between severity and exploit probability,
+25 KEV bump, 1.3x/1.4x multipliers) are a defensible starting point,
not a law of nature -- document in your README that they're tunable,
and ideally show one example where you adjusted a weight after looking
at how it ranked findings, since that's an actual engineering decision
you can talk about in an interview.
"""
from dataclasses import dataclass
from enum import Enum


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


CRITICALITY_MULTIPLIER = {
    Criticality.LOW: 0.8,
    Criticality.MEDIUM: 1.0,
    Criticality.HIGH: 1.2,
    Criticality.CRITICAL: 1.4,
}

KEV_BONUS = 25
INTERNET_FACING_MULTIPLIER = 1.3


@dataclass
class RiskInput:
    cvss_base_score: float | None   # 0-10
    epss_score: float | None        # 0-1
    in_kev: bool
    internet_facing: bool
    asset_criticality: Criticality


@dataclass
class RiskResult:
    score: float          # 0-100
    tier: str             # critical/high/medium/low
    explanation: str      # human-readable breakdown, useful for the LLM prompt + UI


def score_finding(inp: RiskInput) -> RiskResult:
    cvss = inp.cvss_base_score or 0.0
    epss = inp.epss_score or 0.0

    base = cvss * 10
    exploit_adj = epss * 100
    kev_bonus = KEV_BONUS if inp.in_kev else 0

    exposure_mult = INTERNET_FACING_MULTIPLIER if inp.internet_facing else 1.0
    crit_mult = CRITICALITY_MULTIPLIER[inp.asset_criticality]

    raw = (0.5 * base + 0.5 * exploit_adj + kev_bonus) * exposure_mult * crit_mult
    final = min(raw, 100.0)

    tier = _tier_for_score(final)

    explanation = (
        f"CVSS {cvss}/10 (base contribution {base:.1f}), "
        f"EPSS {epss:.1%} exploit probability (contribution {exploit_adj:.1f}), "
        f"{'in CISA KEV (+' + str(KEV_BONUS) + ')' if inp.in_kev else 'not in CISA KEV'}, "
        f"{'internet-facing (x' + str(INTERNET_FACING_MULTIPLIER) + ')' if inp.internet_facing else 'internal only'}, "
        f"asset criticality {inp.asset_criticality.value} (x{CRITICALITY_MULTIPLIER[inp.asset_criticality]}) "
        f"=> {final:.1f}/100 ({tier})"
    )

    return RiskResult(score=round(final, 1), tier=tier, explanation=explanation)


def _tier_for_score(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
