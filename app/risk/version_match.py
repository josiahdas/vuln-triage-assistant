"""
Version applicability heuristic.

The eval harness (app/eval/remediation_eval.py) surfaced a real problem:
generate_findings.py matches CVEs to assets by vendor+product only, with
no version-range logic. That means CVEs affecting only ancient versions
(e.g. "PAN-OS before 4.1.4") get matched against assets running far newer
versions (e.g. 10.1.0) -- a false-positive finding before the LLM even
sees it. Asking the LLM to resolve that from free-text version ranges in
the CVE description turned out to be unreliable (it got the comparison
backwards in several cases even when explicitly told not to guess).

This module does the version comparison deterministically instead, so the
LLM is told a verdict rather than asked to derive one. It's a heuristic,
not a full CPE parser -- NVD description text is inconsistent enough that
perfect parsing isn't realistic here, so this is deliberately conservative:
when parsing is ambiguous, it returns "unknown" rather than guessing.

Returns one of: "affected", "not_affected", "unknown"
"""
import re
from packaging.version import Version, InvalidVersion

# Matches patterns like "7.1.x before 7.1.6" or "7.1.x before 7.1.6," --
# a branch prefix plus an upper bound for that specific branch.
BRANCH_PATTERN = re.compile(r"(\d+(?:\.\d+)?)\.x before (\d+(?:\.\d+){1,3})")

# Matches standalone "before X.Y.Z" not preceded by a branch prefix --
# treated as a global upper bound for versions sharing that major version.
GLOBAL_BEFORE_PATTERN = re.compile(r"(?<!\.x )before (\d+(?:\.\d+){1,3})")


def _safe_parse(v: str) -> Version | None:
    try:
        return Version(v)
    except InvalidVersion:
        return None


def assess_applicability(cve_description: str, asset_version: str) -> str:
    if not cve_description or not asset_version:
        return "unknown"

    asset_v = _safe_parse(asset_version)
    if asset_v is None:
        return "unknown"

    branch_matches = BRANCH_PATTERN.findall(cve_description)
    global_matches = GLOBAL_BEFORE_PATTERN.findall(cve_description)

    if not branch_matches and not global_matches:
        return "unknown"

    # Check branch-specific thresholds first: only applicable if the asset
    # is actually on that branch (matching major.minor prefix).
    branch_majors_mentioned = set()
    for branch_prefix, threshold in branch_matches:
        threshold_v = _safe_parse(threshold)
        if threshold_v is None:
            continue
        asset_branch = ".".join(str(p) for p in asset_v.release[:len(branch_prefix.split("."))])
        if asset_branch == branch_prefix:
            return "affected" if asset_v < threshold_v else "not_affected"
        branch_majors_mentioned.add(int(branch_prefix.split(".")[0]))

    # Asset isn't on any of the explicitly-enumerated branches. If the CVE
    # only lists branches (no unqualified "before X" clause) and the asset's
    # major version is higher than every branch mentioned, it's on a later
    # product line the CVE text doesn't cover -- safe to call not_affected
    # rather than unknown, since the enumeration was exhaustive for the
    # versions the vendor considered affected.
    if branch_matches and not global_matches and branch_majors_mentioned:
        if asset_v.release[0] > max(branch_majors_mentioned):
            return "not_affected"

    # No branch-specific match -- check global "before X" thresholds.
    # Conservative rule: if the asset's major version is higher than every
    # major version mentioned in the CVE text, it's very likely on a later
    # product line entirely and not affected. Otherwise, treat as unknown
    # rather than risk a wrong same-branch comparison.
    parsed_thresholds = [_safe_parse(t) for t in global_matches]
    parsed_thresholds = [t for t in parsed_thresholds if t is not None]
    if not parsed_thresholds:
        return "unknown"

    max_mentioned_major = max(t.release[0] for t in parsed_thresholds)
    if asset_v.release[0] > max_mentioned_major:
        return "not_affected"

    if asset_v.release[0] < max_mentioned_major:
        return "affected"

    # Same major version as the highest mentioned -- compare directly
    # against the largest threshold on that major version as a best effort.
    same_major_thresholds = [t for t in parsed_thresholds if t.release[0] == asset_v.release[0]]
    if same_major_thresholds:
        return "affected" if asset_v < max(same_major_thresholds) else "not_affected"

    return "unknown"
