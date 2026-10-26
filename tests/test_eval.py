from app.eval.remediation_eval import structural_check
from app.eval.retrieval_eval import evaluate_retrieval


def test_structural_check_passes_well_formed_remediation():
    text = (
        "Patch the affected device to the latest release given the CVSS 9.8 "
        "severity. Disable the management interface from untrusted zones per "
        "vendor guidance and enable MFA as a compensating control.\n\n"
        "Priority justification: high CVSS and EPSS on an internet-facing "
        "critical asset warrants immediate action."
    )
    result = structural_check(text)
    assert result["passed"] is True


def test_structural_check_fails_empty_text():
    result = structural_check("")
    assert result["passed"] is False
    assert result["non_empty"] is False


def test_structural_check_fails_generic_filler():
    result = structural_check("Review your security posture. Review your security posture.")
    assert result["passed"] is False
    assert result["not_just_generic_filler"] is False


def test_structural_check_fails_missing_priority_justification():
    text = "Patch the device now. " * 20  # long enough, but no justification line
    result = structural_check(text)
    assert result["has_priority_justification"] is False
    assert result["passed"] is False


def test_retrieval_eval_runs_and_returns_expected_shape():
    report = evaluate_retrieval(k=3)
    assert report["num_queries"] > 0
    assert 0.0 <= report["mean_precision_at_k"] <= 1.0
    assert 0.0 <= report["hit_rate_at_k"] <= 1.0
    assert len(report["per_query"]) == report["num_queries"]
