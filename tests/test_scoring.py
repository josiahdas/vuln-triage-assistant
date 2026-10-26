from app.risk.scoring import score_finding, RiskInput, Criticality


def test_low_severity_internal_low_criticality_is_low_tier():
    result = score_finding(RiskInput(
        cvss_base_score=3.1,
        epss_score=0.01,
        in_kev=False,
        internet_facing=False,
        asset_criticality=Criticality.LOW,
    ))
    assert result.tier == "low"


def test_kev_bumps_a_moderate_cve_up_significantly():
    without_kev = score_finding(RiskInput(
        cvss_base_score=6.5, epss_score=0.4, in_kev=False,
        internet_facing=False, asset_criticality=Criticality.MEDIUM,
    ))
    with_kev = score_finding(RiskInput(
        cvss_base_score=6.5, epss_score=0.4, in_kev=True,
        internet_facing=False, asset_criticality=Criticality.MEDIUM,
    ))
    assert with_kev.score > without_kev.score
    assert with_kev.score - without_kev.score == 25


def test_internet_facing_critical_asset_with_kev_is_critical_tier():
    result = score_finding(RiskInput(
        cvss_base_score=9.8, epss_score=0.9, in_kev=True,
        internet_facing=True, asset_criticality=Criticality.CRITICAL,
    ))
    assert result.tier == "critical"
    assert result.score == 100.0  # capped


def test_score_never_exceeds_100():
    result = score_finding(RiskInput(
        cvss_base_score=10.0, epss_score=1.0, in_kev=True,
        internet_facing=True, asset_criticality=Criticality.CRITICAL,
    ))
    assert result.score <= 100.0
