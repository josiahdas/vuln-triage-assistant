from app.risk.version_match import assess_applicability


PAN_OS_MULTI_BRANCH_DESC = (
    "Buffer overflow in the management web interface in Palo Alto Networks "
    "PAN-OS before 5.0.20, 5.1.x before 5.1.13, 6.0.x before 6.0.15, "
    "6.1.x before 6.1.15, 7.0.x before 7.0.11, and 7.1.x before 7.1.6 "
    "allows remote attackers to execute arbitrary code via unspecified vectors."
)

PAN_OS_OLD_DESC = (
    "Palo Alto Networks PAN-OS before 3.1.10 and 4.0.x before 4.0.5 "
    "allows remote attackers to execute arbitrary code."
)


def test_far_newer_major_version_is_not_affected():
    # This is the exact case the eval harness caught the LLM getting wrong
    assert assess_applicability(PAN_OS_MULTI_BRANCH_DESC, "10.1.0") == "not_affected"
    assert assess_applicability(PAN_OS_MULTI_BRANCH_DESC, "9.1.3") == "not_affected"


def test_version_within_affected_branch_is_affected():
    assert assess_applicability(PAN_OS_MULTI_BRANCH_DESC, "7.1.5") == "affected"


def test_version_at_fixed_threshold_is_not_affected():
    assert assess_applicability(PAN_OS_MULTI_BRANCH_DESC, "7.1.6") == "not_affected"


def test_old_cve_vs_ancient_affected_version():
    assert assess_applicability(PAN_OS_OLD_DESC, "4.0.3") == "affected"


def test_old_cve_vs_modern_version_is_not_affected():
    assert assess_applicability(PAN_OS_OLD_DESC, "10.1.0") == "not_affected"


def test_empty_description_is_unknown():
    assert assess_applicability("", "10.1.0") == "unknown"


def test_unparseable_asset_version_is_unknown():
    assert assess_applicability(PAN_OS_MULTI_BRANCH_DESC, "not-a-version") == "unknown"


def test_no_version_pattern_in_description_is_unknown():
    assert assess_applicability("A vulnerability exists in the product.", "10.1.0") == "unknown"
