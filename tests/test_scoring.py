"""Tests for the fixed, per-rule score and grade scale."""
from app.scoring import ComprehensiveScorer


def score(findings):
    return ComprehensiveScorer().score_all(findings)["scan_summary"]


def test_no_findings_get_full_score_and_grade_a():
    result = score([])
    assert (result["overall_score"], result["grade"]) == (100, "A")


def test_severity_deductions_and_grade_boundaries():
    cases = [
        ([{"rule_id": "PWD001", "severity": "critical"}], 70, "C"),
        ([{"rule_id": "PWD002", "severity": "high"}], 80, "B"),
        ([{"rule_id": "PWD003", "severity": "medium"}], 90, "A"),
        ([{"rule_id": "PWD004", "severity": "low"}], 95, "A"),
        ([{"rule_id": "PWD001", "severity": "critical"},
         {"rule_id": "PWD002", "severity": "high"},
         {"rule_id": "PWD003", "severity": "medium"}], 40, "D"),
    ]
    for findings, expected_score, expected_grade in cases:
        result = score(findings)
        assert (result["overall_score"], result["grade"]) == (expected_score, expected_grade)


def test_repeated_rule_deduction_is_capped():
    findings = [{"rule_id": "PWD001", "severity": "critical"}] * 100
    assert score(findings)["overall_score"] == 70


def test_only_modern_hashing_adds_five_points():
    result = score([{"rule_id": "PWD007", "severity": "info"}])
    assert (result["overall_score"], result["grade"]) == (100, "A")


def test_modern_hashing_bonus_is_once_per_file():
    one_file = score([
        {"rule_id": "PWD004", "severity": "high", "file_name": "secure.py"},
        {"rule_id": "PWD007", "severity": "info", "file_name": "secure.py"},
        {"rule_id": "PWD007", "severity": "info", "file_name": "secure.py"},
    ])
    two_files = score([
        {"rule_id": "PWD004", "severity": "high", "file_name": "secure.py"},
        {"rule_id": "PWD007", "severity": "info", "file_name": "secure.py"},
        {"rule_id": "PWD007", "severity": "info", "file_name": "other.py"},
    ])
    assert (one_file["overall_score"], one_file["grade"]) == (85, "B")
    assert (two_files["overall_score"], two_files["grade"]) == (90, "A")


def test_score_is_clamped():
    result = score([
        {"rule_id": f"PWD{i:03d}", "severity": "critical"}
        for i in range(1, 20)
    ])
    assert (result["overall_score"], result["grade"]) == (0, "F")
