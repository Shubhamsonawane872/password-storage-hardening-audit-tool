"""Tests for finding-count-based primary security scores and grades."""

from pathlib import Path

import pytest

from app.scanner.patterns import CodeScanner
from app.scanner.rules import get_rule
from app.scoring import ComprehensiveScorer


@pytest.mark.parametrize(
    ("severities", "expected_score", "expected_grade"),
    [
        ([], 100, "A+"),
        (["medium"], 88, "A"),
        (["low"] * 4, 80, "A-"),
        (["high"], 75, "B+"),
        (["high", "info"], 75, "B+"),
        (["low"] * 7, 65, "B-"),
        (["critical"], 60, "C+"),
        (["critical", "info"], 60, "C+"),
        (["high"] * 2, 50, "D"),
        (["critical"] * 2, 20, "F"),
        (["info"] * 100, 100, "A+"),
    ],
)
def test_severity_combinations_produce_expected_score_and_grade(
    severities, expected_score, expected_grade
):
    findings = [{"severity": severity} for severity in severities]

    summary = ComprehensiveScorer().score_all(findings)["scan_summary"]

    assert summary["overall_score"] == expected_score
    assert summary["grade"] == expected_grade


def test_primary_score_uses_fixed_deduction_per_finding():
    scorer = ComprehensiveScorer()
    findings = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"},
        {"severity": "info"},
    ]

    report = scorer.score_all(findings)

    assert report["scan_summary"]["overall_score"] == 18
    assert report["scan_summary"]["grade"] == "F"


def test_primary_score_ignores_confidence_and_context():
    scorer = ComprehensiveScorer()
    low_confidence = [{"severity": "high", "confidence": 0.1}]
    high_confidence = [{
        "severity": "high",
        "confidence": 1.0,
        "context": {"in_authentication": True, "affects_admin": True},
    }]

    assert scorer.score_all(low_confidence)["scan_summary"]["overall_score"] == 75
    assert scorer.score_all(high_confidence)["scan_summary"]["overall_score"] == 75


def test_primary_score_clamps_at_zero():
    scorer = ComprehensiveScorer()
    findings = [{"severity": "critical"}] * 3

    report = scorer.score_all(findings)

    assert report["scan_summary"]["overall_score"] == 0
    assert report["scan_summary"]["grade"] == "F"


def test_no_findings_get_full_score_and_top_grade():
    report = ComprehensiveScorer().score_all([])

    assert report["scan_summary"]["overall_score"] == 100
    assert report["scan_summary"]["grade"] == "A+"


def test_safer_sample_information_does_not_lower_grade():
    sample_path = Path("sample_apps/safer_sample.py")
    raw_findings = CodeScanner().scan_file(
        sample_path.name, sample_path.read_text(encoding="utf-8")
    )
    findings = [
        {"severity": get_rule(finding["rule_id"])["severity"]}
        for finding in raw_findings
    ]

    summary = ComprehensiveScorer().score_all(findings)["scan_summary"]

    assert findings
    assert all(finding["severity"] == "info" for finding in findings)
    assert summary["overall_score"] == 100
    assert summary["grade"] == "A+"
