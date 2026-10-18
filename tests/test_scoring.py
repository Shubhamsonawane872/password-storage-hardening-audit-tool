"""Tests for finding-count-based primary security scores and grades."""

import pytest

from app.scoring import ComprehensiveScorer


@pytest.mark.parametrize(
    ("severities", "expected_score", "expected_grade"),
    [
        ([], 100, "A+"),
        (["medium"], 88, "A"),
        (["low"] * 4, 80, "A-"),
        (["high"], 75, "B+"),
        (["high", "info"], 74, "B"),
        (["low"] * 7, 65, "B-"),
        (["critical"], 60, "C+"),
        (["critical", "info"], 59, "C"),
        (["high"] * 2, 50, "D"),
        (["critical"] * 2, 20, "F"),
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

    assert report["scan_summary"]["overall_score"] == 17
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
