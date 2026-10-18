"""Tests for finding-count-based primary security scores and grades."""

from app.scoring import ComprehensiveScorer


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
