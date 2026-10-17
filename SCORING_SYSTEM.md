# Comprehensive Scoring System Documentation

## Overview

The Password Storage Hardening Audit Tool uses a **multi-algorithm scoring system** that provides transparent, accurate, and nuanced security assessments. Instead of relying on a single scoring method, we employ five complementary algorithms to give you a complete picture of your code's security posture.

---

## The Five Scoring Algorithms

### 1. **CVSS v3.1-Inspired Scorer**
**Type:** Vector-based severity assessment  
**Range:** 0.0 - 10.0  
**Philosophy:** Mimics industry-standard CVSS scoring

#### How It Works:
- Assigns base scores by severity (Critical: 9.0, High: 7.0, Medium: 5.0, etc.)
- Applies environmental factors:
  - **In Authentication Code** (1.4x) - Found in login/auth functions
  - **In Production Code** (1.3x) - Affects live code
  - **Affects Admin** (1.5x) - Admin-level impact
  - **In Test Code** (0.3x) - Reduces severity for tests
- Multiplies by confidence score (0-1)
- Final Score = Base Score × Environmental Factor × Confidence

#### Example:
```
Finding: Plaintext password in login.py (auth function)
Base Score: 9.0 (Critical)
Environmental Factor: 1.4 (in auth) × 1.3 (production) = 1.82
Confidence: 0.95
Final: 9.0 × 1.82 × 0.95 = 15.6 → Capped at 10.0
```

**Use This For:** Understanding real-world severity considering context

---

### 2. **Weighted Aggregate Scorer**
**Type:** Score deduction model  
**Range:** 0 - 100  
**Philosophy:** Start at perfect score, deduct for issues

#### How It Works:
- Start with 100 (perfect security)
- Assign severity weights:
  - Critical: -40 points each
  - High: -25 points each
  - Medium: -12 points each
  - Low: -5 points each
  - Info: -1 point each
- Multiply weight by confidence (0-1)
- Deduct from base score: `Score = 100 - (Total Weighted Points × 0.8)`
- Clamp to 0-100 range

#### Example:
```
Findings:
- 1 Critical (0.95 confidence): 40 × 0.95 = 38 points
- 2 High (0.85 confidence): 25 × 0.85 × 2 = 42.5 points
- Total weight: 80.5

Score = 100 - (80.5 × 0.8) = 100 - 64.4 = 35.6
```

**Use This For:** Intuitive "passing grade" style assessment

---

### 3. **Risk Level Categorical Scorer**
**Type:** Threshold-based classification  
**Range:** Critical → Low  
**Philosophy:** Determines worst-case risk tier

#### How It Works:
- Counts findings by severity
- Applies threshold logic:
  - **Critical:** Any critical finding present
  - **High:** 3 or more high-severity findings
  - **Medium:** 10 or more medium-severity findings
  - **Low:** Only low/info findings
- Provides clear reasoning

#### Risk Levels & Actions:
| Risk Level | Score | Meaning | Action |
|-----------|-------|---------|--------|
| Critical | 10 | Any critical vulnerability | Fix immediately |
| High | 8 | Multiple high findings | Fix within days |
| Medium | 5 | Moderate findings | Plan remediation |
| Low | 2 | Only low/info issues | Routine updates |
| Info | 1 | Informational only | Monitor |

**Use This For:** Quick risk assessment, compliance requirements

---

### 4. **Confidence-Weighted Scorer**
**Type:** Uncertainty-adjusted scoring  
**Range:** 0 - 100  
**Philosophy:** Trust levels in individual findings

#### How It Works:
- Calculates average confidence across all findings
- High confidence findings have more impact
- Formula: `Score = 100 - (Severity Sum × (1 - Avg Confidence))`
- Highlights low-confidence findings for manual review

#### Confidence Levels:
- **High Confidence** (≥0.8): Algorithm is very sure
- **Medium Confidence** (0.6-0.8): Good confidence, verify
- **Low Confidence** (<0.6): Manual review recommended

#### Example:
```
3 findings: 0.95, 0.85, 0.65 confidence
Average: 0.816
Impact: High-confidence findings reduce score less
Score accounts for reliability of detection
```

**Use This For:** Understanding detection reliability

---

### 5. **Entropy Risk Scorer**
**Type:** Distribution analysis  
**Range:** 0 - 100 (normalized entropy)  
**Philosophy:** Measures problem concentration

#### How It Works:
- Calculates distribution of findings across files
- Uses Shannon entropy formula
- Normalized to 0-100 scale
- Provides risk reduction factor

#### Concentration Levels:
- **High Concentration** (Entropy <0.3): Issues in few files
  - Risk Reduction: 1.0x (full risk)
  - Action: Focus on problem areas
  
- **Medium Concentration** (Entropy 0.3-0.7): Spread findings
  - Risk Reduction: 0.9x (slight reduction)
  - Action: Systematic review
  
- **Low Concentration** (Entropy >0.7): Spread across many files
  - Risk Reduction: 0.8x (20% reduction)
  - Action: Infrastructure-level fixes

#### Example:
```
Finding Distribution:
- auth.py: 15 findings
- db.py: 2 findings
- utils.py: 3 findings

Entropy = 0.45 (medium concentration)
Recommendation: Focus on auth.py first
```

**Use This For:** Prioritizing remediation efforts

---

## Understanding Your Overall Score

### How the Primary Score is Calculated

```
Primary Score = (CVSS_Score × 0.3 + Weighted_Score × 0.4 + Confidence_Score × 0.3)
```

**Weights:**
- 30% CVSS v3.1-Inspired (severity with context)
- 40% Weighted Aggregate (traditional approach)
- 30% Confidence-Weighted (reliability)

### Grade Scale

| Score | Grade | Assessment | Color | Action |
|-------|-------|------------|-------|--------|
| 90-100 | A+ | Excellent | Green | Maintain current practices |
| 85-89 | A | Very Good | Green | Minor improvements |
| 80-84 | A- | Good | Green | Regular monitoring |
| 75-79 | B+ | Satisfactory | Yellow | Plan improvements |
| 70-74 | B | Fair | Yellow | Moderate action needed |
| 65-69 | B- | Weak | Orange | Significant work required |
| 60-64 | C+ | Poor | Orange | Major security issues |
| 55-59 | C | Poor | Orange | Critical remediation |
| 50-54 | D | Critical | Red | Emergency action |
| <50 | F | Failure | Red | Stop and fix immediately |

---

## Practical Examples

### Example 1: Single Critical Finding

**Scenario:** Found hardcoded API key in production code

**Algorithm Results:**
```
Algorithm              Score/Result
──────────────────────────────────
CVSS v3.1             9.5 (Critical)
Weighted Aggregate    45.2/100
Risk Level            Critical
Confidence-Weighted   52.1/100
Entropy Risk          100 (concentrated)

PRIMARY SCORE: 52.1
GRADE: D (Critical)
```

**Assessment:** Emergency action required. Single high-impact finding in critical area.

**Recommendations:**
1. Rotate the exposed API key immediately
2. Remove hardcoded secret from source
3. Implement secrets management
4. Audit git history

---

### Example 2: Multiple Low Findings Spread Across Files

**Scenario:** 
- 5 low-severity findings in config.py
- 3 low-severity findings in test_utils.py
- 2 low-severity findings in logging.py

**Algorithm Results:**
```
Algorithm              Score/Result
──────────────────────────────────
CVSS v3.1             3.2 (Low)
Weighted Aggregate    82.5/100
Risk Level            Low
Confidence-Weighted   81.8/100
Entropy Risk          45 (moderate spread)

PRIMARY SCORE: 82.1
GRADE: A- (Good)
```

**Assessment:** Generally secure with minor improvements possible.

**Recommendations:**
1. Review logging practices (informational)
2. Clean up test utilities
3. Verify config security

---

### Example 3: Mixed Severity Findings, High Confidence

**Scenario:**
- 1 Critical: plaintext password (confidence: 0.98)
- 3 High: MD5 hashing (confidence: 0.99)
- 5 Medium: base64 encoding (confidence: 0.85)

**Algorithm Results:**
```
Algorithm              Score/Result
──────────────────────────────────
CVSS v3.1             8.7 (High)
Weighted Aggregate    38.2/100
Risk Level            High
Confidence-Weighted   42.1/100
Entropy Risk          25 (concentrated)

PRIMARY SCORE: 42.8
GRADE: C+ (Poor)
```

**Assessment:** High security risk requiring immediate attention.

**Recommendations:**
1. **Urgent:** Replace plaintext password with secure hashing
2. **Priority:** Upgrade MD5 to Argon2 or bcrypt
3. **Soon:** Replace base64 with proper encryption (AES)
4. All findings have high confidence (98-99%) - act with confidence

---

## Interpreting the API Response

### Scoring Breakdown Endpoint
`GET /api/scanner/scan/<scan_id>/scoring-breakdown`

**Response Structure:**
```json
{
  "timestamp": "2026-10-16T12:34:56.789Z",
  "scan_summary": {
    "total_findings": 8,
    "overall_score": 65.3,
    "grade": "C+",
    "assessment": "Poor - High security risk"
  },
  "severity_distribution": {
    "critical": 1,
    "high": 3,
    "medium": 2,
    "low": 2,
    "info": 0,
    "total": 8
  },
  "algorithm_results": {
    "cvss": {
      "algorithm": "CVSS v3.1-Inspired",
      "score": 8.7,
      "average_score": 6.2,
      "breakdown": { /* detailed by severity */ }
    },
    "weighted": {
      "algorithm": "Weighted Aggregate",
      "score": 38.2,
      "total_weight": 77.5,
      "severity_breakdown": { /* counts */ }
    },
    "risk_level": {
      "algorithm": "Risk Level",
      "risk_level": "High",
      "risk_score": 8,
      "reasoning": "3 high-severity findings"
    },
    "confidence": {
      "algorithm": "Confidence-Weighted",
      "score": 42.1,
      "average_confidence": 0.938,
      "low_confidence_findings": 0
    },
    "entropy": {
      "algorithm": "Entropy Risk",
      "entropy_score": 25.3,
      "concentration": "High (concentrated in few files)",
      "files_affected": 3
    }
  },
  "confidence_analysis": {
    "average": 0.938,
    "high_confidence": 7,
    "medium_confidence": 1,
    "low_confidence": 0
  },
  "recommendations": [
    "Urgent: Address 1 critical vulnerability(ies) immediately",
    "Priority: Remediate 3 high-severity finding(s) within days",
    "Findings are concentrated - focus on 3 file(s)"
  ],
  "detailed_breakdown": { /* methodology and explanations */ }
}
```

---

## When to Use Each Algorithm

| Situation | Best Algorithm | Why |
|-----------|---------------|-----|
| Risk assessment for management | Risk Level | Simple, categorical |
| Compliance/standards compliance | CVSS v3.1-Inspired | Industry standard |
| Traditional scoring (pass/fail) | Weighted Aggregate | Intuitive 0-100 |
| Determine reliability | Confidence-Weighted | Shows detection quality |
| Prioritize fixes | Entropy Risk | Shows where to focus |
| Comprehensive view | All Five | Complete picture |

---

## Best Practices for Interpreting Scores

### ✅ DO:
- Consider all five algorithms together
- Look at confidence levels
- Review recommendations
- Check severity distribution
- Prioritize high-confidence critical findings

### ❌ DON'T:
- Rely on a single score alone
- Ignore low-confidence findings
- Forget context (test vs. production code)
- Assume high score = no security issues
- Make security decisions without manual review

---

## Confidence Levels Explained

**How Confidence is Determined:**

1. **Pattern Matching Confidence (0.8-0.99)**
   - Strong regex: 0.95+
   - Weak pattern: 0.70-0.80

2. **Context Adjustment**
   - Auth code: +0.3x (higher confidence)
   - Test code: -0.7x (lower confidence)
   - Production: +0.2x (higher confidence)

3. **Environmental Factors**
   - Found near sensitive operations: +0.1
   - In version control: +0.05
   - Commented code: -0.1

**Typical Confidence Ranges:**
- **0.95-0.99:** Nearly certain (strong evidence)
- **0.85-0.94:** Very confident (good evidence)
- **0.70-0.84:** Confident (pattern matches)
- **0.50-0.69:** Moderate (needs verification)
- **<0.50:** Low (manual review essential)

---

## Continuous Improvement

The scoring system learns from:
1. User feedback on false positives/negatives
2. Pattern accuracy in real-world scans
3. Remediation effectiveness tracking

**Send Feedback:** Include scan ID and assessment when reporting scoring issues.

---

## Troubleshooting

**Q: Why is my score lower/higher than expected?**
- Check confidence levels - they significantly impact score
- Review severity distribution
- Verify findings are in production vs. test code

**Q: What does "concentrated" mean?**
- Findings are in few files (high entropy) vs. spread across many
- Concentrated = easier to fix; spread = systematic issue

**Q: Can I ignore low-confidence findings?**
- No! Manually verify them. They may indicate real issues.
- Use as secondary review layer.

**Q: How often should I rescan?**
- After code changes (CI/CD integration recommended)
- Quarterly minimum for production code
- Before releases mandatory

---

## For Developers

### Integration Example

```python
from app.scoring import ComprehensiveScorer

scorer = ComprehensiveScorer()
findings = [
    {"rule_id": "PWD001", "severity": "critical", "confidence": 0.98, ...},
    {"rule_id": "PWD002", "severity": "high", "confidence": 0.85, ...},
]

report = scorer.score_all(findings)
print(f"Score: {report['scan_summary']['overall_score']}")
print(f"Grade: {report['scan_summary']['grade']}")
print(f"Assessment: {report['scan_summary']['assessment']}")
```

---

## Version History

- **v2.0** (Oct 2026): Five-algorithm comprehensive scoring system
  - CVSS v3.1-inspired
  - Weighted aggregation
  - Risk level classification
  - Confidence-weighted
  - Entropy-based distribution

---

**Last Updated:** October 16, 2026  
**System Version:** Password Audit Tool v2.0  
**Questions?** Contact security@example.com
