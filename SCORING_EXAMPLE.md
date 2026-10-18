# Comprehensive Scoring System - Live Examples

> **Current primary score rule:** start at 100 and deduct 40 per critical, 25 per high, 12 per medium, and 5 per low finding; informational findings have no deduction. Clamp to 0–100 and apply the existing grade scale. Supplementary algorithms, context, and confidence do not affect the primary score or grade.

## Quick Start: Understanding Your Score

When you upload code for scanning, you'll receive a detailed scoring report using **5 different algorithms**. Here's what you'll see:

---

## Example 1: Website with Critical Security Issues

### The Scan Results

```
Files Uploaded: auth.py, db.py, config.py
Total Findings: 6
Critical: 1 | High: 2 | Medium: 2 | Low: 1

PRIMARY SCORE: 0.0 / 100
GRADE: F (Failure - Critical security risk)
```

### Detailed Breakdown by Algorithm

#### 🔴 CVSS v3.1-Inspired (Score: 8.7/10)

**What it shows:** Real-world severity considering context

```
Finding Analysis:
- Plaintext password in auth.py (line 15)
  Base Score: 9.0 (critical severity)
  Context: In authentication function (+1.4x)
  Context: Production code (+1.3x)
  Confidence: 0.98
  Final: 9.0 × 1.82 × 0.98 = 16.0 → CAPPED AT 10.0

- MD5 password hashing (3 instances)
  Base Score: 8.5 each
  Context: Authentication code (+1.4x)
  Confidence: 0.99
  Final: ~11.6 → CAPPED AT 10.0

Average CVSS: 8.7/10
```

**What it means:** At least one finding is at maximum severity. Requires immediate action.

---

#### 📊 Weighted Aggregate (Score: 38.2/100)

**What it shows:** Traditional "starting at 100, losing points" approach

```
Point Deductions:
- 1 Critical finding @ 0.98 confidence:  40 × 0.98 = 39.2 points
- 2 High findings @ 0.99 confidence:     25 × 0.99 × 2 = 49.5 points
- 2 Medium findings @ 0.85 confidence:   12 × 0.85 × 2 = 20.4 points
- 1 Low finding @ 0.70 confidence:       5 × 0.70 = 3.5 points

Total Weight: 112.6 points
Adjustment Factor: 0.8 (moderate reduction)
Score = 100 - (112.6 × 0.8) = 100 - 90.08 = 9.92 → ~38.2
```

**What it means:** You're losing about 90 points on security. Major issues.

---

#### 🎯 Risk Level Categorical (Risk: HIGH)

**What it shows:** Worst-case assessment

```
Threshold Analysis:
- Critical findings present? YES (1 found)
- → RISK LEVEL: HIGH (possibly CRITICAL)

Reasoning: "1 critical vulnerability(ies) found"
Color: 🔴 Red
Risk Score: 8/10

Recommendation: Address critical finding immediately before deployment
```

**What it means:** Do not deploy. Fix critical issues first.

---

#### 📈 Confidence-Weighted (Score: 42.1/100)

**What it shows:** Trust level in the findings

```
Confidence Analysis:
- 5 High-Confidence findings (0.98-0.99)
- 1 Medium-Confidence finding (0.75)

Average Confidence: 0.938 (93.8% sure these are real)

Severity Impact:
- Critical × High Confidence: HIGH TRUST
- High × High Confidence: HIGH TRUST
- Low × Medium Confidence: VERIFY MANUALLY

Score Calculation:
Score = 100 - (Severity Sum × (1 - Avg Confidence))
Score = 100 - (Total Weight × (1 - 0.938))
Score = 100 - (Weighted × 0.062) = 42.1
```

**What it means:** We're 93.8% confident about these findings. Act with confidence.

---

#### 🌐 Entropy Risk Distribution (Concentration: HIGH)

**What it shows:** Where problems are concentrated

```
File Distribution:
- auth.py:        5 findings (83%)
- config.py:      1 finding (17%)
- db.py:          0 findings

Shannon Entropy: 0.25 (HIGH concentration)
Concentration Level: "High (concentrated in few files)"
Risk Reduction Factor: 1.0x (no reduction)

Analysis:
- Findings are concentrated in auth.py
- Action: Fix auth.py first (will solve most issues)
- Files Affected: 2 out of 3
```

**What it means:** Your security problems are in one main file. Fix auth.py, and you've solved 83% of issues.

---

### What This Means for You

| Algorithm | Says | Translation |
|-----------|------|-------------|
| CVSS | 8.7/10 | Extremely high severity |
| Weighted | 38.2/100 | Failing grade |
| Risk | HIGH | Critical risk level |
| Confidence | 93.8% | We're very sure |
| Entropy | auth.py | Focus here first |

### Your Action Items (Prioritized)

1. **IMMEDIATELY (Today):**
   - Remove hardcoded password in auth.py line 15
   - Rotate exposed credentials

2. **URGENT (Within 24 hours):**
   - Replace MD5 with Argon2 (3 locations in auth.py)
   - Enable password hashing in config.py

3. **SOON (Within a week):**
   - Add salt to password hashing
   - Implement secrets management system

---

## Example 2: Generally Secure Code with Minor Issues

### The Scan Results

```
Files Uploaded: app.py, utils.py, models.py
Total Findings: 4
Critical: 0 | High: 0 | Medium: 2 | Low: 2

PRIMARY SCORE: 50.0 / 100
GRADE: D (Critical)
```

### Quick Breakdown

#### Algorithm Consensus

```
Algorithm              Result          Assessment
─────────────────────────────────────────────────
CVSS v3.1-Inspired     5.2/10         Moderate
Weighted Aggregate     82.5/100       Good score
Risk Level             MEDIUM         Plan improvements
Confidence             81.8%          Good trust level
Entropy Risk           Spread         (findings across 3 files)
```

### Interpretation

✅ **Good News:**
- No critical or high-severity findings
- Confidence is solid (81.8%)
- Issues are spread (not concentrated in one area)
- Risk level is moderate (not urgent)

⚠️ **Action Items:**
1. Review 2 medium-severity findings
2. Address 2 low-severity issues
3. Continue current security practices
4. Plan incremental improvements

**Timeline:** Fix within 1-2 months as part of regular maintenance.

---

## Example 3: Excellent Security Code

### The Scan Results

```
Files Uploaded: secure_app.py
Total Findings: 0

PRIMARY SCORE: 100.0 / 100
GRADE: A+ (Excellent - Minimal security risk)
```

### The Report

```
Assessment: "No vulnerabilities detected"

Algorithm Results:
- CVSS v3.1-Inspired:     0.0/10 (No issues)
- Weighted Aggregate:     100/100 (Perfect)
- Risk Level:             Low
- Confidence:             N/A (no findings to assess)
- Entropy Risk:           N/A (no findings to distribute)

Recommendation: "Continue monitoring - maintain current security posture"
```

---

## How to Read the Full Report

### Accessing the Detailed Scoring Report

**Endpoint:** `GET /api/scanner/scan/{scan_id}/scoring-breakdown`

**Example Response:**

```json
{
  "timestamp": "2026-10-16T14:30:00Z",
  "scan_summary": {
    "total_findings": 6,
    "overall_score": 0.0,
    "grade": "F",
    "assessment": "Poor - High security risk"
  },
  "severity_distribution": {
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 1,
    "info": 0,
    "total": 6
  },
  "algorithm_results": {
    "cvss": {
      "algorithm": "CVSS v3.1-Inspired",
      "score": 8.7,
      "max_score": 8.7,
      "average_score": 6.2,
      "finding_count": 6,
      "breakdown": {
        "critical": {
          "count": 1,
          "scores": [10.0]
        },
        "high": {
          "count": 2,
          "scores": [8.5, 8.5]
        },
        "medium": {
          "count": 2,
          "scores": [5.1, 5.3]
        },
        "low": {
          "count": 1,
          "scores": [2.5]
        }
      },
      "description": "Highest CVSS score among 6 findings"
    },
    "weighted": {
      "algorithm": "Weighted Aggregate",
      "score": 38.2,
      "total_weight": 112.6,
      "findings_count": 6,
      "severity_breakdown": {
        "critical": 1,
        "high": 2,
        "medium": 2,
        "low": 1,
        "info": 0
      },
      "description": "Score based on 6 weighted findings"
    },
    "risk_level": {
      "algorithm": "Risk Level",
      "risk_level": "High",
      "risk_score": 8,
      "reasoning": "1 critical vulnerability(ies) found",
      "color": "red",
      "severity_distribution": {
        "critical": 1,
        "high": 2,
        "medium": 2,
        "low": 1,
        "info": 0
      },
      "description": "Overall risk posture assessment"
    },
    "confidence": {
      "algorithm": "Confidence-Weighted",
      "score": 42.1,
      "average_confidence": 0.938,
      "weighted_score": 42.1,
      "low_confidence_findings": 0,
      "high_confidence_findings": 6,
      "description": "Score adjusted by 93.8% average confidence"
    },
    "entropy": {
      "algorithm": "Entropy Risk",
      "entropy_score": 25.3,
      "concentration": "High (concentrated in few files)",
      "files_affected": 2,
      "risk_reduction_factor": 1.0,
      "description": "Findings distributed across 2 file(s)"
    }
  },
  "confidence_analysis": {
    "average": 0.938,
    "high_confidence": 6,
    "medium_confidence": 0,
    "low_confidence": 0,
    "total_findings": 6
  },
  "recommendations": [
    "URGENT: Address 1 critical vulnerability(ies) immediately",
    "Priority: Remediate 2 high-severity finding(s) within days",
    "Findings are concentrated - focus on 2 file(s)"
  ],
  "detailed_breakdown": {
    "methodology": {
      "primary_score": "Fixed severity deductions per finding, clamped to 0-100",
      "grade_scale": "A+ (90-100), A (85-89), ... F (<50)",
      "algorithms_used": ["cvss", "weighted", "risk_level", "confidence", "entropy"]
    },
    "how_to_read": {
      "overall_score": "Primary metric (0-100) from finding severities and counts",
      "grade": "Letter grade equivalent",
      "cvss_score": "Max CVSS-like severity (0-10)",
      "weighted_score": "Score based on severity and confidence weighting",
      "risk_level": "Categorical risk assessment",
      "confidence_analysis": "Trust level in the findings"
    },
    "algorithm_explanations": {
      "cvss": "CVSS v3.1-inspired: Base scores adjusted by context",
      "weighted": "Traditional: Start 100, deduct per finding",
      "risk_level": "Threshold-based: Risk determined by worst finding",
      "confidence": "Confidence-adjusted: High confidence = more impact",
      "entropy": "Distribution: Concentrated vs. spread findings"
    }
  }
}
```

---

## Quick Reference Guide

### When to Use Each Algorithm

| Need | Use | Why |
|------|-----|-----|
| Executive report | Grade + Risk Level | Simple, decisive |
| Technical assessment | CVSS + Weighted | Professional standard |
| Reliability check | Confidence score | Know what to trust |
| Fix prioritization | Entropy risk | Where to focus |
| Compliance proof | All five together | Complete picture |

### Interpreting Confidence Levels

```
Score Component        Confidence Level
────────────────────────────────────
CVSS/Weighted Score    Depends on finding confidence
Overall Score          Weighted by all findings
Grade Accuracy         Higher with high confidence
```

---

## Tips for Better Results

### 1. Address High-Confidence Findings First
- Confidence 0.95+: Act immediately
- Confidence 0.80-0.95: High priority
- Confidence 0.60-0.80: Verify, then fix
- Confidence <0.60: Manual review before acting

### 2. Use Concentration Data
- Concentrated in 1-2 files: Fix those files thoroughly
- Spread across many files: Systematic approach needed
- Very spread (entropy >0.7): Infrastructure/process fix

### 3. Monitor Trends
- Scan regularly (after each major change)
- Track score over time
- Celebrate grade improvements
- Maintain good grades with proactive fixes

### 4. Manual Verification
- Always spot-check critical findings
- Review code context
- Run your own tests
- Don't blindly trust automation

---

## Frequently Asked Questions

**Q: Why do I have different scores from different algorithms?**  
A: Each algorithm looks at security differently. CVSS emphasizes severity, Weighted is traditional, Confidence accounts for certainty. Together they give a complete picture.

**Q: Which score matters most?**  
A: The primary score is based only on finding severities and counts. Read the other algorithms as supplementary context.

**Q: What if I disagree with a finding?**  
A: Check the confidence level. Low confidence findings warrant manual review and may be false positives.

**Q: How do I know if my score is good?**  
A: Grade A- (80+) is excellent. B range (70-79) is acceptable. C or below needs action.

**Q: Should I aim for 100?**  
A: No. 85-95 is realistic and healthy for production code. Perfection isn't necessary.

---

## Contact & Support

- **Questions about scoring?** See SCORING_SYSTEM.md for detailed explanations
- **Found a false positive?** Report with scan ID to help improve accuracy
- **Want different scoring?** Scoring algorithms are open source - customize as needed

---

**Last Updated:** October 16, 2026  
**System:** Password Audit Tool v2.0  
**Version:** Comprehensive Scoring System v1.0
