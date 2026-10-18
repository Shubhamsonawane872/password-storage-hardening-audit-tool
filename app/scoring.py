"""
Comprehensive Scoring System with Multiple Algorithms

Provides transparent, multi-algorithm vulnerability assessment:
1. CVSS v3.1-inspired severity scoring
2. Weighted aggregate scoring
3. Entropy-based risk analysis
4. Confidence-weighted scoring
5. Category-specific scoring
6. Detailed breakdown for understanding
"""

from typing import List, Dict, Tuple, Optional
import math
from enum import Enum


class SeverityLevel(Enum):
    """Standard severity classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScoringAlgorithm:
    """Base class for different scoring algorithms"""
    
    def calculate(self, findings: List[Dict]) -> Dict:
        """Calculate security score using this algorithm"""
        raise NotImplementedError


class CVSSv3InspiredScorer(ScoringAlgorithm):
    """
    CVSS v3.1-inspired scoring algorithm
    
    Mimics Common Vulnerability Scoring System approach:
    - Base score (0-10) determined by severity
    - Attack vector, attack complexity, privileges required, user interaction
    - Scope and confidentiality/integrity/availability impact
    """
    
    # CVSS-like base scores by severity
    SEVERITY_BASE_SCORES = {
        "critical": 9.0,  # 9.0-10.0
        "high": 7.0,      # 7.0-8.9
        "medium": 5.0,    # 5.0-6.9
        "low": 3.0,       # 3.0-4.9
        "info": 0.5       # 0.1-3.9
    }
    
    # Environmental factors (multipliers)
    ENVIRONMENTAL_FACTORS = {
        "in_authentication": 1.4,      # Found in auth code = higher risk
        "in_production": 1.3,           # Production code vs test
        "affects_admin": 1.5,           # Admin-related code
        "no_mitigation": 1.2,           # No defensive coding
        "in_test": 0.3,                 # Test/demo code = lower risk
        "has_mitigation": 0.7,          # Mitigated or defended
    }
    
    def calculate(self, findings: List[Dict]) -> Dict:
        """Calculate CVSS-like score for all findings"""
        if not findings:
            return {
                "algorithm": "CVSS v3.1-Inspired",
                "score": 0.0,
                "max_score": 0.0,
                "average_score": 0.0,
                "finding_count": 0,
                "breakdown": {}
            }
        
        scores = []
        breakdown = {
            "critical": {"count": 0, "scores": []},
            "high": {"count": 0, "scores": []},
            "medium": {"count": 0, "scores": []},
            "low": {"count": 0, "scores": []},
            "info": {"count": 0, "scores": []}
        }
        
        for finding in findings:
            severity = finding.get("severity", "medium")
            base_score = self.SEVERITY_BASE_SCORES.get(severity, 5.0)
            
            # Apply environmental factors
            environmental_factor = 1.0
            context = finding.get("context", {})
            
            for factor, multiplier in self.ENVIRONMENTAL_FACTORS.items():
                if context.get(factor):
                    environmental_factor *= multiplier
            
            # Apply confidence weighting
            confidence = finding.get("confidence", 0.8)
            final_score = base_score * environmental_factor * confidence
            final_score = min(final_score, 10.0)  # Cap at 10.0
            
            scores.append(final_score)
            if severity in breakdown:
                breakdown[severity]["count"] += 1
                breakdown[severity]["scores"].append(round(final_score, 2))
        
        max_score = max(scores) if scores else 0.0
        average_score = sum(scores) / len(scores) if scores else 0.0
        
        return {
            "algorithm": "CVSS v3.1-Inspired",
            "score": round(max_score, 2),
            "max_score": round(max_score, 2),
            "average_score": round(average_score, 2),
            "finding_count": len(findings),
            "breakdown": breakdown,
            "description": f"Highest CVSS score among {len(findings)} findings"
        }


class WeightedAggregateScorer(ScoringAlgorithm):
    """
    Weighted aggregation scoring algorithm
    
    Calculates overall security score (0-100) by:
    1. Assigning severity weights
    2. Adjusting by confidence
    3. Reducing score proportionally to findings
    """
    
    # Severity weights (impact on overall score)
    SEVERITY_WEIGHTS = {
        "critical": 40,  # Each critical finding loses 40 points
        "high": 25,
        "medium": 12,
        "low": 5,
        "info": 1
    }
    
    def calculate(self, findings: List[Dict]) -> Dict:
        """Calculate weighted aggregate score (0-100)"""
        if not findings:
            return {
                "algorithm": "Weighted Aggregate",
                "score": 100,
                "total_weight": 0,
                "findings_count": 0,
                "severity_breakdown": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
            }
        
        total_weight = 0
        severity_breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "medium")
            confidence = finding.get("confidence", 0.8)
            
            # Weight by severity and confidence
            weight = self.SEVERITY_WEIGHTS.get(severity, 10)
            adjusted_weight = weight * confidence
            total_weight += adjusted_weight
            
            if severity in severity_breakdown:
                severity_breakdown[severity] += 1
        
        # Calculate final score: start at 100, reduce by total weight
        # Use sigmoid-like function to cap reduction
        score = 100 - (total_weight * 0.8)  # 0.8 factor to not go too negative too fast
        score = max(0, min(100, score))  # Clamp to 0-100
        
        return {
            "algorithm": "Weighted Aggregate",
            "score": round(score, 1),
            "total_weight": round(total_weight, 2),
            "findings_count": len(findings),
            "severity_breakdown": severity_breakdown,
            "description": f"Score based on {len(findings)} weighted findings"
        }


class RiskLevelScorer(ScoringAlgorithm):
    """
    Risk level classification scorer
    
    Determines overall risk posture using:
    1. Severity distribution
    2. Density of findings
    3. Confidence averaging
    """
    
    RISK_THRESHOLDS = {
        "critical": 1,      # Any critical finding = critical risk
        "high": 3,          # 3+ high = high risk
        "medium": 10,       # 10+ medium = medium risk
        "low": 999,         # Many low = low risk
    }
    
    def calculate(self, findings: List[Dict]) -> Dict:
        """Determine overall risk level"""
        if not findings:
            return {
                "algorithm": "Risk Level",
                "risk_level": "Low",
                "risk_score": 1,
                "reasoning": "No vulnerabilities found",
                "color": "green"
            }
        
        severity_counts = {
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low": sum(1 for f in findings if f.get("severity") == "low"),
            "info": sum(1 for f in findings if f.get("severity") == "info"),
        }
        
        # Determine risk level based on thresholds
        if severity_counts["critical"] >= self.RISK_THRESHOLDS["critical"]:
            risk_level = "Critical"
            risk_score = 10
            reasoning = f"{severity_counts['critical']} critical vulnerability(ies) found"
            color = "red"
        elif severity_counts["high"] >= self.RISK_THRESHOLDS["high"]:
            risk_level = "High"
            risk_score = 8
            reasoning = f"{severity_counts['high']} high-severity findings"
            color = "orange"
        elif severity_counts["medium"] >= self.RISK_THRESHOLDS["medium"]:
            risk_level = "Medium"
            risk_score = 5
            reasoning = f"{severity_counts['medium']} medium-severity findings"
            color = "yellow"
        elif severity_counts["low"] > 0:
            risk_level = "Low"
            risk_score = 2
            reasoning = f"Only {severity_counts['low']} low-severity findings"
            color = "lightgreen"
        else:
            risk_level = "Info"
            risk_score = 1
            reasoning = "Only informational findings"
            color = "blue"
        
        return {
            "algorithm": "Risk Level",
            "risk_level": risk_level,
            "risk_score": risk_score,
            "reasoning": reasoning,
            "color": color,
            "severity_distribution": severity_counts,
            "description": "Overall risk posture assessment"
        }


class ConfidenceWeightedScorer(ScoringAlgorithm):
    """
    Confidence-weighted scoring algorithm
    
    Scores based on:
    1. Individual finding confidence
    2. Severity of findings
    3. Average confidence across all findings
    """
    
    def calculate(self, findings: List[Dict]) -> Dict:
        """Calculate confidence-weighted score"""
        if not findings:
            return {
                "algorithm": "Confidence-Weighted",
                "score": 100,
                "average_confidence": 1.0,
                "weighted_score": 100,
                "low_confidence_findings": 0
            }
        
        confidences = [f.get("confidence", 0.8) for f in findings]
        avg_confidence = sum(confidences) / len(confidences)
        
        # Score = 100 - (finding_count * average_weight * (1 - avg_confidence))
        # High confidence findings have less impact on score reduction
        severity_sum = sum(
            self._severity_to_weight(f.get("severity", "medium"))
            for f in findings
        )
        
        # Adjust score based on confidence
        confidence_factor = avg_confidence
        adjusted_score = 100 - (severity_sum * (1 - confidence_factor))
        weighted_score = max(0, min(100, adjusted_score))
        
        low_conf_findings = sum(1 for f in findings if f.get("confidence", 0.8) < 0.7)
        
        return {
            "algorithm": "Confidence-Weighted",
            "score": round(weighted_score, 1),
            "average_confidence": round(avg_confidence, 3),
            "weighted_score": round(weighted_score, 1),
            "low_confidence_findings": low_conf_findings,
            "high_confidence_findings": len(findings) - low_conf_findings,
            "description": f"Score adjusted by {round(avg_confidence * 100, 1)}% average confidence"
        }
    
    def _severity_to_weight(self, severity: str) -> float:
        """Map severity to numeric weight"""
        weights = {
            "critical": 50,
            "high": 30,
            "medium": 15,
            "low": 5,
            "info": 1
        }
        return weights.get(severity, 15)


class EntropyRiskScorer(ScoringAlgorithm):
    """
    Entropy-based risk assessment
    
    Analyzes:
    1. Distribution of findings (concentrated vs spread)
    2. File entropy (number of findings per file)
    3. Risk clustering
    """
    
    def calculate(self, findings: List[Dict]) -> Dict:
        """Calculate entropy-based risk score"""
        if not findings:
            return {
                "algorithm": "Entropy Risk",
                "entropy_score": 0,
                "concentration": "None",
                "description": "No findings to analyze"
            }
        
        # File distribution analysis
        files = {}
        for finding in findings:
            fname = finding.get("file_name", "unknown")
            if fname not in files:
                files[fname] = {"count": 0, "severity_count": {}}
            files[fname]["count"] += 1
            
            severity = finding.get("severity", "medium")
            if severity not in files[fname]["severity_count"]:
                files[fname]["severity_count"][severity] = 0
            files[fname]["severity_count"][severity] += 1
        
        # Calculate entropy (measure of disorder/spread)
        # High entropy = spread across many files (less critical)
        # Low entropy = concentrated in few files (more critical)
        total_findings = len(findings)
        file_count = len(files)
        
        if file_count == 0:
            return {
                "algorithm": "Entropy Risk",
                "entropy_score": 0,
                "concentration": "None"
            }
        
        # Shannon entropy
        entropy = 0.0
        for fname, data in files.items():
            proportion = data["count"] / total_findings
            if proportion > 0:
                entropy -= proportion * math.log2(proportion)
        
        # Normalize entropy (max entropy when spread evenly)
        max_entropy = math.log2(file_count) if file_count > 0 else 0
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
        
        # Determine concentration (inverse of entropy)
        if normalized_entropy > 0.7:
            concentration = "Low (spread across many files)"
            risk_reduction = 0.8  # Lower risk
        elif normalized_entropy > 0.4:
            concentration = "Medium (moderate spread)"
            risk_reduction = 0.9
        else:
            concentration = "High (concentrated in few files)"
            risk_reduction = 1.0  # Full risk
        
        entropy_score = round(normalized_entropy * 100, 1)
        
        return {
            "algorithm": "Entropy Risk",
            "entropy_score": entropy_score,
            "concentration": concentration,
            "files_affected": file_count,
            "risk_reduction_factor": risk_reduction,
            "description": f"Findings distributed across {file_count} file(s)"
        }


class ComprehensiveScorer:
    """
    Master scoring system combining all algorithms
    
    Provides:
    1. Multiple scoring perspectives
    2. Clear breakdowns
    3. Actionable recommendations
    4. Grade assignment (A-F)
    """

    PRIMARY_SEVERITY_DEDUCTIONS = {
        "critical": 40,
        "high": 25,
        "medium": 12,
        "low": 5,
        "info": 1,
    }

    def __init__(self):
        self.scorers = {
            "cvss": CVSSv3InspiredScorer(),
            "weighted": WeightedAggregateScorer(),
            "risk_level": RiskLevelScorer(),
            "confidence": ConfidenceWeightedScorer(),
            "entropy": EntropyRiskScorer(),
        }
    
    def score_all(self, findings: List[Dict], scan_metadata: Optional[Dict] = None) -> Dict:
        """
        Calculate comprehensive security scores using all algorithms
        
        Args:
            findings: List of finding dictionaries with severity, confidence, etc.
            scan_metadata: Optional metadata about the scan
        
        Returns:
            Comprehensive scoring report
        """
        
        # Run all scorers
        results = {}
        for name, scorer in self.scorers.items():
            results[name] = scorer.calculate(findings)
        
        # Calculate primary metrics
        overall_score = self._calculate_primary_score(findings)
        grade = self._calculate_grade(overall_score)
        recommendations = self._generate_recommendations(findings, results)
        
        # Build comprehensive report
        report = {
            "timestamp": self._get_timestamp(),
            "scan_summary": {
                "total_findings": len(findings),
                "overall_score": overall_score,
                "grade": grade,
                "assessment": self._get_assessment(grade)
            },
            "severity_distribution": self._count_severities(findings),
            "algorithm_results": results,
            "confidence_analysis": self._analyze_confidence(findings),
            "recommendations": recommendations,
            "detailed_breakdown": self._generate_breakdown(findings, results, scan_metadata)
        }
        
        return report
    
    def _calculate_primary_score(self, findings: List[Dict]) -> float:
        """Deduct fixed points for each finding based only on its severity."""
        deductions = sum(
            self.PRIMARY_SEVERITY_DEDUCTIONS.get(
                finding.get("severity", "medium"), 12
            )
            for finding in findings
        )
        return round(max(0.0, min(100.0, 100.0 - deductions)), 1)
    
    def _calculate_grade(self, score: float) -> str:
        """Convert score to letter grade"""
        if score >= 90:
            return "A+"
        elif score >= 85:
            return "A"
        elif score >= 80:
            return "A-"
        elif score >= 75:
            return "B+"
        elif score >= 70:
            return "B"
        elif score >= 65:
            return "B-"
        elif score >= 60:
            return "C+"
        elif score >= 55:
            return "C"
        elif score >= 50:
            return "D"
        else:
            return "F"
    
    def _get_assessment(self, grade: str) -> str:
        """Get textual assessment based on grade"""
        assessments = {
            "A+": "Excellent - Minimal security risk",
            "A": "Very Good - Low security risk",
            "A-": "Good - Low-to-moderate security risk",
            "B+": "Satisfactory - Moderate security risk",
            "B": "Fair - Moderate security risk",
            "B-": "Weak - Moderate-to-high security risk",
            "C+": "Poor - High security risk",
            "C": "Poor - High security risk",
            "D": "Critical - Very high security risk",
            "F": "Failure - Critical security risk"
        }
        return assessments.get(grade, "Unknown")
    
    def _count_severities(self, findings: List[Dict]) -> Dict:
        """Count findings by severity"""
        counts = {
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low": sum(1 for f in findings if f.get("severity") == "low"),
            "info": sum(1 for f in findings if f.get("severity") == "info"),
        }
        counts["total"] = sum(counts.values())
        return counts
    
    def _analyze_confidence(self, findings: List[Dict]) -> Dict:
        """Analyze confidence levels of findings"""
        if not findings:
            return {
                "average": 1.0,
                "high_confidence": 0,
                "medium_confidence": 0,
                "low_confidence": 0
            }
        
        confidences = [f.get("confidence", 0.8) for f in findings]
        
        return {
            "average": round(sum(confidences) / len(confidences), 3),
            "high_confidence": sum(1 for c in confidences if c >= 0.8),
            "medium_confidence": sum(1 for c in confidences if 0.6 <= c < 0.8),
            "low_confidence": sum(1 for c in confidences if c < 0.6),
            "total_findings": len(findings)
        }
    
    def _generate_recommendations(self, findings: List[Dict], results: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        severity_dist = self._count_severities(findings)
        
        if severity_dist["critical"] > 0:
            recommendations.append(
                f"URGENT: Address {severity_dist['critical']} critical vulnerability(ies) immediately"
            )
        
        if severity_dist["high"] > 0:
            recommendations.append(
                f"Priority: Remediate {severity_dist['high']} high-severity finding(s) within days"
            )
        
        if severity_dist["medium"] > 0:
            recommendations.append(
                f"Review {severity_dist['medium']} medium-severity findings for mitigation strategies"
            )
        
        if "entropy" in results and results["entropy"].get("concentration") == "High (concentrated in few files)":
            recommendations.append(
                f"Findings are concentrated - focus on {results['entropy']['files_affected']} file(s)"
            )
        
        if "confidence" in results and results["confidence"]["low_confidence_findings"] > 0:
            recommendations.append(
                f"Manually verify {results['confidence']['low_confidence_findings']} low-confidence findings"
            )
        
        if not recommendations:
            recommendations.append("Continue monitoring - maintain current security posture")
        
        return recommendations
    
    def _generate_breakdown(self, findings: List[Dict], results: Dict, metadata: Optional[Dict]) -> Dict:
        """Generate detailed breakdown for understanding"""
        return {
            "methodology": {
                "primary_score": (
                    "100 minus fixed severity deductions per finding "
                    "(critical 40, high 25, medium 12, low 5, info 1); "
                    "clamped to 0-100. Confidence and context do not affect it."
                ),
                "grade_scale": "A+ (90-100), A (85-89), A- (80-84), B+ (75-79), B (70-74), "
                               "B- (65-69), C+ (60-64), C (55-59), D (50-54), F (<50)",
                "algorithms_used": list(self.scorers.keys()),
            },
            "how_to_read": {
                "overall_score": "Primary metric based only on finding counts and severities",
                "grade": "Letter grade from the primary severity-deduction score",
                "cvss_score": "Max CVSS-like severity (0-10) considering confidence and context",
                "weighted_score": "Score based on severity and confidence weighting",
                "risk_level": "Categorical risk assessment (Critical/High/Medium/Low/Info)",
                "confidence_analysis": "Trust level in the findings"
            },
            "algorithm_explanations": {
                "cvss": "CVSS v3.1-inspired approach: Base scores by severity, adjusted by context",
                "weighted": "Traditional aggregation: Start at 100, deduct points per finding weight",
                "risk_level": "Threshold-based: Risk determined by most severe finding present",
                "confidence": "Confidence-adjusted: High-confidence findings more impactful",
                "entropy": "Distribution analysis: Concentrated risk vs. spread findings"
            }
        }
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
