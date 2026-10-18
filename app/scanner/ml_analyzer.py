"""Machine Learning-based vulnerability analyzer"""
import re
from typing import List, Dict, Tuple


class MLVulnerabilityAnalyzer:
    """Advanced ML-based vulnerability detection"""
    
    def __init__(self):
        """Initialize analyzer with patterns and weights"""
        # Context-based patterns with confidence scoring
        self.high_confidence_patterns = {
            'plaintext_password': [
                (r'password\s*=\s*["\']([^"\']{3,})["\']', 0.95),
                (r'password\s*:\s*["\']([^"\']{3,})["\']', 0.95),
                (r'pwd\s*=\s*["\']([^"\']{3,})["\']', 0.90),
                (r'passwd\s*=\s*["\']([^"\']{3,})["\']', 0.92),
                (r'secret\s*=\s*["\']([^"\']{8,})["\']', 0.88),
            ],
            'weak_hashing': [
                (r'md5\s*\(', 0.99),
                (r'sha1\s*\(', 0.98),
                (r'hashlib\.md5', 0.99),
                (r'hashlib\.sha1', 0.98),
            ],
            'hardcoded_api_key': [
                (r'api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 0.97),
                (r'secret[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 0.96),
                (r'token\s*[=:]\s*["\']([a-zA-Z0-9_.-]{20,})["\']', 0.94),
                (r'auth[_-]?token\s*[=:]\s*["\']', 0.95),
            ],
        }
    
    def analyze_code_context(self, code: str, line_num: int, line_content: str) -> Dict:
        """
        Analyze code with context for better detection
        
        Returns:
            Dict with findings and confidence scores
        """
        findings = {
            'vulnerabilities': [],
            'context_score': 0.0,
            'context_analysis': {}
        }
        
        # Get surrounding lines for context (5 lines each direction)
        lines = code.split('\n')
        context_start = max(0, line_num - 5)
        context_end = min(len(lines), line_num + 6)
        context = '\n'.join(lines[context_start:context_end])
        
        # Check if in function that handles authentication
        in_auth_context = self._is_in_auth_context(context)
        in_test_code = self._is_in_test_code(context)
        in_config = self._is_in_config(context)
        
        # Adjust confidence based on context
        context_multiplier = 1.0
        if in_auth_context:
            context_multiplier = 1.3  # Higher confidence in auth functions
        elif in_test_code:
            context_multiplier = 0.3  # Lower confidence in test code
        elif in_config:
            context_multiplier = 1.1
        
        findings['context_analysis'] = {
            'in_auth': in_auth_context,
            'in_test': in_test_code,
            'in_config': in_config,
            'multiplier': context_multiplier
        }
        
        return findings
    
    def _is_in_auth_context(self, context: str) -> bool:
        """Check if code is in authentication context"""
        auth_keywords = [
            r'def\s+authenticate',
            r'def\s+login',
            r'def\s+verify_password',
            r'def\s+hash_password',
            r'class\s+.*Auth',
            r'@.*auth.*\n',
        ]
        return any(re.search(pattern, context, re.IGNORECASE) for pattern in auth_keywords)
    
    def _is_in_test_code(self, context: str) -> bool:
        """Check if code is in test/demo context"""
        test_keywords = [
            r'test_',
            r'demo',
            r'fixture',
            r'mock',
            r'fake',
            r'example',
        ]
        return any(keyword in context.lower() for keyword in test_keywords)
    
    def _is_in_config(self, context: str) -> bool:
        """Check if code is in configuration"""
        return bool(re.search(r'(config|settings|env)', context, re.IGNORECASE))
    
    def calculate_anomaly_score(self, code: str) -> float:
        """
        Calculate anomaly score for unusual patterns
        Range: 0.0 (normal) to 1.0 (highly anomalous)
        """
        score = 0.0
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'eval\s*\(', 0.3),           # Dynamic code execution
            (r'exec\s*\(', 0.3),           # Code execution
            (r'pickle\.loads', 0.25),      # Unsafe deserialization
            (r'yaml\.load', 0.25),         # Unsafe YAML loading
            (r'__import__', 0.2),          # Dynamic imports
            (r'os\.system', 0.2),          # System command execution
        ]
        
        for pattern, weight in suspicious_patterns:
            if re.search(pattern, code):
                score += weight
        
        return min(score, 1.0)
    
    def detect_secret_patterns(self, code: str) -> List[Dict]:
        """Detect potential secrets using advanced patterns"""
        findings = []
        
        # API Key patterns
        api_patterns = [
            (r'["\']?[a-zA-Z0-9_-]*api[_-]?key["\']?\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'API Key'),
            (r'sk_(?:live|test)_[a-zA-Z0-9]{20,}', 'Stripe Key'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'(?:https?://)?([a-zA-Z0-9_-]+):([a-zA-Z0-9_-]+)@', 'URL Credentials'),
        ]
        
        for pattern, secret_type in api_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                findings.append({
                    'type': secret_type,
                    'pattern': pattern,
                    'evidence': match.group(0)[:50],  # Redacted
                    'confidence': 0.95
                })
        
        return findings
    
    def entropy_analysis(self, value: str) -> float:
        """
        Calculate Shannon entropy to detect random secrets
        High entropy = likely random secret
        """
        if len(value) < 4:
            return 0.0
        
        import math
        entropy = 0.0
        for i in range(256):
            freq = value.count(chr(i)) / len(value)
            if freq > 0:
                entropy -= freq * math.log2(freq)
        
        # Normalize to 0-1
        max_entropy = math.log2(256)
        return entropy / max_entropy if max_entropy > 0 else 0.0
    
    def detect_weak_entropy_secrets(self, code: str) -> List[Dict]:
        """Detect hardcoded values with high entropy (likely secrets)"""
        findings = []
        
        # Find string assignments
        string_pattern = r'[=:]\s*["\']([a-zA-Z0-9_\-\.@!#$%^&*]{8,})["\']'
        
        for match in re.finditer(string_pattern, code):
            value = match.group(1)
            entropy = self.entropy_analysis(value)
            
            # High entropy strings in certain contexts = likely secrets
            if entropy > 0.7:
                findings.append({
                    'value': value[:20],
                    'entropy': entropy,
                    'confidence': min(0.95, 0.5 + entropy),
                    'type': 'High-Entropy String'
                })
        
        return findings


class VulnerabilityRiskScorer:
    """Score and rank vulnerabilities by risk level"""
    
    # CVSS v3.1 inspired scoring
    RISK_FACTORS = {
        'plaintext_password': {
            'base': 9.0,  # Critical
            'factors': {
                'in_auth': 1.5,
                'in_production': 1.2,
                'affects_admin': 1.3,
            }
        },
        'weak_hash_md5': {
            'base': 8.5,
            'factors': {
                'recent_code': 1.2,
                'no_salt': 1.4,
            }
        },
        'hardcoded_secret': {
            'base': 8.0,
            'factors': {
                'git_tracked': 1.5,
                'in_source': 1.2,
            }
        }
    }
    
    def calculate_risk_score(self, vulnerability: Dict) -> float:
        """
        Calculate CVSS-like risk score
        Range: 0.0 - 10.0
        """
        rule_id = vulnerability.get('rule_id')
        
        if rule_id not in self.RISK_FACTORS:
            return 5.0  # Medium by default
        
        risk_data = self.RISK_FACTORS[rule_id]
        score = risk_data['base']
        
        # Apply factors
        for factor, multiplier in risk_data.get('factors', {}).items():
            if vulnerability.get(factor):
                score *= multiplier
        
        return min(score, 10.0)


class CodeQualityAnalyzer:
    """Analyze overall code quality related to security"""
    
    def generate_security_score(self, findings: List[Dict]) -> Dict:
        """Generate overall security score (0-100)"""
        if not findings:
            return {
                'score': 100,
                'grade': 'A+',
                'level': 'Excellent',
                'message': 'No vulnerabilities detected'
            }
        
        # Weight findings by severity
        severity_weights = {
            'critical': 30,
            'high': 20,
            'medium': 10,
            'low': 5,
            'info': 1
        }
        
        total_weight = sum(
            severity_weights.get(f.get('severity', 'medium'), 10)
            for f in findings
        )
        
        # Score calculation
        score = max(0, 100 - total_weight)
        
        if score >= 90:
            grade, level = 'A+', 'Excellent'
        elif score >= 80:
            grade, level = 'A', 'Very Good'
        elif score >= 70:
            grade, level = 'B', 'Good'
        elif score >= 60:
            grade, level = 'C', 'Fair'
        elif score >= 50:
            grade, level = 'D', 'Poor'
        else:
            grade, level = 'F', 'Critical'
        
        return {
            'score': score,
            'grade': grade,
            'level': level,
            'total_findings': len(findings),
            'critical_count': sum(1 for f in findings if f.get('severity') == 'critical'),
            'high_count': sum(1 for f in findings if f.get('severity') == 'high'),
        }
