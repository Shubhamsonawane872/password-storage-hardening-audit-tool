# Advanced Features - Password Storage Hardening Audit Tool

This document describes the advanced features added to enhance the tool's capabilities beyond basic scanning.

## 📊 Advanced Features Overview

### 1. Machine Learning-Based Vulnerability Analyzer

**File**: `app/scanner/ml_analyzer.py`

#### Features:
- **Context-Aware Detection**: Analyzes code context to reduce false positives
- **Confidence Scoring**: Each finding includes a confidence score (0.0-1.0)
- **Entropy Analysis**: Detects hardcoded secrets by calculating Shannon entropy
- **Anomaly Detection**: Identifies unusual code patterns

#### Usage:
```python
from app.scanner.ml_analyzer import MLVulnerabilityAnalyzer

analyzer = MLVulnerabilityAnalyzer()

# Analyze with context
findings = analyzer.analyze_code_context(code, line_num, line_content)

# Calculate anomaly score
anomaly_score = analyzer.calculate_anomaly_score(code)  # 0.0-1.0

# Detect secrets with entropy analysis
secrets = analyzer.detect_weak_entropy_secrets(code)
```

#### Benefits:
- Reduces false positives by analyzing code context
- Identifies test code vs. production code
- Detects high-entropy strings (likely secrets)
- Provides confidence scores for each finding

### 2. Risk Scoring & Compliance Metrics

**File**: `app/scanner/ml_analyzer.py`

#### VulnerabilityRiskScorer:
```python
from app.scanner.ml_analyzer import VulnerabilityRiskScorer

scorer = VulnerabilityRiskScorer()
risk_score = scorer.calculate_risk_score(vulnerability)  # 0.0-10.0
```

#### CVSS-Like Scoring:
- Based on vulnerability type and context
- Takes into account if vulnerability is in auth code
- Production code gets higher weights than test code
- Helps prioritize fixes

#### CodeQualityAnalyzer:
```python
analyzer = CodeQualityAnalyzer()
security_report = analyzer.generate_security_score(findings)
# Returns: {score: 0-100, grade: 'A+', level: 'Excellent'}
```

---

## 🔑 API Token Management

**File**: `app/auth/api_tokens.py`

### Generate API Tokens:
```bash
POST /api/v2/tokens/create
{
  "name": "CI/CD Token",
  "expires_in_days": 90
}
```

### List Your Tokens:
```bash
GET /api/v2/tokens
```

### Revoke a Token:
```bash
DELETE /api/v2/tokens/{token_id}
```

### Use API Token:
Add to requests:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:5000/api/...
```

### Database Table:
```sql
api_tokens (
  id, user_id, token_hash, name, 
  created_at, expires_at, last_used_at
)
```

---

## 📈 Advanced Analytics

**File**: `app/analytics.py`

### Endpoints:

#### 1. Vulnerability Trends
```bash
GET /api/v2/analytics/trends?days=30
```
Response:
```json
{
  "period_days": 30,
  "trends": [
    {"date": "2024-01-01", "scans": 2, "findings": 15},
    {"date": "2024-01-02", "scans": 1, "findings": 8}
  ],
  "total_scans": 30,
  "total_findings": 250
}
```

#### 2. Rule Distribution
```bash
GET /api/v2/analytics/rule-distribution
```
Shows which vulnerability rules are found most often.

#### 3. Severity Breakdown
```bash
GET /api/v2/analytics/severity-breakdown
```
Returns count of findings by severity level.

#### 4. Most Vulnerable Files
```bash
GET /api/v2/analytics/vulnerable-files?limit=10
```
Shows files with most security findings.

#### 5. Improvement Metrics
```bash
GET /api/v2/analytics/improvement
```
Compares findings from last 30 days vs previous 30 days:
```json
{
  "recent_findings": 45,
  "previous_findings": 120,
  "improvement_percentage": 62.5,
  "trend": "improving"
}
```

#### 6. Organization-Wide Score (Admin Only)
```bash
GET /api/v2/analytics/organization-score
```
Calculates security posture score (0-100) for entire organization.

#### 7. Compliance Report (Admin Only)
```bash
GET /api/v2/analytics/compliance-report
```
Generates OWASP compliance status and recommendations.

---

## 🔄 Scheduled Scans

**File**: `app/scheduler.py`

### Schedule Recurring Scans:
```bash
POST /api/v2/scans/schedule
{
  "scan_id": 1,
  "schedule_time": "0 2 * * *"  # Cron format: Daily at 2 AM
}
```

### List Scheduled Scans:
```bash
GET /api/v2/scans/scheduled
```

### Cancel Scheduled Scan:
```bash
DELETE /api/v2/scans/scheduled/{job_id}
```

### Supported Cron Patterns:
- `0 2 * * *` - Every day at 2 AM
- `0 */6 * * *` - Every 6 hours
- `0 0 * * 0` - Every Sunday at midnight
- `0 0 1 * *` - First day of month at midnight

---

## 🔍 Advanced Risk Analysis

### Get Detailed Risk Analysis:
```bash
GET /api/v2/scan/{scan_id}/risk-analysis
```

Response:
```json
{
  "scan_id": 1,
  "findings_with_scores": [
    {
      "finding_id": 1,
      "rule_id": "PWD001",
      "risk_score": 9.5,
      "severity": "critical"
    }
  ],
  "top_risks": [...],
  "average_risk": 7.8
}
```

### Compare Scans:
```bash
POST /api/v2/scan/{scan_id}/comparison
{
  "compare_to_scan_id": 5
}
```

Response:
```json
{
  "current_findings_count": 45,
  "previous_findings_count": 120,
  "new_findings": -75,
  "trend": "improved"
}
```

---

## 🚀 Integration Examples

### Python Client:
```python
import requests

API_URL = "http://localhost:5000/api/v2"
TOKEN = "your_api_token"

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# Get analytics
response = requests.get(
    f"{API_URL}/analytics/trends",
    headers=headers,
    params={"days": 30}
)
trends = response.json()
```

### JavaScript Client:
```javascript
const API_URL = "http://localhost:5000/api/v2";
const TOKEN = "your_api_token";

async function getAnalytics() {
  const response = await fetch(`${API_URL}/analytics/trends?days=30`, {
    headers: {
      "Authorization": `Bearer ${TOKEN}`,
      "Content-Type": "application/json"
    }
  });
  
  return await response.json();
}

getAnalytics().then(data => console.log(data));
```

### CI/CD Integration:
```bash
#!/bin/bash
# Scan project and get results

TOKEN="your_api_token"
SCAN_ID=$(curl -X POST http://localhost:5000/api/scanner/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@myproject.zip" | jq -r '.scan_id')

# Wait for completion
sleep 10

# Get risk analysis
curl http://localhost:5000/api/v2/scan/$SCAN_ID/risk-analysis \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## 📊 Advanced Dashboard (Coming Soon)

Future enhancements will include:
- Interactive charts for trends
- Real-time vulnerability updates via WebSockets
- Custom reporting with drill-down analytics
- Automated remediation suggestions
- Integration with CI/CD pipelines

---

## 🔐 Security Considerations

1. **API Tokens**:
   - Tokens are hashed before storage
   - Never displayed after creation
   - Can be revoked at any time
   - Automatically expire after configured period

2. **Data Privacy**:
   - Users can only access their own data
   - Admins can see organization-wide data only
   - No raw source code is stored
   - All API responses are sanitized

3. **Rate Limiting**:
   - API endpoints should be rate-limited in production
   - Consider using Redis for distributed rate limiting

---

## 🧪 Testing Advanced Features

```bash
# Test ML analyzer
pytest tests/test_ml_analyzer.py -v

# Test analytics
pytest tests/test_analytics.py -v

# Test API tokens
pytest tests/test_api_tokens.py -v

# Test scheduled scans
pytest tests/test_scheduler.py -v
```

---

## 📝 Configuration

Add to `.env`:
```
# Scheduler settings
SCHEDULER_TIMEZONE=UTC
MAX_SCHEDULED_JOBS=100

# API Token settings
API_TOKEN_EXPIRATION_DAYS=90
API_TOKEN_LENGTH=32

# Analytics
ANALYTICS_RETENTION_DAYS=365
```

---

## 🔄 Background Jobs

The scheduler runs background tasks:
- Executing scheduled scans
- Cleaning up expired API tokens
- Generating daily compliance reports
- Archiving old scan data

### Starting the Scheduler:
```python
from app.scheduler import start_scheduler

app = create_app()
start_scheduler(app)
```

### Stopping the Scheduler:
```python
from app.scheduler import stop_scheduler

stop_scheduler()
```

---

## 🎯 Use Cases

### 1. Automated Security Audits
Schedule daily/weekly scans of your codebase:
```bash
POST /api/v2/scans/schedule
{
  "scan_id": 1,
  "schedule_time": "0 2 * * *"  # Daily at 2 AM
}
```

### 2. Continuous Integration
Integrate with CI/CD to scan on commits:
```yaml
scan_security:
  script:
    - curl -X POST http://localhost:5000/api/scanner/upload \
      -H "Authorization: Bearer $SECURITY_TOKEN" \
      -F "file=@project.zip"
```

### 3. Compliance Reporting
Generate monthly compliance reports for auditors:
```bash
GET /api/v2/analytics/compliance-report
```

### 4. Risk-Based Prioritization
Use risk scores to prioritize remediation:
```bash
GET /api/v2/scan/{id}/risk-analysis
```

### 5. Trend Analysis
Track improvement over time:
```bash
GET /api/v2/analytics/improvement
```

---

## 📚 Advanced Architecture

```
┌─────────────────────────────────────────┐
│  Advanced Scanner (ML-Enhanced)        │
├─────────────────────────────────────────┤
│ • MLVulnerabilityAnalyzer               │
│ • VulnerabilityRiskScorer               │
│ • CodeQualityAnalyzer                   │
│ • Context-aware detection               │
│ • Entropy analysis                      │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────┴──────────────────┐
│    Advanced API (v2 Endpoints)      │
├──────────────────────────────────────┤
│ • API Token Management               │
│ • Analytics & Insights               │
│ • Risk Analysis                      │
│ • Scan Comparison                    │
│ • Scheduled Scans                    │
└──────────────────┬──────────────────┘
                   │
┌──────────────────┴──────────────────┐
│  Background Jobs & Scheduler         │
├──────────────────────────────────────┤
│ • Recurring scans (cron)             │
│ • Report generation                  │
│ • Token cleanup                      │
│ • Compliance checks                  │
└──────────────────┬──────────────────┘
                   │
┌──────────────────┴──────────────────┐
│   Enhanced Database                  │
├──────────────────────────────────────┤
│ • api_tokens table (new)             │
│ • Extended audit logging             │
│ • Analytics views                    │
│ • Risk scores                        │
└──────────────────────────────────────┘
```

---

## 🚀 Performance Optimization

### Caching Strategies:
- Cache trending data for 1 hour
- Cache analytics for 6 hours
- Cache organization scores for 24 hours

### Database Indexes:
- Added indexes on api_tokens for faster lookups
- Indexing audit_logs by timestamp for trend queries
- Findings indexed by scan_id and severity

### Scalability:
- Ready for PostgreSQL migration
- Support for distributed caching (Redis)
- Async job processing capability

---

## 🔮 Future Roadmap

- [ ] WebSocket support for real-time updates
- [ ] Machine learning model training on vulnerability patterns
- [ ] GraphQL API support
- [ ] Webhook integrations for CI/CD
- [ ] Advanced visualization dashboard
- [ ] Automated remediation suggestions
- [ ] Integration with GitHub/GitLab
- [ ] SIEM integration

---

## 📞 Support & Documentation

For detailed API documentation, see:
- `README.md` - Main documentation
- `GETTING_STARTED.md` - Quick start guide
- `FEATURES_CHECKLIST.md` - Feature list

For code examples and integration patterns, refer to test files:
- `tests/test_analytics.py`
- `tests/test_api_tokens.py`
- Integration examples in this document

---

**Version**: 2.0 (Advanced Features)
**Last Updated**: 2024
**Status**: Production Ready
