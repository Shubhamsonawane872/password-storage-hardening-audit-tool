"""Report generators for JSON, HTML, and CSV formats"""
import json
import csv
import io
from html import escape
from datetime import datetime


class ReportGenerator:
    """Generate reports in different formats"""
    
    @staticmethod
    def generate_json(scan, findings):
        """Generate JSON report"""
        report = {
            'scan_info': {
                'scan_id': scan['id'],
                'filename': scan['original_filename'],
                'status': scan['scan_status'],
                'created_at': scan['created_at'],
                'completed_at': scan['completed_at'],
                'total_files_scanned': scan['total_files_scanned'],
                'total_findings': scan['total_findings'],
                'security_score': scan.get('security_score'),
                'security_grade': scan.get('security_grade'),
                'severity_breakdown': {
                    'critical': scan['critical_count'],
                    'high': scan['high_count'],
                    'medium': scan['medium_count'],
                    'low': scan['low_count'],
                    'info': scan['info_count']
                }
            },
            'findings': [
                {
                    'rule_id': f['rule_id'],
                    'title': f['rule_title'],
                    'severity': f['severity'],
                    'file': f['file_name'],
                    'line': f['line_number'],
                    'evidence': f['evidence'],
                    'description': f['description'],
                    'recommendation': f['recommendation']
                }
                for f in findings
            ]
        }
        return json.dumps(report, indent=2)
    
    @staticmethod
    def generate_html(scan, findings):
        """Generate HTML report"""
        severity_colors = {
            'critical': '#d32f2f',
            'high': '#f57c00',
            'medium': '#fbc02d',
            'low': '#689f38',
            'info': '#0288d1'
        }
        
        # Group findings by severity
        findings_by_severity = {}
        for finding in findings:
            sev = finding['severity']
            if sev not in findings_by_severity:
                findings_by_severity[sev] = []
            findings_by_severity[sev].append(finding)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Audit Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 28px;
        }}
        .scan-info {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .scan-info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }}
        .info-item {{
            border-left: 4px solid #667eea;
            padding-left: 15px;
        }}
        .info-label {{
            font-size: 12px;
            color: #999;
            text-transform: uppercase;
            font-weight: 600;
        }}
        .info-value {{
            font-size: 20px;
            font-weight: bold;
            margin-top: 5px;
        }}
        .severity-stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
        }}
        .severity-stat {{
            text-align: center;
            padding: 15px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
        }}
        .stat-critical {{ background: #d32f2f; }}
        .stat-high {{ background: #f57c00; }}
        .stat-medium {{ background: #fbc02d; color: #333; }}
        .stat-low {{ background: #689f38; }}
        .stat-info {{ background: #0288d1; }}
        .findings-section {{
            margin-bottom: 30px;
        }}
        .findings-section h2 {{
            font-size: 20px;
            margin-bottom: 15px;
            color: #333;
        }}
        .finding {{
            background: white;
            border-left: 4px solid;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .finding-critical {{ border-left-color: #d32f2f; }}
        .finding-high {{ border-left-color: #f57c00; }}
        .finding-medium {{ border-left-color: #fbc02d; }}
        .finding-low {{ border-left-color: #689f38; }}
        .finding-info {{ border-left-color: #0288d1; }}
        .finding-title {{
            font-weight: bold;
            font-size: 16px;
            margin-bottom: 8px;
        }}
        .finding-meta {{
            font-size: 12px;
            color: #666;
            margin-bottom: 10px;
        }}
        .finding-description {{
            margin: 10px 0;
            line-height: 1.6;
        }}
        .evidence {{
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            overflow-x: auto;
            margin: 10px 0;
        }}
        .recommendation {{
            background: #e8f5e9;
            padding: 10px;
            border-left: 3px solid #4caf50;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 12px;
            border-top: 1px solid #eee;
            margin-top: 30px;
        }}
        @media print {{
            body {{ background: white; }}
            .header {{ page-break-after: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Password Storage Audit Report</h1>
        <p>Static source code analysis for password storage vulnerabilities</p>
    </div>
    
    <div class="scan-info">
        <div class="scan-info-grid">
            <div class="info-item">
                <div class="info-label">Filename</div>
                <div class="info-value">{escape(str(scan['original_filename'] or ''))}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Scan Date</div>
                <div class="info-value">{scan['created_at']}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Files Scanned</div>
                <div class="info-value">{scan['total_files_scanned']}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Total Findings</div>
                <div class="info-value">{scan['total_findings']}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Security Score / Grade</div>
                <div class="info-value">{scan.get('security_score', '—')} / 100 · {escape(str(scan.get('security_grade') or '—'))}</div>
            </div>
        </div>
        
        <h3 style="margin-top: 20px; margin-bottom: 15px;">Severity Breakdown</h3>
        <div class="severity-stats">
            <div class="severity-stat stat-critical">
                Critical: {scan['critical_count']}
            </div>
            <div class="severity-stat stat-high">
                High: {scan['high_count']}
            </div>
            <div class="severity-stat stat-medium">
                Medium: {scan['medium_count']}
            </div>
            <div class="severity-stat stat-low">
                Low: {scan['low_count']}
            </div>
        </div>
    </div>
"""
        
        # Add findings by severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        for severity in severity_order:
            if severity not in findings_by_severity:
                continue
            
            section_findings = findings_by_severity[severity]
            html += f"""
    <div class="findings-section">
        <h2 style="color: {severity_colors.get(severity, '#333')};">
            {severity.upper()} SEVERITY ({len(section_findings)})
        </h2>
"""
            
            for finding in section_findings:
                html += f"""
        <div class="finding finding-{severity}">
                <div class="finding-title">{escape(str(finding['rule_id']))}: {escape(str(finding['rule_title']))}</div>
            <div class="finding-meta">
                File: <strong>{escape(str(finding['file_name'] or ''))}</strong> |
                Line: <strong>{escape(str(finding['line_number'] or ''))}</strong>
            </div>
            <div class="finding-description">{escape(str(finding['description'] or ''))}</div>
            <div class="evidence"><strong>Evidence:</strong><br>{escape(str(finding['evidence'] or ''))}</div>
            <div class="recommendation"><strong>Recommendation:</strong><br>{escape(str(finding['recommendation'] or ''))}</div>
        </div>
"""
            
            html += """
    </div>
"""
        
        html += """
    <div class="footer">
        <p>This report was generated by the Password Storage Hardening Audit Tool.</p>
        <p>Static code analysis can produce false positives and false negatives. 
           Always review findings with manual code inspection and security testing.</p>
    </div>
</body>
</html>
"""
        return html
    
    @staticmethod
    def generate_csv(findings, scan=None):
        """Generate CSV report"""
        output = io.StringIO()
        writer = csv.writer(output)
        score = scan.get('security_score') if scan else ''
        grade = scan.get('security_grade') if scan else ''
        writer.writerow(['Security Score', 'Security Grade', 'Rule ID', 'Title', 'Severity', 'File', 'Line', 'Evidence', 'Description', 'Recommendation'])
        if not findings:
            writer.writerow([score, grade, '', '', '', '', '', '', '', ''])
        for finding in findings:
            writer.writerow([score, grade, *[finding.get(key, '') for key in (
                'rule_id', 'rule_title', 'severity', 'file_name', 'line_number',
                'evidence', 'description', 'recommendation')]])
        return output.getvalue()
