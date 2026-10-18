"""Report generation and export routes"""
from flask import Blueprint, session, jsonify, current_app, send_file
from app.auth.decorators import login_required
from app.db import get_db_connection
from app.reports.generators import ReportGenerator
import io
from datetime import datetime

reports_bp = Blueprint('reports', __name__, url_prefix='/api/reports')


@reports_bp.route('/scan/<int:scan_id>/json', methods=['GET'])
@login_required
def export_json(scan_id):
    """Export scan as JSON"""
    user_id = session.get('user_id')
    
    db = get_db_connection(current_app.config['DATABASE_PATH'])
    cursor = db.cursor()
    
    # Verify ownership
    cursor.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id))
    scan = cursor.fetchone()
    
    if not scan:
        db.close()
        return jsonify({'error': 'Scan not found'}), 404
    
    # Fetch findings
    cursor.execute('SELECT * FROM findings WHERE scan_id = ? ORDER BY severity DESC', (scan_id,))
    findings = [dict(row) for row in cursor.fetchall()]
    
    db.close()
    
    # Generate JSON
    json_report = ReportGenerator.generate_json(dict(scan), findings)
    
    # Create response
    response = send_file(
        io.BytesIO(json_report.encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name=f'audit_report_{scan_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    )
    
    return response


@reports_bp.route('/scan/<int:scan_id>/html', methods=['GET'])
@login_required
def export_html(scan_id):
    """Export scan as HTML"""
    user_id = session.get('user_id')
    
    db = get_db_connection(current_app.config['DATABASE_PATH'])
    cursor = db.cursor()
    
    # Verify ownership
    cursor.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id))
    scan = cursor.fetchone()
    
    if not scan:
        db.close()
        return jsonify({'error': 'Scan not found'}), 404
    
    # Fetch findings
    cursor.execute('SELECT * FROM findings WHERE scan_id = ? ORDER BY severity DESC', (scan_id,))
    findings = [dict(row) for row in cursor.fetchall()]
    
    db.close()
    
    # Generate HTML
    html_report = ReportGenerator.generate_html(dict(scan), findings)
    
    # Create response
    response = send_file(
        io.BytesIO(html_report.encode()),
        mimetype='text/html',
        as_attachment=True,
        download_name=f'audit_report_{scan_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
    )
    
    return response


@reports_bp.route('/scan/<int:scan_id>/csv', methods=['GET'])
@login_required
def export_csv(scan_id):
    """Export findings as CSV"""
    user_id = session.get('user_id')
    
    db = get_db_connection(current_app.config['DATABASE_PATH'])
    cursor = db.cursor()
    
    # Verify ownership
    cursor.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id))
    scan = cursor.fetchone()
    
    if not scan:
        db.close()
        return jsonify({'error': 'Scan not found'}), 404
    
    # Fetch findings
    cursor.execute('SELECT * FROM findings WHERE scan_id = ? ORDER BY severity DESC', (scan_id,))
    findings = [dict(row) for row in cursor.fetchall()]
    
    db.close()
    
    # Generate CSV
    csv_report = ReportGenerator.generate_csv(findings, dict(scan))
    
    # Create response
    response = send_file(
        io.BytesIO(csv_report.encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'audit_report_{scan_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )
    
    return response
