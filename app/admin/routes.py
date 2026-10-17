"""Admin routes for user management and audit logs"""
from flask import Blueprint, session, jsonify, request, current_app
from app.auth.decorators import admin_required, login_required
from app.db import get_db_connection

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


@admin_bp.route('/users', methods=['GET'])
@admin_required
def list_users():
    """List all users (admin only)"""
    db = get_db_connection(current_app.config['DATABASE_PATH'])
    cursor = db.cursor()
    
    cursor.execute('''
        SELECT id, name, email, role, is_active, created_at
        FROM users
        ORDER BY created_at DESC
    ''')
    
    users = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    return jsonify({'users': users}), 200


@admin_bp.route('/user/<int:user_id>/deactivate', methods=['POST'])
@admin_required
def deactivate_user(user_id):
    """Deactivate a user (admin only)"""
    admin_id = session.get('user_id')
    
    # Prevent self-deactivation
    if admin_id == user_id:
        return jsonify({'error': 'Cannot deactivate yourself'}), 400
    
    db = get_db_connection(current_app.config['DATABASE_PATH'])
    cursor = db.cursor()
    
    # Check if user exists
    cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,))
    if not cursor.fetchone():
        db.close()
        return jsonify({'error': 'User not found'}), 404
    
    cursor.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
    db.commit()
    
    # Log audit
    cursor.execute('''
        INSERT INTO audit_logs (user_id, action, resource_type, resource_id, status)
        VALUES (?, 'user_deactivated', 'user', ?, 'success')
    ''', (admin_id, user_id))
    db.commit()
    db.close()
    
    return jsonify({'message': 'User deactivated'}), 200


@admin_bp.route('/user/<int:user_id>/activate', methods=['POST'])
@admin_required
def activate_user(user_id):
    """Activate a user (admin only)"""
    admin_id = session.get('user_id')
    
    db = get_db_connection(current_app.config['DATABASE_PATH'])
    cursor = db.cursor()
    
    # Check if user exists
    cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,))
    if not cursor.fetchone():
        db.close()
        return jsonify({'error': 'User not found'}), 404
    
    cursor.execute('UPDATE users SET is_active = 1 WHERE id = ?', (user_id,))
    db.commit()
    
    # Log audit
    cursor.execute('''
        INSERT INTO audit_logs (user_id, action, resource_type, resource_id, status)
        VALUES (?, 'user_activated', 'user', ?, 'success')
    ''', (admin_id, user_id))
    db.commit()
    db.close()
    
    return jsonify({'message': 'User activated'}), 200


@admin_bp.route('/audit-logs', methods=['GET'])
@admin_required
def get_audit_logs():
    """Get audit logs (admin only)"""
    db = get_db_connection(current_app.config['DATABASE_PATH'])
    cursor = db.cursor()
    
    # Get query parameters for pagination
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    
    cursor.execute('''
        SELECT id, user_id, action, resource_type, resource_id, 
               ip_address, status, timestamp
        FROM audit_logs
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    ''', (limit, offset))
    
    logs = [dict(row) for row in cursor.fetchall()]
    
    # Get total count
    cursor.execute('SELECT COUNT(*) as total FROM audit_logs')
    total = cursor.fetchone()['total']
    
    db.close()
    
    return jsonify({
        'logs': logs,
        'total': total,
        'limit': limit,
        'offset': offset
    }), 200


@admin_bp.route('/stats', methods=['GET'])
@admin_required
def get_admin_stats():
    """Get admin statistics"""
    db = get_db_connection(current_app.config['DATABASE_PATH'])
    cursor = db.cursor()
    
    # Total users
    cursor.execute('SELECT COUNT(*) as count FROM users')
    total_users = cursor.fetchone()['count']
    
    # Active users
    cursor.execute('SELECT COUNT(*) as count FROM users WHERE is_active = 1')
    active_users = cursor.fetchone()['count']
    
    # Total scans
    cursor.execute('SELECT COUNT(*) as count FROM scans')
    total_scans = cursor.fetchone()['count']
    
    # Total findings
    cursor.execute('SELECT COUNT(*) as count FROM findings')
    total_findings = cursor.fetchone()['count']
    
    # Recent activity (past 24 hours)
    cursor.execute('''
        SELECT COUNT(*) as count FROM audit_logs 
        WHERE timestamp > datetime('now', '-24 hours')
    ''')
    recent_activity = cursor.fetchone()['count']
    
    db.close()
    
    return jsonify({
        'stats': {
            'total_users': total_users,
            'active_users': active_users,
            'total_scans': total_scans,
            'total_findings': total_findings,
            'recent_activity_24h': recent_activity
        }
    }), 200
