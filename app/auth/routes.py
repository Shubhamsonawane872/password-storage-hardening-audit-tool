"""Authentication routes (login, register, logout)"""
from flask import Blueprint, request, session, jsonify, current_app
from app.db import get_db_connection
from app.auth.utils import (
    hash_password, verify_password, validate_email, 
    validate_password, validate_name
)
import time
from datetime import datetime

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    data = request.get_json() or {}
    
    # Validate input
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    
    # Client-side validation should happen, but also validate server-side
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    
    is_valid, message = validate_name(name)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400
    
    is_valid, message = validate_password(password)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    # Check if email already exists
    db = get_db_connection(current_app.config['DATABASE_PATH'])
    cursor = db.cursor()
    
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    if cursor.fetchone():
        db.close()
        return jsonify({'error': 'Email already registered'}), 409
    
    # Hash password and create user
    password_hash = hash_password(password)
    
    try:
        cursor.execute('''
            INSERT INTO users (name, email, password_hash, role)
            VALUES (?, ?, ?, 'user')
        ''', (name, email, password_hash))
        db.commit()
        
        # Log the registration
        user_id = cursor.lastrowid
        cursor.execute('''
            INSERT INTO audit_logs (user_id, action, resource_type, resource_id, status)
            VALUES (?, 'register', 'user', ?, 'success')
        ''', (user_id, user_id))
        db.commit()
        
        db.close()
        return jsonify({'message': 'Registration successful. Please log in.'}), 201
    
    except Exception as e:
        db.rollback()
        db.close()
        return jsonify({'error': 'Registration failed'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json() or {}
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    db = get_db_connection(current_app.config['DATABASE_PATH'])
    cursor = db.cursor()
    
    # Check rate limiting
    client_ip = request.remote_addr
    rate_limit_key = f'login_attempt:{client_ip}'
    
    cursor.execute('''
        SELECT COUNT(*) as attempt_count
        FROM audit_logs
        WHERE ip_address = ? 
        AND action = 'login_failed'
        AND timestamp > datetime('now', '-5 minutes')
    ''', (client_ip,))
    
    result = cursor.fetchone()
    attempt_count = result['attempt_count'] if result else 0
    
    if attempt_count >= current_app.config['LOGIN_RATE_LIMIT_ATTEMPTS']:
        db.close()
        return jsonify({'error': 'Too many login attempts. Please try again later.'}), 429
    
    # Fetch user
    cursor.execute('''
        SELECT id, name, email, password_hash, role, is_active
        FROM users WHERE email = ?
    ''', (email,))
    
    user = cursor.fetchone()
    
    # Verify credentials
    if user and user['is_active'] and verify_password(user['password_hash'], password):
        # Successful login
        session['user_id'] = user['id']
        session['name'] = user['name']
        session['email'] = user['email']
        session['role'] = user['role']
        
        cursor.execute('''
            INSERT INTO audit_logs (user_id, action, resource_type, ip_address, status)
            VALUES (?, 'login', 'user', ?, 'success')
        ''', (user['id'], client_ip))
        db.commit()
        db.close()
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role']
            }
        }), 200
    
    else:
        # Failed login
        cursor.execute('''
            INSERT INTO audit_logs (action, resource_type, ip_address, status)
            VALUES ('login_failed', 'user', ?, 'failure')
        ''', (client_ip,))
        db.commit()
        db.close()
        
        # Generic error message to prevent account enumeration
        return jsonify({'error': 'Invalid email or password'}), 401


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """User logout endpoint"""
    user_id = session.get('user_id')
    
    if user_id:
        db = get_db_connection(current_app.config['DATABASE_PATH'])
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO audit_logs (user_id, action, resource_type, status)
            VALUES (?, 'logout', 'user', 'success')
        ''', (user_id,))
        db.commit()
        db.close()
    
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200


@auth_bp.route('/me', methods=['GET'])
def get_current_user():
    """Get current logged-in user information"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    return jsonify({
        'user': {
            'id': session.get('user_id'),
            'name': session.get('name'),
            'email': session.get('email'),
            'role': session.get('role')
        }
    }), 200
