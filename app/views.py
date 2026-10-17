"""View routes for serving HTML templates"""
from flask import Blueprint, render_template, redirect, session

views_bp = Blueprint('views', __name__)


@views_bp.route('/')
def index():
    """Landing page"""
    return render_template('index.html')


@views_bp.route('/register')
def register():
    """Registration page"""
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('auth/register.html')


@views_bp.route('/login')
def login():
    """Login page"""
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('auth/login.html')


@views_bp.route('/dashboard')
def dashboard():
    """Dashboard page"""
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html')


@views_bp.route('/scan')
def scan():
    """Scan upload page"""
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('scan_upload.html')


@views_bp.route('/history')
def history():
    """Scan history page"""
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('scan_history.html')


@views_bp.route('/scan/<int:scan_id>')
def scan_results(scan_id):
    """Scan results page"""
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('scan_results.html', scan_id=scan_id)


@views_bp.route('/admin')
def admin():
    """Admin dashboard page"""
    if 'user_id' not in session:
        return redirect('/login')
    if session.get('role') != 'admin':
        return redirect('/dashboard')
    return render_template('admin_dashboard.html')


@views_bp.route('/profile')
def profile():
    """User profile and settings page"""
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('profile.html')


@views_bp.route('/api-tokens')
def api_tokens_page():
    """API token management page"""
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('api_tokens.html')
