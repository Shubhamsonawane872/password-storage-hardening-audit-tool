# Password Storage Hardening Audit Tool for Web Applications

A complete, functional web application for auditing source code to identify insecure password storage practices and provide actionable recommendations.

## Features

✅ **Complete End-to-End Application**
- Full-stack implementation: Frontend (HTML/CSS/JS), Backend (Flask/Python), Database (SQLite)
- User authentication with secure password hashing (Argon2id)
- Role-based access control (User and Admin roles)
- Comprehensive security controls

✅ **Static Source Code Analysis**
- Detects plaintext password storage
- Identifies weak hashing algorithms (MD5, SHA1)
- Finds hardcoded passwords and API keys
- Detects unsalted password hashing
- Recognizes modern password hashing practices (Argon2id, bcrypt, scrypt)
- Supports Python, JavaScript, Java, and PHP
- ZIP archive support with path traversal protection

Scan results come from static checks against the submitted source; uploaded code is never executed. Each finding points to the matched file and line, and uploads with no readable supported source files are rejected rather than presented as clean scans. Static pattern checks are indicators for review, not proof of runtime exploitability.

✅ **Vulnerability Rules**
- PWD001: Plaintext password storage (Critical)
- PWD002: MD5 hashing (High)
- PWD003: SHA1 hashing (High)
- PWD004: Hardcoded secrets (High)
- PWD005: Unsalted hashing (High)
- PWD006: Weak password patterns (Medium)
- PWD007: Modern hashing detected (Info)

✅ **Reports & Exports**
- JSON export for integration
- HTML reports with formatting
- CSV export for spreadsheets
- Detailed findings with recommendations

✅ **Admin Features**
- User management
- User activation/deactivation
- Audit logging
- System statistics

## Technology Stack

- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Backend**: Flask 2.3.3 (Python web framework)
- **Database**: SQLite 3
- **Password Hashing**: Argon2id (via argon2-cffi)
- **Testing**: pytest
- **Security**: Login attempt throttling, secure cookie flags, input validation

## Project Structure

```
password-storage-audit/
├── app/                           # Flask application
│   ├── __init__.py               # App factory
│   ├── config.py                 # Configuration
│   ├── db.py                     # Database initialization
│   ├── views.py                  # View routes
│   ├── auth/                     # Authentication module
│   │   ├── routes.py             # Login/register/logout
│   │   ├── utils.py              # Password hashing, validation
│   │   └── decorators.py         # Auth decorators
│   ├── dashboard/                # Dashboard module
│   │   └── routes.py             # Dashboard stats
│   ├── scanner/                  # Scanner module
│   │   ├── routes.py             # Upload, scan endpoints
│   │   ├── patterns.py           # Detection patterns
│   │   ├── rules.py              # Rule definitions
│   │   └── file_handler.py       # ZIP validation
│   ├── reports/                  # Reports module
│   │   ├── routes.py             # Export endpoints
│   │   └── generators.py         # JSON/HTML/CSV generators
│   ├── admin/                    # Admin module
│   │   └── routes.py             # User management
│   ├── templates/                # HTML templates
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── dashboard.html
│   │   ├── scan_upload.html
│   │   ├── scan_results.html
│   │   ├── scan_history.html
│   │   ├── admin_dashboard.html
│   │   └── auth/
│   │       ├── login.html
│   │       └── register.html
│   └── static/
│       ├── css/
│       │   ├── style.css         # Main styles
│       │   └── responsive.css    # Mobile styles
│       └── js/
│           └── utils.js          # JavaScript utilities
├── tests/                         # Test suite
│   ├── conftest.py               # Pytest fixtures
│   ├── test_auth.py              # Auth tests
│   ├── test_scanner_patterns.py  # Scanner tests
│   ├── test_security.py          # Security tests
│   └── ...
├── sample_apps/                  # Sample vulnerable code
│   ├── vulnerable_sample.py      # Python vulnerable code
│   ├── safer_sample.py           # Python secure code
│   ├── vulnerable_sample.js      # JavaScript vulnerable code
│   └── vulnerable_sample.php     # PHP vulnerable code
├── instance/                     # Instance-specific (created at runtime)
│   └── password_audit.db         # SQLite database
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment template
├── .gitignore                    # Git ignore rules
├── init_db.py                    # Database initialization
├── seed_demo.py                  # Demo data seeding
├── run.py                        # Application entry point
└── README.md                     # This file
```

## Setup Instructions (Windows PowerShell)

### 1. Prerequisites

Ensure you have Python 3.10+ installed. Download from: https://www.python.org/downloads/

Verify installation:
```powershell
python --version
```

### 2. Create Virtual Environment

```powershell
cd "c:\Users\Om Sai Ram\Desktop\Password-Audit"
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 4. Set Up Environment Variables

Copy the example environment file:
```powershell
Copy-Item .env.example .env
```

Edit `.env` and update if needed:
```
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DATABASE_PATH=instance/password_audit.db
```

### 5. Initialize Database

```powershell
python init_db.py
```

### 6. (Optional) Seed Demo Data

```powershell
python seed_demo.py
```

This creates demo users:
- Email: `demo@example.com` | Password: `DemoPass123!` | Role: user
- Email: `admin@example.com` | Password: `AdminPass123!` | Role: admin

### 7. Run the Application

```powershell
python run.py
```

The application will start on `http://127.0.0.1:5000`

### 8. Create Initial Admin (if not using demo data)

You can manually create an admin in `app/__init__.py` or use the database directly:

```powershell
python
>>> from app.auth.utils import hash_password
>>> hash_password("YourAdminPass123!")
```

Then insert into the database.

## Usage

### Register & Login

1. Visit http://127.0.0.1:5000
2. Click "Get Started" and create an account
3. Log in with your credentials

### Scan Your Code

1. Go to Dashboard → "Start New Scan"
2. Upload a Python, JavaScript, Java, or PHP file
3. Or upload a ZIP archive containing multiple files
4. Wait for the scan to complete

### Review Results

1. View findings with severity levels
2. Read descriptions and recommendations
3. Export reports (JSON, HTML, CSV)
4. View previous scans in "Scan History"

### Admin Features (if admin user)

1. Click "Admin" in navigation
2. View all users and system statistics
3. Deactivate/activate users
4. View audit logs

## Running Tests

Run the test suite:

```powershell
cd "c:\Users\Om Sai Ram\Desktop\Password-Audit"
.\venv\Scripts\Activate.ps1
pytest tests/ -v
```

Run specific test file:
```powershell
pytest tests/test_auth.py -v
```

Run with coverage:
```powershell
pytest tests/ --cov=app
```

## Security Features Implemented

✅ **Authentication & Authorization**
- Argon2id password hashing (OWASP recommended)
- Secure session management with HttpOnly cookies
- Rate limiting on login attempts (5 attempts per 5 minutes)
- Role-based access control (RBAC)

✅ **Input Validation**
- Server-side validation on all inputs
- Email format validation
- Password policy enforcement (8+ chars, uppercase, lowercase, digit, special char)
- File type whitelist (.py, .js, .java, .php, .zip)

✅ **File Upload Security**
- File size limits (10MB individual, 50MB ZIP)
- ZIP-slip attack prevention (path traversal protection)
- Temporary file extraction (not in public folder)
- Malformed archive detection
- Uploaded files deleted after scan

✅ **Data Protection**
- Parameterized SQL queries (SQL injection prevention)
- Output escaping (XSS prevention)
- Safe file handling
- No plaintext password storage
- No raw source code retention

✅ **Audit & Logging**
- All authentication events logged
- Scan history with timestamps
- Admin action tracking
- IP address logging for security events
- Status tracking (success/failure)

✅ **Session Security**
- HttpOnly cookies (JavaScript cannot access)
- SameSite=Lax cookie attribute (this is a browser cookie policy and does not provide CSRF token validation)
- Secure flag for HTTPS (configurable)
- Session timeout (1 hour default)

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user info

### Dashboard
- `GET /api/dashboard/stats` - Get dashboard statistics

### Scanner
- `POST /api/scanner/upload` - Upload and scan file
- `GET /api/scanner/scan/<id>` - Get scan details
- `GET /api/scanner/scans` - List user's scans
- `DELETE /api/scanner/scan/<id>` - Delete scan

### Reports
- `GET /api/reports/scan/<id>/json` - Export JSON
- `GET /api/reports/scan/<id>/html` - Export HTML
- `GET /api/reports/scan/<id>/csv` - Export CSV

### Admin
- `GET /api/admin/users` - List all users
- `POST /api/admin/user/<id>/activate` - Activate user
- `POST /api/admin/user/<id>/deactivate` - Deactivate user
- `GET /api/admin/audit-logs` - Get audit logs
- `GET /api/admin/stats` - Get admin statistics

## Sample Vulnerable Code

The `sample_apps/` directory contains intentionally vulnerable code for testing:

- `vulnerable_sample.py` - Plaintext passwords, MD5/SHA1 hashing, hardcoded secrets
- `vulnerable_sample.js` - JavaScript password storage vulnerabilities
- `vulnerable_sample.php` - PHP password storage vulnerabilities
- `safer_sample.py` - Examples of secure password hashing with Argon2id, bcrypt, scrypt

Use these to test the scanner!

## Troubleshooting

### "ModuleNotFoundError: No module named 'flask'"
Solution: Ensure virtual environment is activated and dependencies installed:
```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### "Database is locked"
Solution: Close other connections and retry. SQLite has limited concurrency.

### Port 5000 already in use
Solution: Change port in `run.py`:
```python
app.run(debug=True, host='127.0.0.1', port=5001)
```

### Static files not loading
Solution: Ensure you're running from the project root directory:
```powershell
cd "c:\Users\Om Sai Ram\Desktop\Password-Audit"
python run.py
```

## Important Security Notes

1. **Development Only**: Flask's development server is NOT suitable for production. Use gunicorn or similar for deployment.

2. **HTTPS Required**: In production, enable `SESSION_COOKIE_SECURE=True` and configure HTTPS.

3. **Secret Key**: Change `SECRET_KEY` in production to a strong random value.

4. **Static Analysis Limitations**: 
   - Scanner uses pattern matching and can produce false positives/negatives
   - Always conduct manual code review
   - Use dynamic testing and penetration testing for comprehensive security assessment
   - Do not rely solely on this tool for security validation

5. **Database Backups**: For production use, implement regular database backups.

6. **Rate Limiting**: The built-in rate limiting is basic. Consider using Flask-Limiter or similar for production.

## Limitations & Future Improvements

- Static analysis only (no dynamic execution)
- Single-node database (use PostgreSQL for multi-node)
- Basic file upload limits (implement S3/cloud storage for scalability)
- No LDAP/OAuth integration
- No API key authentication
- Limited to 5 minutes of rate limiting window

## Testing Coverage

The test suite includes:
- ✅ User registration and validation
- ✅ Login with rate limiting
- ✅ Password hashing and verification
- ✅ Scanner pattern detection
- ✅ File upload restrictions
- ✅ Authorization checks
- Login throttling (5 failed attempts per client IP in a five-minute window)
- ✅ Ownership verification (IDOR prevention)

Run all tests:
```powershell
pytest tests/ -v --cov=app
```

## Architecture Overview

```
┌─────────────────────────────────────┐
│     User Browser (HTML/CSS/JS)      │
│  - Landing, Auth, Dashboard, Scan   │
└──────────────────┬──────────────────┘
                   │ HTTP/HTTPS
                   ▼
┌─────────────────────────────────────┐
│      Flask Backend (Python)         │
│  ┌─────────────────────────────┐    │
│  │ Blueprints:                 │    │
│  │ - Auth (register, login)    │    │
│  │ - Dashboard (stats)         │    │
│  │ - Scanner (upload, scan)    │    │
│  │ - Reports (export)          │    │
│  │ - Admin (users, logs)       │    │
│  └─────────────────────────────┘    │
│  ┌─────────────────────────────┐    │
│  │ Security:                   │    │
│  │ - Argon2id hashing          │    │
│  │ - Rate limiting             │    │
│  │ - SameSite cookie policy    │    │
│  │ - Input validation          │    │
│  └─────────────────────────────┘    │
│  ┌─────────────────────────────┐    │
│  │ Scanner:                    │    │
│  │ - Pattern matching          │    │
│  │ - Rule engine (PWD001-007)  │    │
│  │ - File handling             │    │
│  │ - ZIP extraction (safe)     │    │
│  └─────────────────────────────┘    │
└──────────────────┬──────────────────┘
                   │ SQL
                   ▼
        ┌──────────────────────┐
        │   SQLite Database    │
        │  - users             │
        │  - scans             │
        │  - findings          │
        │  - audit_logs        │
        └──────────────────────┘
```

## For Your College Project Presentation

**Project Title**: "Password Storage Hardening Audit Tool for Web Applications"

**What It Does**:
- Analyzes source code to find password storage vulnerabilities
- Detects plaintext passwords, weak hashing (MD5/SHA1), hardcoded secrets
- Provides actionable recommendations for remediation
- Includes secure authentication, role-based access control, and audit logging

**Key Technologies**:
- Flask (Python web framework) with modular blueprint architecture
- SQLite database with proper schema design
- Argon2id password hashing (OWASP recommended)
- Static code analysis using regex patterns and Python AST for Python files
- Login throttling, ownership checks, and input validation

**Why It's Secure**:
- Passwords hashed with Argon2id, never stored plaintext
- Server-side validation on all inputs
- Protected file uploads with ZIP-slip attack prevention
- Audit logging for all security events
- Role-based access control with ownership verification

**What I Learned**:
- Full-stack web development (frontend to database)
- Secure authentication and authorization patterns
- Static code analysis techniques
- Security controls and best practices
- Database design and relationships
- Testing and quality assurance

## License & Disclaimer

This tool is for educational purposes. Use it only on code you own or have permission to audit. The authors are not responsible for misuse.

Static code analysis produces point-in-time insights and can have false positives and false negatives. Always combine with manual code review and dynamic testing.

## Support

For issues, questions, or improvements, refer to the code comments and test files for examples.

---

**Created**: 2024
**Purpose**: Educational demonstration of secure web application development
