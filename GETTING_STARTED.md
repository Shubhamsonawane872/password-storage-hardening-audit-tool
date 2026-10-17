# Getting Started - Password Storage Hardening Audit Tool

## Quick Start (5 Minutes)

### Step 1: Open PowerShell and Navigate to Project

```powershell
cd "c:\Users\Om Sai Ram\Desktop\Password-Audit"
```

### Step 2: Create and Activate Virtual Environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies

```powershell
pip install -r requirements.txt
```

This installs:
- Flask 2.3.3 - Web framework
- argon2-cffi 23.1.0 - Password hashing
- pytest 7.4.2 - Testing framework
- python-dotenv 1.0.0 - Environment management

### Step 4: Initialize Database

```powershell
python init_db.py
```

### Step 5: Load Demo Data (Optional but Recommended)

```powershell
python seed_demo.py
```

Demo credentials created:
- User: `demo@example.com` / `DemoPass123!`
- Admin: `admin@example.com` / `AdminPass123!`

### Step 6: Start the Application

```powershell
python run.py
```

You should see:
```
 * Running on http://127.0.0.1:5000
 * Press CTRL+C to quit
```

### Step 7: Open in Browser

Navigate to: **http://127.0.0.1:5000**

---

## First Test Run

### Option A: Using Demo Data

1. Click "Sign In"
2. Enter email: `demo@example.com`
3. Enter password: `DemoPass123!`
4. Click "Dashboard"
5. You should see demo scans and findings from the seeded data

### Option B: Starting Fresh

1. Click "Get Started"
2. Fill in your details and create an account
3. On login, dashboard will be empty
4. Click "Start New Scan"
5. Upload one of the sample files

---

## Testing the Scanner

### Upload a Sample File

1. Go to **Dashboard** → **Start New Scan**
2. Click the upload area or select a file
3. Choose one from `sample_apps/`:
   - **vulnerable_sample.py** - Contains intentional vulnerabilities
   - **safer_sample.py** - Shows best practices
   - **vulnerable_sample.js** - JavaScript vulnerabilities
   - **vulnerable_sample.php** - PHP vulnerabilities
4. Click "Start Scan"
5. Wait for analysis to complete
6. View the results with severity badges

### Expected Findings

**vulnerable_sample.py** should detect:
- PWD001: Plaintext password storage
- PWD002: MD5 hashing
- PWD003: SHA1 hashing
- PWD004: Hardcoded API keys
- PWD005: Unsalted hashing

**safer_sample.py** should detect:
- PWD007: Modern hashing (Argon2id, bcrypt, scrypt)

---

## Running Tests

### Run All Tests

```powershell
pytest tests/ -v
```

### Run Specific Test File

```powershell
pytest tests/test_auth.py -v
pytest tests/test_scanner_patterns.py -v
```

### Run with Coverage

```powershell
pytest tests/ --cov=app
```

### Expected Test Results

- ✅ 20+ tests should pass
- 100% pass rate indicates all functionality working

---

## Exploring Features

### Dashboard
- View total scans and vulnerability statistics
- See recent scan history
- Quick access to start new scans

### New Scan
- Upload Python, JavaScript, Java, or PHP files
- Upload ZIP archives with multiple files
- Drag-and-drop support
- File size validation

### Scan Results
- View detailed findings with severity levels
- Filter by severity or rule ID
- Search through findings
- Export results (JSON, HTML, CSV)
- Delete scans with confirmation

### Scan History
- List all your scans
- View individual scan details
- Delete old scans

### Admin Dashboard (If Admin)
- View all users and statistics
- Activate/deactivate users
- View audit logs
- Track system activity

---

## Understanding the Architecture

### Frontend
- **HTML**: Semantic structure (`templates/`)
- **CSS**: Professional styling (`static/css/`)
  - Main styles: `style.css`
  - Responsive design: `responsive.css`
- **JavaScript**: API interaction (`static/js/utils.js`)
  - Fetch wrapper for API calls
  - Form validation
  - DOM manipulation

### Backend
- **Flask App Factory** (`app/__init__.py`)
- **Blueprints** (modular organization)
  - auth: Login, register, logout
  - dashboard: User statistics
  - scanner: Upload and scan
  - reports: Export functionality
  - admin: User management
- **Security** (Argon2id, rate limiting, CSRF)
- **Database** (SQLite with 4 tables)

### Scanner Engine
- **Pattern Matching** (`scanner/patterns.py`)
  - Regex for common patterns
  - Language-specific checks
- **Rules** (`scanner/rules.py`)
  - 7 vulnerability rules (PWD001-007)
  - Severity levels and descriptions
- **File Handler** (`scanner/file_handler.py`)
  - Safe ZIP extraction
  - Path traversal prevention
  - File type validation

---

## File Structure Overview

```
app/
├── templates/              # HTML pages (11 files)
│   ├── index.html         # Landing page
│   ├── base.html          # Layout template
│   ├── auth/              # Login/Register
│   ├── dashboard.html     # Main dashboard
│   ├── scan_*.html        # Scan pages
│   └── admin_*.html       # Admin pages
│
├── static/                # Frontend assets
│   ├── css/              # Stylesheets
│   │   ├── style.css     # Main styles
│   │   └── responsive.css # Mobile styles
│   └── js/
│       └── utils.js      # JavaScript utilities
│
├── auth/                 # Authentication module
│   ├── routes.py        # Login/register endpoints
│   ├── utils.py         # Password hashing
│   └── decorators.py    # Auth decorators
│
├── scanner/             # Scanner module
│   ├── routes.py        # Upload/scan endpoints
│   ├── patterns.py      # Pattern matching logic
│   ├── rules.py         # Vulnerability rules
│   ├── engine.py        # Scan execution
│   └── file_handler.py  # File operations
│
├── reports/             # Report module
│   ├── routes.py        # Export endpoints
│   └── generators.py    # JSON/HTML/CSV export
│
├── admin/               # Admin module
│   └── routes.py        # User management
│
└── db.py               # Database initialization

tests/
├── test_auth.py                # Authentication tests
├── test_scanner_patterns.py   # Scanner tests
├── test_security.py           # Security tests
├── test_authorization.py      # Authorization tests
└── conftest.py               # Test fixtures
```

---

## Common Tasks

### Create New Admin User

Edit `seed_demo.py` and run it again, or manually in database:

```python
from app.auth.utils import hash_password
from app.db import get_db_connection

db = get_db_connection('instance/password_audit.db')
cursor = db.cursor()
cursor.execute(
    "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
    ('Admin Name', 'admin@youremail.com', hash_password('AdminPass123!'))
)
db.commit()
db.close()
```

### Change Upload Limits

Edit `.env`:
```
MAX_FILE_SIZE=52428800        # 50MB instead of 10MB
MAX_ZIP_SIZE=104857600        # 100MB instead of 50MB
MAX_FILES_IN_ZIP=500          # 500 files instead of 100
```

### Modify Session Timeout

Edit `.env`:
```
PERMANENT_SESSION_LIFETIME=7200  # 2 hours instead of 1 hour
```

### Reset Database

```powershell
Remove-Item instance/password_audit.db
python init_db.py
python seed_demo.py  # Optional
```

---

## Debugging

### View Debug Logs

Edit `.env`:
```
FLASK_DEBUG=True
```

Then restart:
```powershell
python run.py
```

The application will reload on file changes.

### Check Database

```python
from app.db import get_db_connection

db = get_db_connection('instance/password_audit.db')
cursor = db.cursor()

# List all users
cursor.execute("SELECT id, name, email, role FROM users")
for row in cursor.fetchall():
    print(row)

# List all scans
cursor.execute("SELECT id, user_id, original_filename, total_findings FROM scans")
for row in cursor.fetchall():
    print(row)

db.close()
```

### Check Scanner Rules

Edit `app/scanner/rules.py` to add/modify rules:

```python
RULES = {
    'PWD008': {  # New rule
        'title': 'Your Rule Title',
        'description': 'Description',
        'severity': 'high',
        'recommendation': 'What to do'
    }
}
```

Then add pattern detection in `app/scanner/patterns.py`.

---

## Performance Tips

### For Large Projects

- If scanning thousands of files, consider:
  - Implementing async processing
  - Using Celery for background jobs
  - Upgrading to PostgreSQL

### Database Optimization

- Current SQLite is perfect for development
- For production with many users:
  - Use PostgreSQL
  - Add connection pooling
  - Consider caching with Redis

---

## Troubleshooting

### "Python not found"

Your Python installation isn't in PATH. Either:
1. Reinstall Python (check "Add to PATH")
2. Use full path: `C:\Python312\python.exe run.py`
3. Use PowerShell App Execution Aliases settings

### Port 5000 in use

Another app is using port 5000. Change in `run.py`:

```python
app.run(debug=True, host='127.0.0.1', port=5001)
```

### "Database is locked"

Close other database connections. SQLite has limited concurrency.

### Tests failing

Ensure:
- Virtual environment is activated
- All dependencies installed: `pip install -r requirements.txt`
- Run from project root: `cd c:\Users\Om Sai Ram\Desktop\Password-Audit`

### Files not uploading

Check:
- File size within limits
- File type supported (.py, .js, .java, .php, .zip)
- Disk space available
- Folder permissions: `instance/` directory

---

## Next Steps

1. ✅ **Understand the Code**
   - Read `app/__init__.py` (app factory)
   - Review `app/scanner/patterns.py` (detection logic)
   - Check `app/auth/utils.py` (password hashing)

2. ✅ **Try the Features**
   - Create an account
   - Upload sample files
   - Export reports
   - Browse admin features

3. ✅ **Run Tests**
   - `pytest tests/ -v`
   - Review test coverage
   - Add your own tests

4. ✅ **Modify & Extend**
   - Add new vulnerability rules
   - Extend scanner to new languages
   - Customize the UI
   - Implement new features

5. ✅ **Deploy (Future)**
   - Set up production environment
   - Use gunicorn/uWSGI
   - Configure PostgreSQL
   - Set up HTTPS

---

## Resources

### Documentation
- Flask: https://flask.palletsprojects.com/
- Argon2: https://argon2-cffi.readthedocs.io/
- SQLite: https://www.sqlite.org/
- pytest: https://docs.pytest.org/

### Security References
- OWASP Password Guidelines: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- CWE-256: Plaintext Storage of Password: https://cwe.mitre.org/data/definitions/256.html
- CWE-326: Inadequate Encryption Strength: https://cwe.mitre.org/data/definitions/326.html

---

## Support

For issues or questions:
1. Check FEATURES_CHECKLIST.md for implementation details
2. Review README.md for comprehensive documentation
3. Check test files for usage examples
4. Review comments in source code

---

## Summary

You now have a complete, functional Password Storage Hardening Audit Tool with:
- ✅ Secure user authentication
- ✅ Static code analysis
- ✅ Professional web interface
- ✅ Comprehensive testing
- ✅ Full documentation

Happy scanning! 🔐
