"""
Static code scanner — rule engine for PWD001-PWD013.

Each public method returns a list of finding dicts:
    {
        'rule_id':    str,
        'line_number': int,
        'evidence':   str   (safely truncated / redacted),
        'confidence': float (0.0 – 1.0),
    }

The scanner intentionally avoids *executing* any uploaded code; it only
reads text. AST analysis is applied to Python files where safe.
"""
from __future__ import annotations

import ast
import base64
import io
import math
import re
import tokenize
from pathlib import Path
from typing import List, Dict

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_SECRET_NAMES = re.compile(
    r'\b(password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|'
    r'access[_-]?token|private[_-]?key|jwt[_-]?secret|signing[_-]?key|'
    r'db[_-]?pass|database[_-]?password|credential)\b',
    re.IGNORECASE,
)

_HASH_SAFE_KEYWORDS = frozenset([
    'hash', 'hashed', 'hasher', 'bcrypt', 'argon', 'scrypt', 'pbkdf',
])

_MODERN_HASH_RE = re.compile(
    r'\b(argon2(?:id)?|bcrypt|scrypt|pbkdf2(?:_hmac)?|PasswordHasher|'
    r'BCryptPasswordEncoder|password_hash)\b',
    re.IGNORECASE,
)


def _is_modern_hash_usage(line: str) -> bool:
    """Require an import/declaration or hashing API call, not a variable mention."""
    if not _MODERN_HASH_RE.search(line):
        return False
    if re.search(r'\b(import|from|use)\b', line, re.IGNORECASE):
        return True
    return bool(re.search(
        r'\b(?:hashpw|gensalt|checkpw|hash|verify|scrypt|pbkdf2(?:_hmac)?|'
        r'password_hash|PasswordHasher|BCryptPasswordEncoder)\s*\(',
        line, re.IGNORECASE,
    ))


def _shannon_entropy(value: str) -> float:
    """Return Shannon entropy (0–1) for a string."""
    if not value:
        return 0.0
    freq = [value.count(chr(i)) / len(value) for i in range(256) if value.count(chr(i))]
    raw = -sum(f * math.log2(f) for f in freq if f > 0)
    return raw / 8.0  # normalise against log2(256)


def _redact(text: str) -> str:
    """Replace long quoted literals with [REDACTED] to avoid storing secrets."""
    return re.sub(r"""(['"])([A-Za-z0-9!@#$%^&*_+\-=]{8,})\1""", r'\1[REDACTED]\1', text)


def _truncate(text: str, n: int = 120) -> str:
    text = text.strip()
    return text[:n] + ("…" if len(text) > n else "")


def _is_comment(line: str, ext: str) -> bool:
    s = line.lstrip()
    if ext == "py":
        return s.startswith("#")
    if ext in ("js", "ts", "java", "php", "c", "cpp"):
        return s.startswith("//") or s.startswith("/*") or s.startswith("*")
    return False


def _looks_safe(line: str) -> bool:
    lower = line.lower()
    return any(kw in lower for kw in _HASH_SAFE_KEYWORDS)


def _is_test_context(lines: list[str], idx: int) -> bool:
    """Heuristic: is line idx inside a test / demo / fixture function?"""
    window = "\n".join(lines[max(0, idx - 6): idx + 7]).lower()
    return bool(re.search(r'(def test_|@pytest|fixture|mock|fake|demo|example)', window))


def _is_auth_context(lines: list[str], idx: int) -> bool:
    window = "\n".join(lines[max(0, idx - 6): idx + 7])
    return bool(re.search(
        r'(def\s+(authenticate|login|verify|hash_password|check_password)|'
        r'class\s+\w*(Auth|Login|User)\w*)',
        window, re.IGNORECASE,
    ))


def _context_confidence(lines: list[str], idx: int, base: float) -> float:
    if _is_test_context(lines, idx):
        return base * 0.35          # heavily suppress test-code findings
    if _is_auth_context(lines, idx):
        return min(base * 1.25, 1.0)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Main scanner
# ─────────────────────────────────────────────────────────────────────────────

class CodeScanner:
    """Rule-based + entropy-aware static scanner for password vulnerabilities."""

    # ── Pre-compiled patterns ─────────────────────────────────────────────────

    # PWD001 – plaintext storage
    # PWD001 is deliberately limited to storage/write operations or a
    # plaintext comparison. A local assignment is handled by PWD004 instead.
    _P001_STORAGE = [
        re.compile(
            r"\b(?:execute\w*|executemany|query|prepare)\s*\(.*"
            r"\b(?:insert\s+into|update)\b.*\b(?:password|passwd|pwd)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:write|writelines|json\.dump|json_encode)\s*\([^)]*"
            r"\b(?:password|passwd|pwd)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:stored_)?(?:password|passwd|pwd)\b\s*==\s*"
            r"(?:\w+\.get\s*\(|\w+\.(?:password|passwd|pwd)\b|stored_)",
            re.IGNORECASE,
        ),
    ]

    # PWD002 – MD5   (fixed: now covers ALL md5 forms including hashlib.md5)
    _P002 = re.compile(
        r'(hashlib\.md5\b|(?<!\w)md5\s*\(|MD5\s*\(|CryptoJS\.MD5|\.md5\('
        r'|createHash\s*\(\s*[\'\"]md5[\'\"]|getInstance\s*\(\s*[\'\"]MD5[\'\"])',
        re.IGNORECASE,
    )

    # PWD003 – SHA-1  (fixed: covers hashlib.sha1 etc.)
    _P003 = re.compile(
        r'(hashlib\.sha1\b|(?<!\w)sha1\s*\(|SHA1\s*\(|CryptoJS\.SHA1|\.sha1\('
        r'|createHash\s*\(\s*[\'\"]sha-?1[\'\"]|getInstance\s*\(\s*[\'\"]SHA-?1[\'\"])',
        re.IGNORECASE,
    )

    # PWD004 – hardcoded secret
    _P004 = [
        re.compile(r"api[_-]?key\s*[=:]\s*['\"][^'\"]{10,}['\"]", re.IGNORECASE),
        re.compile(r"secret\s*[=:]\s*['\"][^'\"]{10,}['\"]", re.IGNORECASE),
        re.compile(r"token\s*[=:]\s*['\"][^'\"]{20,}['\"]", re.IGNORECASE),
        re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
        # Stripe / GitHub / AWS-style tokens
        re.compile(r"sk_(live|test)_[A-Za-z0-9]{20,}", re.IGNORECASE),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
    ]

    # PWD005 – unsalted SHA-2
    _P005 = [
        re.compile(
            r"hashlib\.sha(256|512)\s*\(.*\bpassword\b.*\)\.hexdigest\(\)",
            re.IGNORECASE,
        ),
        re.compile(r"CryptoJS\.SHA(256|512)\s*\([^,]+\)", re.IGNORECASE),
        re.compile(r"(?:createHash\s*\(\s*['\"]sha-?256['\"]|getInstance\s*\(\s*['\"]SHA-256['\"])", re.IGNORECASE),
        re.compile(r"hash\s*\(\s*['\"]sha(256|512)['\"]\s*,\s*\$password", re.IGNORECASE),
    ]

    # PWD006 – weak / obsolete  (was previously untriggered)
    _P006 = [
        re.compile(r"hashlib\.(sha224|sha384|sha3_|blake2|new\s*\(['\"]sha)", re.IGNORECASE),
        re.compile(r"passlib\.hash\.(md5|sha1|des_crypt)", re.IGNORECASE),
        re.compile(
            r"from\s+passlib\.hash\s+import\s+.*\b(md5|sha1|des_crypt)(?:_crypt)?\b",
            re.IGNORECASE,
        ),
        re.compile(r"\bcrypt\.crypt\s*\(", re.IGNORECASE),          # Python crypt()
        re.compile(r"CRC32\s*\(", re.IGNORECASE),
    ]

    # PWD008 – base64-encoded secret
    _P008 = re.compile(
        r"""(['"])[A-Za-z0-9+/]{20,}={0,2}\1""",
    )

    # PWD009 – hardcoded JWT secret
    _P009 = [
        re.compile(r"jwt[_\s]?secret\s*[=:]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
        re.compile(r"JWT_SECRET\s*=\s*['\"][^'\"]{8,}['\"]"),
        re.compile(r"app\.config\[['\"]SECRET_KEY['\"]\]\s*=\s*['\"][^'\"]{8,}['\"]"),
        re.compile(r"SECRET_KEY\s*=\s*['\"][^'\"]{8,}['\"]"),
    ]

    # PWD010 – DES / 3DES
    _P010 = re.compile(
        r'\b(DES\.new|DES3\.new|Cipher\.DES\b|Cipher\.3DES\b|'
        r'DESede|TripleDES|createDecipheriv\s*\(\s*[\'"]des)',
        re.IGNORECASE,
    )

    # PWD011 – PBKDF2 with low iteration count (< 100 000)
    _P011 = re.compile(
        r'(?:(?:pbkdf2_hmac\s*\([^,]+,[^,]+,[^,]+,)|'
        r'(?:pbkdf2\s*\([^,]+,[^,]+,))\s*(?P<iterations>\d+)\b',
        re.IGNORECASE,
    )

    # PWD012 – custom / homebrew crypto
    _P012 = [
        re.compile(r'\bxor\s*\(\s*(?:password|secret|key)', re.IGNORECASE),
        re.compile(r'ord\s*\(.*\)\s*\^\s*ord\s*\(.*\)'),        # xor bytes
        re.compile(r'#\s*(encrypt|cipher|custom\s+crypto)', re.IGNORECASE),
        re.compile(r'def\s+(my|custom|simple|home)[_\s]?(encrypt|cipher|hash)', re.IGNORECASE),
        re.compile(r'rot13|caesar\s+cipher', re.IGNORECASE),
    ]

    # PWD013 for Python is AST-only. Non-Python languages use a narrower
    # argument matcher in _non_python_password_logged.

    # ── Public API ────────────────────────────────────────────────────────────

    def scan_file(self, filename: str, content: str) -> List[Dict]:
        """
        Scan *content* (text of *filename*) and return a list of finding dicts.
        Does not execute the code.
        """
        ext = Path(filename).suffix.lstrip(".").lower()
        lines = content.splitlines()
        scan_lines = (self._python_code_lines(content, lines) if ext == "py"
                      else self._non_python_code_lines(content, ext))
        saved_model_names = {name.lower() for name in re.findall(
            r"\$?([A-Za-z_]\w*)\s*(?:->|\.)\s*save\s*\(", content, re.IGNORECASE
        )} if ext != "py" else set()
        findings: List[Dict] = []

        # --- Python AST pre-pass (deeper analysis, Python only) ---------------
        if ext == "py":
            findings.extend(self._ast_scan(content, lines))

        # --- Line-by-line regex scan ------------------------------------------
        for i, line in enumerate(scan_lines):
            if _is_comment(line, ext):
                continue

            lineno = i + 1          # 1-indexed for reporting
            stripped = line.strip()

            # PWD001 – non-Python storage calls and stored-value comparisons.
            # Python is analyzed structurally in _ast_scan.
            model_field_assignment = re.search(
                r"\$?([A-Za-z_]\w*)\s*(?:->|\.)\s*(?:password|passwd|pwd)\s*=\s*\$?"
                r"(password|passwd|pwd)\b",
                line, re.IGNORECASE,
            )
            saved_model_password = bool(
                model_field_assignment
                and model_field_assignment.group(1).lower() in saved_model_names
            )
            if (ext != "py" and (saved_model_password or any(
                    pat.search(line) for pat in self._P001_STORAGE))):
                conf = _context_confidence(lines, i, 0.88)
                findings.append(self._finding("PWD001", lineno, stripped, conf))

            # PWD002 – MD5
            if self._P002.search(line):
                conf = _context_confidence(lines, i, 0.97)
                findings.append(self._finding("PWD002", lineno, stripped, conf))

            # PWD003 – SHA-1
            if self._P003.search(line):
                conf = _context_confidence(lines, i, 0.96)
                findings.append(self._finding("PWD003", lineno, stripped, conf))

            # PWD004 – hardcoded secret
            for pat in self._P004:
                match = pat.search(line)
                if match:
                    conf = _context_confidence(lines, i, 0.93)
                    finding = self._finding("PWD004", lineno, _redact(stripped), conf)
                    literal = re.search(r"['\"]([^'\"]*)['\"]", match.group(0))
                    if (literal and literal.group(1).strip().lower() in {"changeme", "change_me"}
                            and re.search(r"(?:sample|test)", filename, re.IGNORECASE)):
                        finding["severity"] = "low"
                    findings.append(finding)
                    break

            # PWD005 – unsalted SHA-2
            for pat in self._P005:
                if pat.search(line) and not re.search(r"\bsalt\b", line, re.IGNORECASE):
                    conf = _context_confidence(lines, i, 0.91)
                    findings.append(self._finding("PWD005", lineno, stripped, conf))
                    break

            # PWD006 – weak/obsolete pattern
            for pat in self._P006:
                if pat.search(line):
                    conf = _context_confidence(lines, i, 0.80)
                    findings.append(self._finding("PWD006", lineno, stripped, conf))
                    break

            # PWD007 – modern hashing (positive)
            if _is_modern_hash_usage(line):
                findings.append(self._finding("PWD007", lineno, stripped, 0.99))

            # PWD008 – base64-encoded secret
            b64_match = self._P008.search(line)
            if b64_match and _SECRET_NAMES.search(line):
                raw = b64_match.group(0).strip("'\"")
                if self._looks_like_base64_secret(raw):
                    conf = _context_confidence(lines, i, 0.85)
                    findings.append(self._finding("PWD008", lineno, _redact(stripped), conf))

            # PWD009 – JWT secret
            for pat in self._P009:
                if pat.search(line):
                    conf = _context_confidence(lines, i, 0.96)
                    findings.append(self._finding("PWD009", lineno, _redact(stripped), conf))
                    break

            # PWD010 – DES / 3DES
            if self._P010.search(line):
                conf = _context_confidence(lines, i, 0.95)
                findings.append(self._finding("PWD010", lineno, stripped, conf))

            # PWD011 – PBKDF2 low iteration count
            m = self._P011.search(line)
            if m:
                try:
                    iters = int(m.group("iterations"))
                    if iters < 100_000:
                        conf = _context_confidence(lines, i, 0.90)
                        findings.append(
                            self._finding("PWD011", lineno,
                                          f"{stripped} [iterations={iters}]", conf)
                        )
                except ValueError:
                    pass

            # PWD012 – custom crypto
            for pat in self._P012:
                if pat.search(line):
                    conf = _context_confidence(lines, i, 0.75)
                    findings.append(self._finding("PWD012", lineno, stripped, conf))
                    break

            # PWD013 – non-Python only; Python uses AST argument analysis.
            if ext != "py" and self._non_python_password_logged(line, ext):
                conf = _context_confidence(lines, i, 0.92)
                findings.append(self._finding("PWD013", lineno, _redact(stripped), conf))

        # --- Entropy scan (file-level, only for non-test files) ----------------
        if not self._is_test_file(filename):
            findings.extend(self._entropy_scan(scan_lines, ext))

        # AST, line-pattern, and entropy checks can flag the same source line.
        # Keep one auditable finding per rule and line, using the strongest match.
        unique_findings: dict[tuple[str, int], Dict] = {}
        modern_algorithms: dict[str, Dict] = {}
        for finding in findings:
            if finding["rule_id"] == "PWD007":
                algorithm = self._modern_hash_algorithm(finding["evidence"])
                previous = modern_algorithms.get(algorithm)
                # Prefer a hashing/verification call over an import line.
                if previous is None or _is_modern_hash_usage(finding["evidence"]):
                    modern_algorithms[algorithm] = finding
                continue
            key = (finding["rule_id"], finding["line_number"])
            previous = unique_findings.get(key)
            if previous is None or finding["confidence"] > previous["confidence"]:
                unique_findings[key] = finding

        return list(unique_findings.values()) + list(modern_algorithms.values())

    @staticmethod
    def _python_code_lines(source: str, lines: list[str]) -> list[str]:
        """Mask comments and docstrings so examples in prose are not findings."""
        masked = [list(line) for line in lines]
        try:
            for token in tokenize.generate_tokens(io.StringIO(source).readline):
                if token.type == tokenize.COMMENT:
                    row, col = token.start
                    end_row, end_col = token.end
                    for r in range(row - 1, end_row):
                        start = col if r == row - 1 else 0
                        stop = end_col if r == end_row - 1 else len(masked[r])
                        for c in range(start, min(stop, len(masked[r]))):
                            masked[r][c] = " "
        except (tokenize.TokenError, IndentationError):
            pass
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                body = getattr(node, "body", None)
                if not isinstance(body, list) or not body:
                    continue
                first = body[0]
                if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                        and isinstance(first.value.value, str)):
                    for row in range(first.lineno - 1, getattr(first, "end_lineno", first.lineno)):
                        masked[row] = [" "] * len(masked[row])
        except SyntaxError:
            pass
        return ["".join(line) for line in masked]

    @staticmethod
    def _non_python_code_lines(source: str, ext: str) -> list[str]:
        """Mask inline and block comments while preserving strings and line positions."""
        chars = list(source)
        quote = None
        block_comment = False
        line_comment = False
        escaped = False
        i = 0
        while i < len(chars):
            ch = chars[i]
            nxt = chars[i + 1] if i + 1 < len(chars) else ""
            if ch == "\n":
                line_comment = False
                escaped = False
                i += 1
                continue
            if block_comment:
                if ch == "*" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    block_comment = False
                    i += 2
                    continue
                if ch != "\r":
                    chars[i] = " "
                i += 1
                continue
            if line_comment:
                if ch != "\r":
                    chars[i] = " "
                i += 1
                continue
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                i += 1
                continue
            if ch in ("'", '"', '`'):
                quote = ch
                i += 1
                continue
            if ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                block_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "/" or (ext == "php" and ch == "#"):
                line_comment = True
                chars[i] = " "
                i += 1
                continue
            i += 1
        return "".join(chars).splitlines()

    # ── Private helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _finding(rule_id: str, lineno: int, evidence: str, confidence: float) -> Dict:
        return {
            "rule_id": rule_id,
            "line_number": lineno,
            "evidence": _truncate(evidence),
            "confidence": round(min(max(confidence, 0.0), 1.0), 3),
        }

    @staticmethod
    def _is_test_file(filename: str) -> bool:
        return bool(re.search(r'test_|_test\.|spec\.', filename, re.IGNORECASE))

    def _looks_like_base64_secret(self, value: str) -> bool:
        """True if the string has high entropy and decodes cleanly."""
        if _shannon_entropy(value) < 0.55:
            return False
        try:
            decoded = base64.b64decode(value + "==").decode("utf-8", errors="strict")
            return len(decoded) >= 6
        except Exception:
            return False

    @staticmethod
    def _python_password_logged(node: ast.Call) -> bool:
        """Match secret variables passed directly to an output call.

        Nested calls such as ``print(verify_password(password, digest))`` are
        intentionally ignored: their result, not the password, is printed.
        """
        func = node.func
        if isinstance(func, ast.Name):
            output_call = func.id.lower() == "print"
        elif isinstance(func, ast.Attribute):
            method = func.attr.lower()
            base = func.value
            logger_base = (
                isinstance(base, ast.Name)
                and (base.id.lower() in {"logger", "log", "logging", "console"}
                     or base.id.lower().endswith("logger"))
            ) or (isinstance(base, ast.Attribute) and base.attr.lower() == "logger")
            logger_factory = (
                isinstance(base, ast.Call)
                and isinstance(base.func, ast.Attribute)
                and base.func.attr.lower() == "getlogger"
            )
            output_call = (
                method == "log" and logger_base
            ) or (
                method in {"debug", "info", "warning", "error", "critical", "exception"}
                and (logger_base or logger_factory)
            )
        else:
            output_call = False
        if not output_call:
            return False

        def secret_name(name: str) -> bool:
            return bool(_SECRET_NAMES.search(name))

        for arg in node.args:
            if isinstance(arg, ast.Name) and secret_name(arg.id):
                return True
            if isinstance(arg, ast.JoinedStr):
                for value in arg.values:
                    if (isinstance(value, ast.FormattedValue)
                            and isinstance(value.value, ast.Name)
                            and secret_name(value.value.id)):
                        return True
        return False

    @staticmethod
    def _modern_hash_algorithm(evidence: str) -> str:
        lower = evidence.lower()
        if "argon" in lower or "passwordhasher" in lower:
            return "argon2"
        if "bcrypt" in lower:
            return "bcrypt"
        if "scrypt" in lower:
            return "scrypt"
        if "pbkdf2" in lower:
            return "pbkdf2"
        return "password_hash"

    @staticmethod
    def _non_python_password_logged(line: str, ext: str) -> bool:
        """Conservative output-call check for JS, Java, and PHP source."""
        call = re.search(
            r"(?:console\s*\.\s*log|logger\s*\.\s*(?:debug|info|warning|error|critical)"
            r"|logging\s*\.\s*(?:debug|info|warning|error|critical)|"
            r"System\s*\.\s*out\s*\.\s*print(?:ln)?|error_log|print_r|print)\s*\((.*)\)",
            line, re.IGNORECASE,
        )
        if not call:
            return False
        args = call.group(1)
        # A variable in a template interpolation is direct output in JS.
        interpolation_names = re.findall(r"\$\{\s*([A-Za-z_$][\w$]*)\s*\}", args)
        # Drop quoted literals so prose such as "password is safe" is ignored.
        without_literals = re.sub(r"(['\"`])(?:\\.|(?!\1)[^\\])*?\1", " ", args)
        without_literals = re.sub(r"\b\w+\s*\([^()]*\)", " ", without_literals)
        direct_names = re.findall(r"(?<![\w.$])([A-Za-z_$][\w$]*)(?![\w$])", without_literals)
        names = direct_names + interpolation_names
        return any(_SECRET_NAMES.search(name) for name in names)

    # ── AST-based Python scanner ───────────────────────────────────────────────

    def _ast_scan(self, source: str, lines: list[str]) -> List[Dict]:
        """
        Deep-inspect Python source via the AST to find patterns that
        regex alone can miss (e.g. multi-line dict literals, type annotations).
        """
        results: List[Dict] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return results

        saved_models = {
            ast.unparse(node.func.value)
            for node in ast.walk(tree)
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr.lower() == "save" and hasattr(ast, "unparse"))
        }

        for node in ast.walk(tree):
            # Passwords are plaintext only when they are written to a storage
            # API/model field or compared against a stored value.
            if isinstance(node, ast.Call):
                func_name = self._ast_func_name(node) or ""
                call_text = ast.unparse(node) if hasattr(ast, "unparse") else ""
                sql_api = func_name.lower() in {
                    "execute", "executemany", "query", "prepare",
                }
                other_storage_api = func_name.lower() in {
                    "write", "writelines", "dump", "json_encode",
                }
                sql_write = bool(re.search(
                    r"\b(?:insert\s+into|update)\b.*\b(?:password|passwd|pwd)\b",
                    call_text, re.IGNORECASE,
                ))
                sensitive_arg = any(
                    isinstance(child, ast.Name) and _SECRET_NAMES.search(child.id)
                    for arg in node.args for child in ast.walk(arg)
                )
                if (sql_api and sql_write) or (other_storage_api and sensitive_arg):
                    results.append(self._finding(
                        "PWD001", node.lineno,
                        lines[node.lineno - 1].strip() if node.lineno <= len(lines) else call_text,
                        0.88,
                    ))

                if self._python_password_logged(node):
                    results.append(self._finding(
                        "PWD013", node.lineno,
                        lines[node.lineno - 1].strip() if node.lineno <= len(lines) else call_text,
                        0.92,
                    ))

            if isinstance(node, ast.Assign):
                for target in node.targets:
                    value_is_secret = isinstance(node.value, ast.Name) and bool(
                        _SECRET_NAMES.search(node.value.id)
                    )
                    target_text = ast.unparse(target) if hasattr(ast, "unparse") else ""
                    model_field_saved = (
                        isinstance(target, ast.Attribute)
                        and bool(_SECRET_NAMES.search(target.attr))
                        and (ast.unparse(target.value) if hasattr(ast, "unparse") else "") in saved_models
                    )
                    sensitive_mapping = (
                        isinstance(target, ast.Subscript)
                        and bool(re.search(r"user|account|database|store|credential", target_text, re.I))
                    )
                    if (model_field_saved or sensitive_mapping) and value_is_secret:
                        results.append(self._finding(
                            "PWD001", node.lineno, lines[node.lineno - 1].strip(), 0.88
                        ))

            if isinstance(node, ast.Compare):
                operands = [node.left, *node.comparators]
                if any(isinstance(op, ast.Eq) for op in node.ops):
                    has_password = any(
                        isinstance(op, ast.Name) and _SECRET_NAMES.search(op.id)
                        for op in operands
                    )
                    has_stored_value = any(
                        isinstance(op, ast.Call) and self._ast_func_name(op) == "get"
                        or isinstance(op, ast.Attribute) and bool(
                            re.search(r"user|stored|database|record|account", op.attr, re.I)
                        )
                        or isinstance(op, ast.Name) and bool(
                            re.search(r"stored|database|users|record|account", op.id, re.I)
                        )
                        for op in operands
                    )
                    if has_password and has_stored_value:
                        results.append(self._finding(
                            "PWD001", node.lineno, lines[node.lineno - 1].strip(), 0.88
                        ))

            # Detect password/secret string constants assigned to sensitive names
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    name = self._ast_name(target)
                    if name and _SECRET_NAMES.search(name):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            lineno = node.lineno
                            if len(val) >= 3 and not _looks_safe(val):
                                conf = _context_confidence(lines, lineno - 1, 0.92)
                                results.append(
                                    self._finding(
                                        "PWD004", lineno,
                                        f"{name} = [REDACTED]", conf,
                                    )
                                )

            # Detect function calls to hash functions
            if isinstance(node, ast.Call):
                func_name = self._ast_func_name(node)
                lineno = node.lineno
                if func_name:
                    if re.search(r'\bmd5\b', func_name, re.IGNORECASE):
                        conf = _context_confidence(lines, lineno - 1, 0.98)
                        results.append(
                            self._finding("PWD002", lineno,
                                          lines[lineno - 1].strip() if lineno <= len(lines) else func_name,
                                          conf)
                        )
                    elif re.search(r'\bsha1\b', func_name, re.IGNORECASE):
                        conf = _context_confidence(lines, lineno - 1, 0.97)
                        results.append(
                            self._finding("PWD003", lineno,
                                          lines[lineno - 1].strip() if lineno <= len(lines) else func_name,
                                          conf)
                        )

        return results

    @staticmethod
    def _ast_name(node) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    @staticmethod
    def _ast_func_name(node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    # ── Entropy-based secret scanner ───────────────────────────────────────────

    def _entropy_scan(self, lines: list[str], ext: str) -> List[Dict]:
        """
        Flag high-entropy string literals adjacent to sensitive variable names
        that weren't caught by the keyword patterns above.
        """
        results: List[Dict] = []
        assignment_re = re.compile(r"""(['"])([A-Za-z0-9+/!@#$%^&*_\-=.]{12,})\1""")

        for i, line in enumerate(lines):
            if _is_comment(line, ext) or not _SECRET_NAMES.search(line):
                continue
            for m in assignment_re.finditer(line):
                val = m.group(2)
                ent = _shannon_entropy(val)
                if ent >= 0.65:
                    conf = _context_confidence(lines, i, min(0.5 + ent, 0.95))
                    if not _is_test_context(lines, i):
                        results.append(
                            self._finding(
                                "PWD004", i + 1,
                                _redact(line.strip()), conf,
                            )
                        )
                        break  # one per line

        return results
