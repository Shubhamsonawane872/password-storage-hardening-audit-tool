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
    _P001 = [
        re.compile(r"password\s*=\s*['\"][^'\"]{3,}['\"]", re.IGNORECASE),
        re.compile(r"password\s*:\s*['\"][^'\"]{3,}['\"]", re.IGNORECASE),
        re.compile(r"\$password\s*=\s*['\"][^'\"]{3,}['\"]", re.IGNORECASE),
        re.compile(r"passwd\s*=\s*['\"][^'\"]{3,}['\"]", re.IGNORECASE),
        re.compile(r"\bpwd\s*=\s*['\"][^'\"]{3,}['\"]", re.IGNORECASE),
        re.compile(r"\bINSERT\s+INTO\b.*\bpassword\b", re.IGNORECASE),
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
        re.compile(r"password\s*[=:]\s*['\"][A-Za-z0-9!@#$%^&*]{8,}['\"]", re.IGNORECASE),
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

    # PWD013 – password printed / logged
    _P013 = re.compile(
        r'(print|console\.log|logger\.(debug|info|warning|error|critical)|'
        r'logging\.(debug|info|warning|error|critical))\s*\(.*?password',
        re.IGNORECASE,
    )

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

            # PWD001 – plaintext
            for pat in self._P001:
                if pat.search(line) and not _looks_safe(line):
                    conf = _context_confidence(lines, i, 0.88)
                    findings.append(self._finding("PWD001", lineno, stripped, conf))
                    break

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
                if pat.search(line):
                    conf = _context_confidence(lines, i, 0.93)
                    findings.append(self._finding("PWD004", lineno, _redact(stripped), conf))
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

            # PWD013 – password logged
            if self._P013.search(line):
                conf = _context_confidence(lines, i, 0.92)
                findings.append(self._finding("PWD013", lineno, _redact(stripped), conf))

        # --- Entropy scan (file-level, only for non-test files) ----------------
        if not self._is_test_file(filename):
            findings.extend(self._entropy_scan(scan_lines, ext))

        # AST, line-pattern, and entropy checks can flag the same source line.
        # Keep one auditable finding per rule and line, using the strongest match.
        unique_findings: dict[tuple[str, int], Dict] = {}
        for finding in findings:
            key = (finding["rule_id"], finding["line_number"])
            previous = unique_findings.get(key)
            if previous is None or finding["confidence"] > previous["confidence"]:
                unique_findings[key] = finding

        return list(unique_findings.values())

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

        for node in ast.walk(tree):
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
