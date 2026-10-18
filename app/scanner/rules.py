"""Scanner rule registry — PWD001 through PWD013."""

RULES: dict = {
    # ── Core password-storage rules ─────────────────────────────────────────
    "PWD001": {
        "title": "Possible plaintext password storage",
        "description": (
            "Detected code that writes a raw password to a database, file, or "
            "model field, or compares it with a stored value in plaintext. "
            "Storing plaintext passwords means any database "
            "breach immediately exposes every user's password."
        ),
        "severity": "critical",
        "recommendation": (
            "Hash passwords with Argon2id (argon2-cffi), bcrypt, or scrypt "
            "before persisting or comparing them. Never store or log raw passwords."
        ),
        "cwe": "CWE-256",
        "owasp": "A02:2021",
    },
    "PWD002": {
        "title": "MD5 used for password hashing",
        "description": (
            "MD5 is cryptographically broken; GPU-based crackers can test "
            "billions of MD5 hashes per second. It must not be used for "
            "password storage, even with a salt."
        ),
        "severity": "high",
        "recommendation": (
            "Replace md5() with Argon2id, bcrypt, or scrypt. "
            "If MD5 is used for non-password data integrity checks, "
            "consider SHA-256 or BLAKE2 instead."
        ),
        "cwe": "CWE-327",
        "owasp": "A02:2021",
    },
    "PWD003": {
        "title": "SHA-1 used for password hashing",
        "description": (
            "SHA-1 is collision-vulnerable and far too fast for password "
            "hashing — an attacker can enumerate common passwords in seconds."
        ),
        "severity": "high",
        "recommendation": (
            "Replace sha1() with a memory-hard KDF: Argon2id, bcrypt, or scrypt."
        ),
        "cwe": "CWE-327",
        "owasp": "A02:2021",
    },
    "PWD004": {
        "title": "Hardcoded password or secret",
        "description": (
            "A credential or high-entropy secret appears to be hardcoded in "
            "source code. Anyone with read access to the repository gains "
            "access to the protected resource permanently."
        ),
        "severity": "high",
        "recommendation": (
            "Store secrets in environment variables or a dedicated secrets "
            "manager (Vault, AWS Secrets Manager, etc.). "
            "Rotate any secrets that have already been committed."
        ),
        "cwe": "CWE-798",
        "owasp": "A07:2021",
    },
    "PWD005": {
        "title": "Possible unsalted password hashing",
        "description": (
            "A general-purpose hash function (SHA-256, SHA-512) is called with "
            "only the password as input, with no observable salt parameter. "
            "Unsalted hashes are vulnerable to rainbow-table attacks."
        ),
        "severity": "high",
        "recommendation": (
            "Use Argon2id, bcrypt, or scrypt — they handle salt automatically. "
            "Never implement manual salting on top of SHA-2."
        ),
        "cwe": "CWE-759",
        "owasp": "A02:2021",
    },
    "PWD006": {
        "title": "Weak or obsolete password-storage pattern",
        "description": (
            "Detected a known-weak approach: a fast general-purpose hash "
            "(SHA-2, SHA-3, BLAKE2, CRC32) used directly on a password, "
            "or a deprecated library (passlib with MD5/SHA1 scheme, crypt() "
            "with DES rounds, base64-encoded passwords)."
        ),
        "severity": "medium",
        "recommendation": (
            "Migrate to Argon2id. Avoid SHA-2/SHA-3/BLAKE2 for passwords even "
            "with a salt — they are not memory-hard and are trivially brute-forced."
        ),
        "cwe": "CWE-916",
        "owasp": "A02:2021",
    },
    "PWD007": {
        "title": "Modern password hashing detected",
        "description": (
            "Detected use of a recommended password-hashing algorithm "
            "(Argon2id, bcrypt, scrypt, PBKDF2). This is a positive finding."
        ),
        "severity": "info",
        "recommendation": (
            "Good practice. Ensure Argon2id parameters meet current OWASP "
            "recommendations: memory ≥ 64 MiB, iterations ≥ 1, parallelism ≥ 4."
        ),
        "cwe": None,
        "owasp": None,
    },
    # ── Extended rules (new) ─────────────────────────────────────────────────
    "PWD008": {
        "title": "Base64-encoded secret or password",
        "description": (
            "A string that decodes to printable text is base64-encoded and "
            "assigned to a variable with a sensitive name. Base64 is encoding, "
            "not encryption — it provides zero security."
        ),
        "severity": "high",
        "recommendation": (
            "Remove hardcoded encoded secrets. Use environment variables or a "
            "secrets manager. Never confuse encoding with encryption."
        ),
        "cwe": "CWE-312",
        "owasp": "A02:2021",
    },
    "PWD009": {
        "title": "Hardcoded JWT secret key",
        "description": (
            "A JWT signing secret is hardcoded in source code. Any party with "
            "code access can forge arbitrary tokens and authenticate as any user."
        ),
        "severity": "critical",
        "recommendation": (
            "Load the JWT secret from an environment variable "
            "(e.g. os.getenv('JWT_SECRET')). Rotate the secret immediately if "
            "it has been committed to version control."
        ),
        "cwe": "CWE-798",
        "owasp": "A07:2021",
    },
    "PWD010": {
        "title": "DES or 3DES used for password or data encryption",
        "description": (
            "DES has a 56-bit key and is trivially brute-forced. 3DES is "
            "deprecated by NIST (2023) and vulnerable to Sweet32. Neither "
            "should be used for new code."
        ),
        "severity": "high",
        "recommendation": (
            "Replace DES/3DES with AES-256-GCM for symmetric encryption. "
            "For passwords specifically, use Argon2id hashing instead."
        ),
        "cwe": "CWE-327",
        "owasp": "A02:2021",
    },
    "PWD011": {
        "title": "PBKDF2 with dangerously low iteration count",
        "description": (
            "PBKDF2 is called with an iteration count below the OWASP minimum "
            "(600 000 for PBKDF2-HMAC-SHA256 as of 2023). Low iteration counts "
            "allow fast brute-force attacks."
        ),
        "severity": "medium",
        "recommendation": (
            "Set PBKDF2 iterations to at least 600 000 (SHA-256) or 210 000 "
            "(SHA-512). Prefer Argon2id for new implementations."
        ),
        "cwe": "CWE-916",
        "owasp": "A02:2021",
    },
    "PWD012": {
        "title": "Custom or homebrew cryptography detected",
        "description": (
            "Detected patterns suggesting hand-rolled cryptographic logic: "
            "XOR-based ciphers, Caesar/ROT shifts, manual bit-manipulation "
            "described as 'encryption', or reimplemented known algorithms. "
            "Custom crypto is almost always broken."
        ),
        "severity": "high",
        "recommendation": (
            "Use only well-audited cryptographic libraries "
            "(cryptography, PyNaCl, OpenSSL). Never implement your own cipher, "
            "KDF, or password hasher."
        ),
        "cwe": "CWE-327",
        "owasp": "A02:2021",
    },
    "PWD013": {
        "title": "Password logged or printed to output",
        "description": (
            "A password or credential variable is passed directly to a print, "
            "console.log, logger call, or similar output statement. "
            "Logged passwords end up in log files, monitoring systems, and "
            "crash reports — significantly expanding the attack surface."
        ),
        "severity": "high",
        "recommendation": (
            "Remove all logging of passwords, tokens, or secrets. "
            "Use structured logging and allowlist-based log sanitisation."
        ),
        "cwe": "CWE-312",
        "owasp": "A09:2021",
    },
}


def get_rule(rule_id: str) -> dict | None:
    """Return a single rule dict or None if the ID is unknown."""
    return RULES.get(rule_id)


def get_all_rules() -> dict:
    """Return the complete rule registry."""
    return RULES
