"""Intentionally insecure sample for static scanning; never use these dummy values."""

import hashlib


# Scanner should flag this hardcoded demo password (PWD001 and PWD004).
DEMO_PASSWORD = "NotARealPassword123!"

# Scanner should flag the fast legacy hash (PWD002).
DEMO_PASSWORD_HASH = hashlib.md5(DEMO_PASSWORD.encode()).hexdigest()
