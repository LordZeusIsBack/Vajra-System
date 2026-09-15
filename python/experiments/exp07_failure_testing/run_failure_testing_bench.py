import os
import secrets

os.environ.setdefault("MANIFEST_HMAC_SECRET", secrets.token_hex(32))