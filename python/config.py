"""config.py — Centralised settings loaded from .env (or environment variables).

All Shamir n/k defaults + hard limits, IPFS node list, and Rust binary path
live here so nothing is scattered around as magic numbers or hardcoded strings.
"""

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Sentinel value shipped in env.example. Refuse to run if this leaks into prod.
_PLACEHOLDER_HMAC_SECRET = "change-me-before-any-real-use"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Rust binary ───────────────────────────────────────────────────────────
    vajra_binary: str = Field(
        default="../rust/target/release/vajra",
        alias="VAJRA_BIN",
        description=(
            "Path to the compiled vajra binary. "
            "Run `make rs-build` first, then point this at the output."
        ),
    )
    vajra_timeout_secs: int = Field(
        default=300,
        description=(
            "Max wall-clock seconds for a single vajra subprocess call. "
            "Covers the 2s benchmark inside `vajra generate`."
        ),
    )

    # ── IPFS nodes ────────────────────────────────────────────────────────────
    ipfs_api_urls: str = Field(
        default="http://127.0.0.1:5001,http://127.0.0.1:5002,http://127.0.0.1:5003",
        description=(
            "Comma-separated Kubo RPC API URLs. "
            "Shards are distributed round-robin across all listed nodes. "
            "Example: http://127.0.0.1:5001,http://127.0.0.1:5002,http://127.0.0.1:5003"
        ),
    )

    @property
    def ipfs_node_list(self) -> list[str]:
        """Parsed, deduplicated list of IPFS API base URLs (no trailing slash)."""
        seen: set[str] = set()
        result: list[str] = []
        for raw in self.ipfs_api_urls.split(","):
            url = raw.strip().rstrip("/")
            if url and url not in seen:
                seen.add(url)
                result.append(url)
        return result

    # ── Shamir SSS ────────────────────────────────────────────────────────────
    default_n: int = Field(default=10, ge=2, description="Default total shards")
    default_k: int = Field(default=8,  ge=2, description="Default threshold")
    max_shards: int = Field(
        default=50, ge=2, le=255,
        description="Hard cap on n (GF(2^8) field limits x-coords to 1..255)",
    )
    min_threshold: int = Field(default=2, ge=2, description="Hard floor on k")

    # ── Manifest signing ──────────────────────────────────────────────────────
    manifest_hmac_secret: str = Field(
        default=_PLACEHOLDER_HMAC_SECRET,
        min_length=16,
        description=(
            "HMAC-SHA256 key for manifest signatures. "
            "Generate: python -c \"import secrets; print(secrets.token_hex(32))\""
        ),
    )

    # ── Upload limits ─────────────────────────────────────────────────────────
    max_upload_bytes: int = Field(
        default=50 * 1024 * 1024,
        description="Max exam PDF upload size in bytes (default 50 MB)",
    )

    # ── Centers registry (Step 2: per-center encryption) ─────────────────────
    centers_registry_path: str = Field(
        default="./centers.json",
        description=(
            "Path to centers registry JSON ({centers: [{id, pubkey}, ...]}). "
            "Required for the per-center shard encryption pipeline. "
            "Generate with: python vajra_keygen.py bulk --n 10 --out-dir ./keys"
        ),
    )

    # ── drand (Layer A: time-anchor) ──────────────────────────────────────────
    # League of Entropy mainnet, 30s chained chain.
    # Constants are public — see https://drand.love
    drand_chain_hash: str = Field(
        default="8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce",
        description="Hex chain hash of the drand chain VAJRA is anchored to",
    )
    drand_genesis: int = Field(
        default=1595431050,
        description="Unix-seconds genesis time of the configured drand chain",
    )
    drand_period: int = Field(
        default=30,
        ge=1,
        description="Seconds between drand rounds on the configured chain",
    )
    drand_relays: str = Field(
        default=(
            "https://api.drand.sh,"
            "https://api2.drand.sh,"
            "https://api3.drand.sh,"
            "https://drand.cloudflare.com"
        ),
        description="Comma-separated drand HTTP relay base URLs",
    )
    drand_agreement_threshold: int = Field(
        default=2,
        ge=1,
        description=(
            "Minimum number of relays that must return identical signature + "
            "randomness for a round before we trust it. With 4 relays, 2 is "
            "a sensible default (tolerates 2 down or 1 dishonest)."
        ),
    )
    drand_timeout_secs: int = Field(
        default=10,
        ge=1,
        description="Per-request HTTP timeout when fetching drand rounds",
    )

    @property
    def drand_relay_list(self) -> list[str]:
        """Parsed, deduplicated drand relay base URLs (no trailing slash)."""
        seen: set[str] = set()
        result: list[str] = []
        for raw in self.drand_relays.split(","):
            url = raw.strip().rstrip("/")
            if url and url not in seen:
                seen.add(url)
                result.append(url)
        return result

    # ── Validators ────────────────────────────────────────────────────────────

    @field_validator("ipfs_api_urls")
    @classmethod
    def at_least_one_node(cls, v: str) -> str:
        urls = [u.strip() for u in v.split(",") if u.strip()]
        if not urls:
            raise ValueError("IPFS_API_URLS must contain at least one URL")
        return v

    @field_validator("drand_chain_hash")
    @classmethod
    def chain_hash_is_32_bytes(cls, v: str) -> str:
        try:
            raw = bytes.fromhex(v)
        except ValueError as exc:
            raise ValueError(f"DRAND_CHAIN_HASH must be hex: {exc}")
        if len(raw) != 32:
            raise ValueError(
                f"DRAND_CHAIN_HASH must be exactly 32 bytes (64 hex chars), "
                f"got {len(raw)} bytes"
            )
        return v

    @field_validator("drand_relays")
    @classmethod
    def at_least_one_relay(cls, v: str) -> str:
        urls = [u.strip() for u in v.split(",") if u.strip()]
        if not urls:
            raise ValueError("DRAND_RELAYS must contain at least one URL")
        return v

    @field_validator("manifest_hmac_secret")
    @classmethod
    def reject_placeholder_secret(cls, v: str) -> str:
        """Don't let the env.example placeholder ever make it into a real deploy.

        The min_length=16 check on the field doesn't catch this because the
        placeholder is 28 chars. We need an explicit equality check.
        """
        if v.strip() == _PLACEHOLDER_HMAC_SECRET:
            raise ValueError(
                "MANIFEST_HMAC_SECRET is still the placeholder from env.example. "
                "Generate a real one with:\n"
                "  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
                "and put it in your .env file."
            )
        # Cheap entropy sanity check: a single repeated character is not a key.
        if len(set(v)) < 8:
            raise ValueError(
                "MANIFEST_HMAC_SECRET has too little entropy (< 8 unique chars). "
                "Use `secrets.token_hex(32)` to generate one."
            )
        return v

    @model_validator(mode="after")
    def shamir_defaults_consistent(self) -> "Settings":
        if self.default_k > self.default_n:
            raise ValueError(
                f"DEFAULT_K ({self.default_k}) must be ≤ DEFAULT_N ({self.default_n})"
            )
        if self.default_n > self.max_shards:
            raise ValueError(
                f"DEFAULT_N ({self.default_n}) must be ≤ MAX_SHARDS ({self.max_shards})"
            )
        if self.default_k < self.min_threshold:
            raise ValueError(
                f"DEFAULT_K ({self.default_k}) must be ≥ MIN_THRESHOLD ({self.min_threshold})"
            )
        # drand: agreement threshold must be ≤ number of relays
        if self.drand_agreement_threshold > len(self.drand_relay_list):
            raise ValueError(
                f"DRAND_AGREEMENT_THRESHOLD ({self.drand_agreement_threshold}) "
                f"cannot exceed number of relays ({len(self.drand_relay_list)})"
            )
        return self


# Module-level singleton — import this everywhere
settings = Settings()