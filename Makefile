.PHONY: help \
        py-install py-server py-steg py-lint \
        rs-add rs-build rs-run rs-lint \
        check clean

# ── Default ───────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  VAJRA — Development Commands"
	@echo ""
	@echo "  Python"
	@echo "    make py-install   Install all Python deps via uv"
	@echo "    make py-server    Run FastAPI ingestion server (hot-reload)"
	@echo "    make py-steg      Run steganography CLI (python/steg.py)"
	@echo "    make py-lint      Ruff lint + format check"
	@echo ""
	@echo "  Rust"
	@echo "    make rs-add       cargo add all required dependencies"
	@echo "    make rs-build     Compile release binary"
	@echo "    make rs-run       Run debug build via cargo run"
	@echo "    make rs-lint      cargo clippy"
	@echo ""
	@echo "  Combined"
	@echo "    make check        cargo check + pyright type check"
	@echo "    make clean        Remove all build artifacts"
	@echo ""

# ── Python ────────────────────────────────────────────────────────────────────

py-install:
	cd python && uv sync

# FastAPI ingestion server: PDF upload → shard → encrypt → IPFS
py-server:
	cd python && uv run fastapi run main.py --reload

# Steganography: watermark a decrypted PDF with center metadata
py-steg:
	cd python && uv run python steg.py

py-lint:
	cd python && uv run ruff check . && uv run ruff format --check .

# ── Rust ──────────────────────────────────────────────────────────────────────

# Run this ONCE after cloning to install all Cargo dependencies
rs-add:
	cd rust && \
	cargo add clap --features derive && \
	cargo add serde --features derive && \
	cargo add serde_json && \
	cargo add num-bigint --features rand && \
	cargo add num-traits && \
	cargo add rand && \
	cargo add aes-gcm && \
	cargo add sha2 && \
	cargo add hex

rs-build:
	cd rust && cargo build --release

rs-run:
	cd rust && cargo run

rs-lint:
	cd rust && cargo clippy -- -D warnings

# ── Combined ──────────────────────────────────────────────────────────────────

check:
	cd rust   && cargo check
	cd python && uv run pyright main.py

clean:
	cd rust   && cargo clean
	cd python && rm -rf __pycache__ .ruff_cache .mypy_cache