.PHONY: help \
        py-install py-server py-steg py-lint py-fmt \
        rs-build rs-run rs-lint rs-fmt \
        test test-py test-rs \
        keys demo-lock \
        check clean

# ── Default ───────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  VAJRA — Development Commands"
	@echo ""
	@echo "  Python"
	@echo "    make py-install   Install all Python deps via uv"
	@echo "    make py-server    Run FastAPI Source Vault server (hot-reload)"
	@echo "    make py-steg      Run steganography placeholder (python/steg.py)"
	@echo "    make py-lint      Ruff lint + format check"
	@echo "    make py-fmt       Ruff auto-format"
	@echo ""
	@echo "  Rust"
	@echo "    make rs-build     Compile release binary"
	@echo "    make rs-run       Run debug build via cargo run"
	@echo "    make rs-lint      cargo clippy (warnings as errors)"
	@echo "    make rs-fmt       cargo fmt"
	@echo ""
	@echo "  Tests"
	@echo "    make test         Run all tests (Python + Rust)"
	@echo "    make test-py      Run the Python test suite (85 tests)"
	@echo "    make test-rs      Run Rust integration tests"
	@echo ""
	@echo "  Demo"
	@echo "    make keys         Generate 10 example centre keypairs"
	@echo "    make demo-lock    Lock a PDF (PDF=path/to/file.pdf [EXAM_SECS=60])"
	@echo ""
	@echo "  Combined"
	@echo "    make check        cargo check + pyright type check"
	@echo "    make clean        Remove all build artifacts"
	@echo ""

# ── Python ────────────────────────────────────────────────────────────────────

py-install:
	cd python && uv sync

# FastAPI Source Vault server: PDF upload → encrypt → Shamir split → IPFS
# (fastapi dev = development w/ hot-reload; fastapi run = production)
py-server:
	cd python && uv run fastapi dev main.py

# Steganography: placeholder for forensic watermarking — see docs/DEPLOYMENT.md §2.6
py-steg:
	cd python && uv run python steg.py

py-lint:
	cd python && uv run ruff check . && uv run ruff format --check .

py-fmt:
	cd python && uv run ruff format .

# ── Rust ──────────────────────────────────────────────────────────────────────

rs-build:
	cd rust && cargo build --release

rs-run:
	cd rust && cargo run

rs-lint:
	cd rust && cargo clippy -- -D warnings

rs-fmt:
	cd rust && cargo fmt

# ── Tests ─────────────────────────────────────────────────────────────────────

test: test-py test-rs

test-py:
	cd python && uv run pytest tests/ -v

test-rs:
	cd rust && cargo test --release

# ── Demo helpers ──────────────────────────────────────────────────────────────

# Generate 10 example centre keypairs in python/keys/
keys:
	cd python && uv run python vajra_keygen.py bulk --n 10 --out-dir ./keys
	@echo ""
	@echo "  ⚠  python/keys/ contains private keys. It is in .gitignore."
	@echo "  ⚠  Do not commit, share, or upload these files."

# Lock a PDF via the running FastAPI server.
# Usage:  make demo-lock PDF=path/to/exam.pdf [EXAM_SECS=60]
demo-lock:
	@if [ -z "$(PDF)" ]; then \
		echo "Usage: make demo-lock PDF=path/to/file.pdf [EXAM_SECS=60]"; \
		exit 1; \
	fi
	curl -X POST http://127.0.0.1:8000/api/v1/lock \
		-F "file=@$(PDF)" \
		-F "exam_start_seconds=$(or $(EXAM_SECS),60)" \
		| python3 -m json.tool

# ── Combined ──────────────────────────────────────────────────────────────────

check:
	cd rust   && cargo check
	cd python && uv run pyright main.py

clean:
	cd rust   && cargo clean
	cd python && rm -rf __pycache__ .ruff_cache .mypy_cache .pytest_cache
	find python -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
