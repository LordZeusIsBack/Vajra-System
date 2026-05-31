# Contributing to VAJRA

Thank you for the interest. Contributions are welcome with the
understanding that VAJRA is a small prototype maintained by one person.

## What's most valuable

In rough order of impact:

1. **Cryptographic audit findings.** If you can identify a weakness in
   the protocol or its implementation, open an issue. Be specific about
   the attack and what the attacker is assumed to be able to do. Replies
   may take a few days; non-trivial findings will be acknowledged in
   release notes.

2. **Documentation clarity.** If something in the README, ARCHITECTURE,
   or DEPLOYMENT docs is unclear or wrong, open an issue or a PR. The
   goal is that a non-cryptographer policymaker can read the docs and
   understand what's claimed and what isn't.

3. **Test coverage.** The current suite is 85 tests. Edge cases at
   the boundary between Python and Rust, on Windows specifically, and
   under partial-network conditions are under-covered.

4. **Bug reports with reproduction steps.** A clear bug report is
   worth a lot. Include the command you ran, the expected output, the
   actual output, and the contents of your `.env` (with the HMAC
   secret redacted, obviously).

## What's not in scope

- **Restructuring the repository.** The current layout is what
  ARCHITECTURE.md and DEPLOYMENT.md reference. Reorganising for taste
  introduces bugs and breaks external links. Save it for v0.2.

- **Switching cryptographic primitives without discussion.** RSW,
  Shamir, X25519, ChaCha20-Poly1305, drand — these are deliberate
  choices documented in ARCHITECTURE.md. Proposing a switch is fine;
  doing it without an issue first is not.

- **Production deployment guides.** The system is not ready for
  production. Writing such guides is misleading. See DEPLOYMENT.md
  for what would actually need to happen first.

## How to submit a PR

1. Fork the repo, create a feature branch off `main`.
2. Make the change. Keep the diff focused — one logical change per PR.
3. Add tests if you're touching code. `make test` must still pass.
4. Run the linters: `make py-lint rs-lint`.
5. Update the relevant docs if your change is user-visible.
6. Open a PR with a clear description of *what* and *why*.

By contributing code, you agree to license your contribution under
Apache 2.0, the same license as the rest of the project.

## Code style

- **Python:** ruff handles formatting and lint. Defaults from `pyproject.toml`.
- **Rust:** `rustfmt` defaults; `cargo clippy` clean.
- **Docstrings:** Real ones, in the style of the existing code. Document
  the *why*, not the *what* — the code is the what.
- **Commit messages:** Imperative present tense ("Add X" not "Added X"),
  explain why the change is being made in the body if it's not obvious.

## Contact

For questions that don't fit GitHub issues:

- Email: anubhavsharma5645@gmail.com

I'll respond when I can. Allow a few days.
