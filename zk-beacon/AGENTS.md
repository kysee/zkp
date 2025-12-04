# Repository Guidelines

## Project Structure & Module Organization
- Go module root lives at `../go.mod`; run tooling from the repo root or target this package with the `./zk-beacon` import path.
- Circuits live in `circuit/` (`block_root.go`, `bls_verifier.go`, `sc_verifier.go`) and define gnark constraints for beacon block roots and sync-committee BLS verification.
- Top-level `*_test.go` files exercise the circuits end-to-end; JSON fixtures (`curr-sc.json`, `lcupdate.json`) provide Holesky sync committee data.
- `.created/` caches compiled circuits and Groth16 keys; they regenerate automatically if missing but are large, so avoid churn unless you intend to recompile.

## Build, Test, and Development Commands
```bash
cd .. && go test ./zk-beacon/...            # Run all tests for this package
cd .. && go test ./zk-beacon -run TestName  # Target a specific test
gofmt -w circuit/*.go *_test.go             # Format before committing
```
- Tests will compile circuits and may write updated `.css/.pk/.vk` artifacts into `.created/`; delete that directory to force a clean rebuild.

## Coding Style & Naming Conventions
- Use `gofmt` (tabs, Go standard ordering); prefer `goimports` if available to group imports.
- Follow Go naming: exported identifiers in `CamelCase`, locals in `lowerCamelCase`; keep the package name `zk_beacon` for tests and `circuit` for constraints.
- Keep circuits deterministic: avoid random sources, panic only on irrecoverable setup failures, and comment non-obvious constraint wiring.
- Place fixtures or generated data beside the tests that use them; prefer hex-encoded bytes for reproducibility.

## Testing Guidelines
- Frameworks: Go `testing` with `testify/require` for assertions; gnark’s Groth16 prover/verifier runs in tests.
- Tests expect Holesky parameters (fork version `0x90000075`, genesis root in `verify_bls_aggr_test.go`); update fixtures and assertions together when network values change.
- Name tests with `TestXxx` and keep proofs deterministic by reusing fixtures; add focused tests for new constraints or hashing paths.
- When altering circuits, remove `.created` to ensure proving/verifying keys are regenerated and re-checked in CI/local runs.

## Commit & Pull Request Guidelines
- Commit history follows Conventional Commit prefixes (`feat: ...`, `fix: ...`); keep messages imperative and scoped.
- PRs should describe what changed, why, and how to validate (commands run, regenerated assets noted). Link issues and mention fixture updates or large artifact changes.
- Include screenshots/log snippets only when they clarify proof generation or performance notes; avoid committing secrets or unreproducible binary blobs.
