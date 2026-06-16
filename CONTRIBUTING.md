# Contributing

Thanks for taking the time. Moonglass is a readability-focused implementation of Ethereum consensus, so contributions should keep behavior clear, traceable, and easy to audit.

## PR titles

PRs are squash-merged. Your PR title becomes the single commit on `master`, so it must follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <subject>
```

CI rejects titles that don't match. Subject starts lowercase, no trailing period.

### Allowed types

| Type | When to use |
| --- | --- |
| `feat` | New behavior or new public API |
| `fix` | Bug fix |
| `docs` | Doc-only change (`///`, `//!`, README) |
| `refactor` | Internal restructure with no behavior change |
| `perf` | Performance improvement |
| `test` | Adding or fixing tests only |
| `chore` | Tooling, dependencies, repo housekeeping |
| `ci` | Workflow or CI configuration |
| `build` | Build system or external build deps |
| `style` | Formatting only (`cargo fmt`, whitespace) |
| `revert` | Revert a previous change |

### Optional scope

A scope is the subsystem the change touches. Useful but not required. Examples: `fork_choice`, `state_transition`, `reftests`, `crypto`, `primitives`, `containers`, `constants`, `error`, `ci`.

### Examples

```
feat(fork_choice): add proposer boost reset on slot rollover
fix(state_transition): reject attestation with future target epoch
docs(constants): document bit-40 builder index flag
refactor(epoch): split process_epoch into phase-named helpers
test(primitives): add round-trip for BuilderIndex encoding
chore: bump ssz_rs to 0.10
ci: cache reftest vectors per consensus-specs tag
```

Bad examples and why:

```
Fix bug                       # missing type, capital F, vague subject
feat: Added new helper.       # capital A, trailing period
feat(ForkChoice): ...         # scope should be lowercase
update                        # not a conventional-commit type
```

## Local checks

Before opening a PR, run:

```
cargo fmt --all -- --check
cargo clippy --workspace --no-default-features --features minimal --all-targets --locked -- -D warnings
cargo test --workspace --no-default-features --features minimal --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-default-features --features minimal --no-deps --document-private-items --locked
cargo run --release --locked -p reftests --no-default-features --features minimal -- --verbose
```

All five must pass cleanly before requesting review. Preset means the
consensus-specs configuration compiled into Moonglass. `minimal` uses the
reduced consensus-spec test constants and is the required CI, coverage, and
published-rustdoc lane. The default `mainnet` preset uses mainnet constants.

For workflow changes, also run:

```
SHELLCHECK_OPTS="-S error" actionlint -color
```

The workspace test command only exercises the `reftests` harness plumbing
today. `moonglass` behavior is tested through the reference fixtures. For
changes that touch preset-specific constants or mainnet-only behavior, also run:

```
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run --release --locked -p reftests -- --verbose
```

Consensus correctness is not checked by unit tests. The CI correctness gate is the consensus-specs reference fixtures on the `minimal` preset.

## Review

Every PR needs **one approving review** before it can be squash-merged. Required checks must be green: `CI / required`, `Docs / minimal rustdoc`, and `PR title / conventional-commit`. For workflow changes, `Workflow lint / actionlint and shellcheck` must also be green.

## Testing convention

The `moonglass` library carries no inline unit tests. Its behavior is checked against the currently wired consensus-spec reference vectors in the `reftests` crate. CI runs the `minimal` preset as the required fixture lane, and unsupported fixture families are not evidence of correctness until an adapter wires them in. When you change transition or fork-choice behavior, the relevant reference-test family is the test.

The `reftests` crate keeps inline `#[cfg(test)] mod tests` blocks for its own plumbing (parsing, hex, manifests). CI runs them, but they exercise the harness crate only, not consensus correctness. See `reftests/src/hex.rs` for the canonical example. New harness helpers should ship with at least one test covering boundary or sentinel behavior.

## Documentation convention

`moonglass` denies `clippy::missing_docs_in_private_items`. Public API items, private consensus helpers, private scratch structs, and their fields must carry `///` docs when they live in the library. Use those docs to name protocol ownership, mutations, invariants, and implementation boundaries. Avoid comments that only restate obvious control flow.

Error descriptions are centralized in the domain error modules under `moonglass/src/error*.rs`. Do not add repetitive per-function `# Errors` sections just to satisfy Clippy. Function docs should explain protocol flow and local invariants, and only mention a rejection inline when it is essential to understanding that function.

Do not add per-file or per-item lint attributes for documentation policy. If a lint truly does not fit the project, make that decision once in Cargo lint configuration and keep the rationale visible in review.
