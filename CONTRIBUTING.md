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
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test -p reftests
cargo build -p moonglass --no-default-features --features minimal
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

All five must pass cleanly. The third runs the reftests crate's own harness tests, which check the test plumbing rather than consensus correctness. The fourth catches breakage of the minimal preset, which CI also exercises. The fifth catches broken intra-doc links in `///` and `//!` comments.

Consensus correctness is not checked by unit tests. The tests are the consensus-specs reference fixtures, which CI runs on the minimal preset. Run them locally with `cargo run --release -p reftests`. Timeouts are reported but do not block merges.

## Review

Every PR needs **one approving review** before it can be squash-merged. CI must be green: `build`, `doc`, `reftests`, and `conventional-commit`.

## Testing convention

The `moonglass` library carries no inline unit tests. Its correctness is covered end to end by the consensus-spec reference vectors in the `reftests` crate, which must stay green on both the `mainnet` and `minimal` presets. When you change transition or fork-choice behavior, the relevant reference-test family is the test.

The `reftests` crate keeps inline `#[cfg(test)] mod tests` blocks for its own plumbing (parsing, hex, manifests). CI runs them, but they exercise the harness crate only, not consensus correctness. See `reftests/src/hex.rs` for the canonical example. New harness helpers should ship with at least one test covering boundary or sentinel behavior.
