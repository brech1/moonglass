# Contributing

Moonglass is a readability-focused implementation of Ethereum consensus.
Contributions should keep behavior clear, traceable, and auditable.

## PR titles

PRs are squash-merged. Your PR title becomes the single commit on `master`, so
it must follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<optional scope>): <subject>
```

CI rejects titles that do not match. The subject starts lowercase and has no
trailing period.

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

A scope is the subsystem the change touches. Useful but not required. Examples:
`fork_choice`, `state_transition`, `reftests`, `crypto`, `primitives`,
`containers`, `constants`, `error`, `docs`, `ci`.

Use lowercase snake_case scopes when a scope is present.

### Examples

```text
feat(fork_choice): add proposer boost reset on slot rollover
fix(state_transition): reject attestation with future target epoch
docs(constants): document bit-40 builder index flag
refactor(epoch): split process_epoch into phase-named helpers
test(primitives): add round-trip for BuilderIndex encoding
chore: bump ssz_rs to 0.10
ci: split required checks by lane
```

Bad examples and why:

```text
Fix bug                       # missing type, capital F, vague subject
feat: Added new helper.       # capital A, trailing period
feat(ForkChoice): ...         # scope should be snake_case
update                        # not a conventional-commit type
```

## Local checks

Before opening a PR, run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
```

For workflow changes, also run:

```bash
SHELLCHECK_OPTS="-S error" actionlint -color
```

Crates and tools outside the main library may document extra checks in their own
README files. Run those when your change touches that code.

Consensus changes also need fixture validation. If upstream consensus-spec
fixtures cover the behavior, add the matching `reftests` adapter and checks,
then run that lane. See [`reftests/README.md`](reftests/README.md).

## Review

Project policy requires **one approving review** before squash merge. The
expected required checks are `lint / lint-required`, `test / test-required`,
`docs / rustdoc`, and `pr-title / conventional-commit`.

## Contribution areas

Useful areas for contributors:

- Wire execution-engine payload validity into the payload evidence path.
- Add blob and data-availability verification.
- Add missing reference-test adapters for upstream fixture families that map to
  implemented Moonglass behavior.
- Expand transition and fork-choice coverage as Moonglass exposes more public
  consensus APIs.
- Evaluate replacing the current `ssz_rs` dependency when the project is ready
  to own that surface.
- Explore Rust-to-Lean generation and formal verification.

Discuss larger scope changes before implementation, especially networking,
sync, validator duties, persistence, and production operations.

## Testing convention

Tests should live as close as practical to the behavior they protect. Prefer
small unit tests for pure parsing, arithmetic, and boundary conditions. Use
higher-level tests when behavior crosses module boundaries or depends on public
API contracts.

Do not add tests that duplicate implementation logic only to assert the same
code path twice. A useful test should make a regression observable from inputs,
outputs, state changes, or a documented error.

When a consensus-spec fixture exists, prefer it through `reftests` over
synthetic harness-only tests.

## Documentation convention

`moonglass` denies `clippy::missing_docs_in_private_items`. Public API items,
private consensus helpers, private scratch structs, and their fields must carry
`///` docs when they live in the library. Use those docs to name protocol
ownership, mutations, invariants, and implementation boundaries. Avoid comments
that only restate obvious control flow.

Error descriptions are centralized in the domain error modules under
`moonglass/src/error*.rs`. Do not add repetitive per-function `# Errors`
sections only to satisfy Clippy. Function docs should explain protocol flow and
local invariants, and only mention a rejection inline when it is essential to
understanding that function.

Do not add per-file or per-item lint attributes for documentation policy. If a
lint truly does not fit the project, make that decision once in Cargo lint
configuration and keep the rationale visible in review.
