# reftests

Conformance runner for moonglass against the generated fixtures published on
the hardcoded [`ethereum/consensus-specs`](https://github.com/ethereum/consensus-specs)
release tag.

## Usage

CI runs the minimal preset as the required reference-test lane:

```bash
cargo run --release --locked -p reftests --no-default-features --features minimal -- --verbose
```

Local two-preset runs use the default `mainnet` entry point. The runner runs
wired mainnet fixtures plus shared `general` fixtures, then builds and runs
wired minimal fixtures from a separate target directory so the two feature
presets do not unify:

```bash
cargo build --release -p reftests
target/release/reftests
```

Discovery runs every fixture family currently wired to Moonglass adapters.
Unsupported upstream families are reported as skipped, but they do not affect
pass/fail totals or the runner exit status.

The release tag and fixture target live in code as constants. Users do not pass
tags, configs, filters, or subcommands.

The runner auto-fetches the hardcoded test-vector release into
`reftests/vectors/` when the required fixtures are missing.

The default release runner exits `0` only when both presets match at least one
wired case and every matched case passes.
