# reftests

`reftests` is an accessory crate that runs Moonglass against generated
[`ethereum/consensus-specs`](https://github.com/ethereum/consensus-specs)
fixtures. It is not part of the `moonglass` library API.

The crate owns fixture discovery, vector-cache management, adapter dispatch,
process isolation, terminal output, and trace rendering. Consensus behavior must
still live in `moonglass`. Adapters translate fixture files into calls on
Moonglass and compare the result with the fixture.

## Quick Start

Run the CI-required minimal lane:

```bash
cargo build --release -p reftests --no-default-features --features minimal
target/release/reftests-minimal
```

Run the mainnet lane, including shared `general` fixtures:

```bash
cargo build --release -p reftests
target/release/reftests
```

Run both lanes explicitly:

```bash
cargo build --release -p reftests --no-default-features --features minimal
target/release/reftests-minimal

cargo build --release -p reftests
target/release/reftests
```

The lanes build separate binaries. `target/release/reftests` is the
mainnet-plus-general runner. `target/release/reftests-minimal` is the minimal
runner. Keeping them separate prevents a minimal build from replacing the
mainnet runner.

## CLI

Runtime syntax:

```text
reftests [--nocapture] [NAME ...] [-- NAME ...]
```

`NAME` values are substring filters over full case display names. A case runs
when any supplied pattern is contained in its display name.

Examples:

```bash
target/release/reftests get_head
target/release/reftests eth_aggregate_pubkeys_empty_list
target/release/reftests pyspec_tests/skipped_slots
target/release/reftests --nocapture get_head
target/release/reftests-minimal genesis
```

Output always uses ANSI colors.

## Output

Default output is one line per executed case, a failed-case name list when any
case fails, then a summary. Unsupported fixture families are reported after the
run as ignored fixture inventory, separate from executed pass/fail totals.

`--nocapture` enables and prints a compact trace for every executed case. Use it
with a name filter when debugging a failure:

```bash
target/release/reftests-minimal failing_case_name --nocapture
```

The trace focuses on execution data:

- fixture setup and decode steps
- state transition or fork-choice steps
- individual checks and expected rejection notes
- captured stdout/stderr from the isolated worker
- elapsed time

Normal runs do not collect or serialize traces. That keeps full-lane validation
close to `cargo test` behavior and reserves detailed logs for explicit local
debugging.

## Vectors

The consensus-specs release tag and target fork are constants in code. The
runtime CLI does not accept release tags, forks, presets, or runner subcommands.
Select the lane with Cargo features at build time, then run the matching binary
from `target/release/`.

When required fixtures are missing, the runner downloads the configured release
archives into `reftests/vectors/`. The cache is local working data and is not
part of the source tree.

Unfiltered runs enforce the pinned fixture inventory for the active lane. This
catches upstream vector-surface drift before execution. Filtered runs skip that
global inventory check so local debugging is not blocked by unrelated fixture
families.

## Architecture

The crate is split around the runner boundary:

| Path | Role |
| --- | --- |
| `src/bin/` | Thin binaries for the mainnet and minimal lanes. |
| `src/lib.rs` | Library entry point and configured consensus-specs target. |
| `src/harness/` | CLI parsing, isolated workers, terminal reports, and traces. |
| `src/inventory/` | Fixture discovery, skipped-family accounting, and pinned coverage validation. |
| `src/vectors/` | Release archive download, extraction, hashing, and cache location. |
| `src/fixtures/` | Manifest validation, fixture-file loading, SSZ/YAML helpers, and diffs. |
| `src/adapters/` | Fixture adapters that call Moonglass and compare expected results. |

Each case runs in a child process. That keeps panics and accidental process
state from leaking into the rest of the lane while preserving deterministic
serial output.

## Adapter Rules

Adapters are glue code. They should:

- decode real fixture files
- call public Moonglass APIs
- compare Moonglass results with fixture expectations
- emit useful trace events for `--nocapture`
- keep unsupported upstream families out of the runnable inventory

Adapters should not:

- reimplement consensus algorithms inside `reftests`
- mock cryptography, state transition, or fork-choice behavior
- invent synthetic fixture formats when an actual consensus-spec fixture exists
- mark a handler supported before the corresponding Moonglass behavior exists

If a needed behavior is private in Moonglass, expose the smallest sensible
Moonglass API first, then call it from the adapter.

## Development Checks

For harness changes, run:

```bash
cargo test -p reftests
cargo test -p reftests --no-default-features --features minimal
cargo clippy -p reftests --all-targets -- -D warnings
cargo clippy -p reftests --no-default-features --features minimal --all-targets -- -D warnings
```

For full fixture validation, run both release lanes:

```bash
cargo build --release -p reftests --no-default-features --features minimal
target/release/reftests-minimal

cargo build --release -p reftests
target/release/reftests
```

The mainnet lane can be slow. Some fixtures advance many slots or exercise
large SSZ containers.
