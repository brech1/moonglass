# Moonglass

[![test][test-badge]][actions-url] [![coverage][coverage-badge]][coverage-url] [![docs][docs-badge]][docs-url] [![license][license-badge]][license-url]

[test-badge]: https://github.com/brech1/moonglass/actions/workflows/test.yml/badge.svg
[actions-url]: https://github.com/brech1/moonglass/actions?query=branch%3Amaster
[coverage-badge]: https://codecov.io/gh/brech1/moonglass/branch/master/graph/badge.svg
[coverage-url]: https://codecov.io/gh/brech1/moonglass
[docs-badge]: https://img.shields.io/badge/docs-online-blue
[docs-url]: https://brech1.github.io/moonglass/
[license-badge]: https://img.shields.io/badge/license-AGPL--3.0-blue
[license-url]: https://github.com/brech1/moonglass/blob/master/LICENSE

> [!WARNING]
> Moonglass is experimental.

Moonglass is a Rust implementation of the Ethereum consensus specifications,
built for traceable reading: each consensus path makes clear which object
enters, which rule owns it, what state changes, and where local validation
stops.

The implementation is the engine crate [`moonglass-core`](moonglass-core/):
state transition, fork choice, the in-house SSZ layer (`moonglass_core::ssz`),
crypto (BLS, KZG), typed primitives, constants, and errors. It is pure
consensus, with no I/O. The compile-time preset (`mainnet` / `minimal`) is
selected here. This README is about that engine.

## Workspace

Two accessory crates build on the engine and document themselves:

| Crate | Role |
| --- | --- |
| [`moonglass-node`](moonglass-node/) | Devnet `config.yaml` / genesis loading plus a read-only follower that tracks a live chain's head through the engine. See [`moonglass-node/README.md`](moonglass-node/README.md). |
| [`tests`](tests/) | Consensus-spec reference-test harness, run over `mainnet` and `minimal` lanes. See [`tests/README.md`](tests/README.md). |

## Scope

`moonglass-core` implements:

- State transition and fork choice for the currently live fork.
- Typed consensus objects, constants, and errors that stay close to spec shape.
- The SSZ encoding and the crypto (BLS, KZG) the specs depend on.

It is an engine, not a node. Validator duties, execution-engine driving,
request/response serving, sync, and persistence live outside `moonglass-core`;
[`moonglass-node`](moonglass-node/) adds the network-facing pieces on top.

## Build and test

```bash
cargo build -p moonglass-core                      # the engine
cargo build --workspace                            # the whole workspace
cargo clippy -p moonglass-core --all-targets
```

Correctness is checked against the consensus-spec reference vectors; the runner,
its lanes, and their setup live in [`tests/README.md`](tests/README.md). The
follower and its feature flags live in
[`moonglass-node/README.md`](moonglass-node/README.md).

## Reading model

Start with the state boundary, not the directory tree. `BeaconState` is durable
consensus state, advanced by state transition. `Store` is one node's local
fork-choice view, updated after accepted blocks and messages. `Store::payloads`
is local payload evidence, not an execution-engine verdict. `ForkChoiceNode`
includes payload status because head selection may choose between pending,
empty, and full payload branches.

For any consensus path, ask:

1. What object enters the path?
2. Which rule owns it: state transition, fork choice, or a local verifier?
3. What is read and what is mutated: `BeaconState`, `Store`, both, or neither?
4. What is verified locally, and what external verifier is not modeled?

Useful entry points:

- Blocks: `BeaconState::apply_signed_block`, then `Store::on_block`.
- Payload commitments: `process_execution_payload_bid`,
  `Store::on_execution_payload_envelope`, and
  `process_parent_execution_payload`.
- Votes and head choice: `process_attestation`, `Store::on_attestation`, and
  `Store::get_head`.

## Repository layout

| Path | Role |
| --- | --- |
| `moonglass-core/src/containers/` | SSZ containers carried by consensus paths. |
| `moonglass-core/src/primitives/` | Typed roots, slots, epochs, indices, and checked arithmetic. |
| `moonglass-core/src/constants/` | Consumed protocol constants for the active preset. |
| `moonglass-core/src/ssz/` | In-house SSZ encoding, decoding, and hash-tree-root. |
| `moonglass-core/src/state_transition/` | Slot, epoch, block, operation, and builder processing. |
| `moonglass-core/src/fork_choice/` | Local store updates, filtering, weights, and head selection. |
| `moonglass-core/src/networking.rs` | Fork digests, gossip topics, and request/response protocol ids. |
| `moonglass-core/src/gossip.rs` | Pure gossip and validator-duty predicates. |
| `moonglass-core/src/glossary.rs` | Reading vocabulary, the recommended starting point. |
| `moonglass-core/src/crypto/` | Hashing, BLS, and KZG wrappers. |
| `moonglass-core/src/error/` | Centralized rejection reasons. |

## Documentation standard

Rustdoc is the project documentation surface. Published docs are at
[brech1.github.io/moonglass](https://brech1.github.io/moonglass/).

Library docs should explain protocol ownership, mutations, invariants, and the
boundaries where the code makes those decisions.

The workspace denies missing docs, missing docs in private items, unused code,
dead code, unreachable public items, unsafe code, unescaped rustdoc backticks,
broken intra-doc links, missing cargo metadata, and Clippy `all` and `pedantic`.
The `missing_errors_doc` lint is allowed because error descriptions are
centralized in the error modules.

See [CONTRIBUTING.md](CONTRIBUTING.md) for review, testing, and documentation
policy.

## Contributing

Contribution policy, local checks, and current contribution areas live in
[CONTRIBUTING.md](CONTRIBUTING.md). Consensus changes should include the
matching `tests` adapter and checks when upstream fixtures exist.

## License

Moonglass is licensed under [AGPL-3.0-only](LICENSE).

[consensus-specs]: https://github.com/ethereum/consensus-specs
