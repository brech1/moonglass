# moonglass-node

`moonglass-node` runs [`moonglass-core`](../moonglass-core/) against a real
devnet. It parses a `config.yaml` into a typed `ChainConfig`, loads a
genesis/anchor `GenesisBundle`, and, behind feature flags, hosts a read-only
follower that feeds gossip into the engine's fork choice to track the chain head.

The default build is just the config and genesis library; the network-facing
parts are feature-gated.

## Features

| Feature | Adds |
| --- | --- |
| _default_ | `ChainConfig` parsing and `GenesisBundle` loading. No extra dependencies. |
| `follower` | The engine seam: gossip decode, topic dispatch, fork-choice handlers, and a replay-driven correctness oracle. Adds only `snap`. |
| `node` | The live transport: a libp2p swarm, discv5 discovery, the follow loop, a consensus-client checkpoint fetch, and the runnable binary. Adds the async networking stack (libp2p, discv5, tokio, futures) plus reqwest and tracing. |

The preset (`mainnet` / `minimal`) is inherited from `moonglass-core` and is
orthogonal to these features.

## The follower

The follower is the smallest thing that runs the engine against a live network:
it anchors at a checkpoint, subscribes to the chain's gossip, and feeds each
message through fork choice. Every piece is a permanent part of the node, not
throwaway scaffolding.

- **Engine seam (`follower`).** `codec` handles snappy (raw block, used by both
  gossip and fixtures); `topics` builds the subscribe set for a fork digest;
  `dispatch` maps a topic to a decoded container and the owning fork-choice
  handler; `replay` drives a captured message stream offline and verifies the
  head. `anchor`, `clock`, and `runtime` bridge to a live session.
- **Transport (`node`).** `node/network` builds the libp2p swarm and consensus
  gossipsub (anonymous validation, content message id, a 10 MiB limit);
  `node/discovery` runs discv5 and forwards discovered peers as dial targets;
  `node/run` is the loop that ticks the clock and routes each gossip message
  through the seam. Blocks apply their embedded attestations and aggregate
  attestations feed fork-choice weight, so the head reflects votes.
- **Execution boundary.** Payload execution validity is an injected
  `ExecutionPayloadVerifier`. The follower accepts all payloads, so a recorded
  payload is consensus-checked, not engine-confirmed; a real engine verifier
  slots into the same seam later.
- **Anchor rule.** Moonglass models a single live fork, so the follower anchors
  at a checkpoint already inside that fork's range, never a pre-fork genesis.
  `anchor::adopt_checkpoint` enforces this.

## Running the node

```bash
cargo run -p moonglass-node --features node -- \
    config.yaml genesis.ssz http://localhost:5052 \
    /ip4/0.0.0.0/tcp/9000 9000 5053 <bootnode-enr> ...
```

The follower reads `config.yaml` and `genesis.ssz` from the launcher, fetches the
finalized checkpoint state and block from the consensus client at the given URL,
anchors on it, then listens on the multiaddr, discovers peers over discv5 on the
UDP port, subscribes to the chain's gossip, and logs the head each slot.
`RUST_LOG` controls verbosity.

## Build and test

```bash
cargo build  -p moonglass-node                       # default: config and genesis only
cargo test   -p moonglass-node --no-default-features --features minimal,follower
cargo clippy -p moonglass-node --features node --all-targets
```

## Status

The engine seam, the replay oracle, and the libp2p + discv5 transport with the
runnable binary are all in place and build on both presets. It is not yet
verified against a live devnet. Deferred refinements: per-subnet attestation
topics, request/response sync, peer filtering by fork digest, and a real
execution-engine verifier.
