//! Adapter for `sanity` reference-test fixtures.
//!
//! `sanity/blocks`, `finality/finality`, and `random/random` all apply a
//! sequence of signed blocks from `blocks_<n>.ssz_snappy`. `sanity/slots`
//! advances the pre-state by the number in `slots.yaml`. Both shapes finish
//! with the common post-state comparison logic.

use moonglass::containers::{BeaconState, SignedBeaconBlock};
use moonglass::primitives::Slot;

use super::{
    Adapter, CaseRunner, Outcome, StateTransition, SupportedHandler, run_state_case,
    trace_block_snapshot, trace_fail, trace_info, trace_pass,
};
use crate::fixtures::{CaseFiles, FixtureFile, FixtureStem};
use crate::inventory::{Case, Runner};

const SLOTS: FixtureFile = FixtureFile::new("slots.yaml");

pub(super) static SANITY_ADAPTER: Adapter<Sanity> = Adapter::new();
pub(super) static FINALITY_ADAPTER: Adapter<Finality> = Adapter::new();
pub(super) static RANDOM_ADAPTER: Adapter<Random> = Adapter::new();

pub(super) struct Sanity;
pub(super) struct Finality;
pub(super) struct Random;

impl CaseRunner for Sanity {
    type Handler = SanityHandler;

    const RUNNER: Runner = Runner::Sanity;

    fn run(case: &Case, handler: Self::Handler) -> Outcome {
        let subject = format!("{}/{}", Self::RUNNER, handler.as_str());
        run_shared(case, handler.shape(), &subject)
    }
}

impl CaseRunner for Finality {
    type Handler = FinalityHandler;

    const RUNNER: Runner = Runner::Finality;

    fn run(case: &Case, _handler: Self::Handler) -> Outcome {
        let subject = format!("{}/{}", Self::RUNNER, FinalityHandler::FINALITY);
        run_shared(case, HandlerShape::Blocks, &subject)
    }
}

impl CaseRunner for Random {
    type Handler = RandomHandler;

    const RUNNER: Runner = Runner::Random;

    fn run(case: &Case, _handler: Self::Handler) -> Outcome {
        let subject = format!("{}/{}", Self::RUNNER, RandomHandler::RANDOM);
        run_shared(case, HandlerShape::Blocks, &subject)
    }
}

#[derive(Clone, Copy)]
enum HandlerShape {
    Blocks,
    Slots,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SanityHandler {
    Blocks,
    Slots,
}

impl SanityHandler {
    const BLOCKS: &'static str = "blocks";
    const SLOTS: &'static str = "slots";

    const fn shape(self) -> HandlerShape {
        match self {
            Self::Blocks => HandlerShape::Blocks,
            Self::Slots => HandlerShape::Slots,
        }
    }
}

impl SupportedHandler for SanityHandler {
    const ALL: &'static [Self] = &[Self::Blocks, Self::Slots];

    fn as_str(self) -> &'static str {
        match self {
            Self::Blocks => Self::BLOCKS,
            Self::Slots => Self::SLOTS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FinalityHandler {
    Finality,
}

impl FinalityHandler {
    const FINALITY: &'static str = "finality";
}

impl SupportedHandler for FinalityHandler {
    const ALL: &'static [Self] = &[Self::Finality];

    fn as_str(self) -> &'static str {
        match self {
            Self::Finality => Self::FINALITY,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RandomHandler {
    Random,
}

impl RandomHandler {
    const RANDOM: &'static str = "random";
}

impl SupportedHandler for RandomHandler {
    const ALL: &'static [Self] = &[Self::Random];

    fn as_str(self) -> &'static str {
        match self {
            Self::Random => Self::RANDOM,
        }
    }
}

/// Sanity, finality, and random runners share the apply-blocks-and-compare shape.
#[must_use]
fn run_shared(case: &Case, shape: HandlerShape, subject: &str) -> Outcome {
    run_state_case(case, subject, |case, state| match shape {
        HandlerShape::Blocks => apply_blocks(case, state),
        HandlerShape::Slots => apply_slots(case, state),
    })
}

fn apply_blocks(case: &Case, state: &mut BeaconState) -> StateTransition {
    let meta = match CaseFiles::new(case).read_meta() {
        Ok(meta) => {
            trace_pass("read meta.yaml", "loaded block-count metadata");
            meta
        }
        Err(e) => {
            let detail = format!("read meta.yaml: {e:#}");
            trace_fail("read meta.yaml", &detail);
            return StateTransition::HarnessError(detail);
        }
    };
    let count = meta
        .blocks_count
        .ok_or_else(|| "meta.yaml missing `blocks_count` for blocks/finality case".to_owned());
    let count = match count {
        Ok(count) => {
            trace_pass("blocks_count", format_args!("{count} blocks"));
            count
        }
        Err(e) => {
            trace_fail("blocks_count", &e);
            return StateTransition::HarnessError(e);
        }
    };
    for i in 0..count {
        let stem = FixtureStem::indexed("blocks", i);
        let block = match CaseFiles::new(case).decode_ssz_snappy_stem::<SignedBeaconBlock>(&stem) {
            Ok(block) => {
                trace_pass(format_args!("decode {stem}"), "decoded signed block");
                trace_block_snapshot(format_args!("{stem} block"), &block.message);
                block
            }
            Err(e) => {
                let detail = format!("decode {stem}: {e:#}");
                trace_fail(format_args!("decode {stem}"), &detail);
                return StateTransition::HarnessError(detail);
            }
        };
        if let Err(e) = state.apply_signed_block(&block) {
            trace_fail(format_args!("apply {stem}"), &e);
            return StateTransition::Applied(Err(e));
        }
        trace_pass(format_args!("apply {stem}"), "block applied");
    }
    StateTransition::Applied(Ok(()))
}

fn apply_slots(case: &Case, state: &mut BeaconState) -> StateTransition {
    let advance: u64 = match CaseFiles::new(case).read_yaml(SLOTS) {
        Ok(advance) => {
            trace_pass(
                format_args!("read {}", SLOTS.as_str()),
                format_args!("advance={advance}"),
            );
            advance
        }
        Err(e) => {
            let detail = format!("read {}: {e}", SLOTS.as_str());
            trace_fail(format_args!("read {}", SLOTS.as_str()), &detail);
            return StateTransition::HarnessError(detail);
        }
    };
    let Some(target_slot) = state.slot.0.checked_add(advance) else {
        let detail = format!(
            "{} advances slot {} by {advance}, which overflows u64",
            SLOTS.as_str(),
            state.slot.0
        );
        trace_fail("process_slots", &detail);
        return StateTransition::HarnessError(detail);
    };
    trace_info(
        "process_slots",
        format_args!("slot {} -> {target_slot}", state.slot.0),
    );
    StateTransition::Applied(state.process_slots(Slot::new(target_slot)))
}
