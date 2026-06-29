//! Slot timing for a follower, sharing the fork-choice store's clock.
//!
//! The store keeps time in whole seconds and derives slots from the compile-time
//! [`SLOT_DURATION_MS`]. [`SlotClock`] uses that same constant and genesis time,
//! so the live loop decides when to tick and which slot a wall-clock time falls
//! in with the exact arithmetic the store uses internally, and the two can never
//! disagree.

use moonglass_core::constants::SLOT_DURATION_MS;
use moonglass_core::fork_choice::helpers::seconds_to_milliseconds;

/// Converts between Unix seconds and slot numbers for one genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotClock {
    /// Genesis time in Unix seconds.
    pub genesis_time: u64,
}

impl SlotClock {
    /// A clock anchored at `genesis_time` (Unix seconds).
    pub fn new(genesis_time: u64) -> Self {
        Self { genesis_time }
    }

    /// The slot that `unix_time` falls in.
    pub fn slot_at(&self, unix_time: u64) -> u64 {
        seconds_to_milliseconds(unix_time.saturating_sub(self.genesis_time)) / SLOT_DURATION_MS
    }

    /// The Unix second at which `slot` opens.
    pub fn slot_start_unix(&self, slot: u64) -> u64 {
        self.genesis_time
            .saturating_add(slot.saturating_mul(SLOT_DURATION_MS) / 1_000)
    }

    /// The Unix second at which the slot after `unix_time` opens.
    pub fn next_slot_start_unix(&self, unix_time: u64) -> u64 {
        self.slot_start_unix(self.slot_at(unix_time).saturating_add(1))
    }
}

/// Current Unix time in whole seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}
