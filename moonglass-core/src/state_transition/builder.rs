//! Builder-market transition phases.
//!
//! Covers payload-bid acceptance, builder-payment quorum accounting,
//! payload-timeliness committee voting, builder exits and slashings, and the
//! per-slot pending-payment settlement.

pub mod bids;
pub mod lifecycle;
pub mod payload_attestations;
pub mod payments;
