//! Gossip-facing containers with consensus-defined SSZ shapes.

use crate::primitives::{BLSSignature, ExecutionAddress, Root, Slot, ValidatorIndex};
use crate::ssz::prelude::*;

/// Proposer's execution-payload preferences for a future proposal slot.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposerPreferences {
    /// Dependent block root for the proposer lookahead.
    pub dependent_root: Root,
    /// Slot the preferences apply to.
    pub proposal_slot: Slot,
    /// Validator expected to propose at `proposal_slot`.
    pub validator_index: ValidatorIndex,
    /// Preferred execution-layer fee recipient.
    pub fee_recipient: ExecutionAddress,
    /// Preferred execution payload gas limit.
    pub target_gas_limit: u64,
}

/// Signed proposer preferences gossip object.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedProposerPreferences {
    /// Preferences being signed.
    pub message: ProposerPreferences,
    /// Validator signature over `message`.
    pub signature: BLSSignature,
}

impl SszSized for ProposerPreferences {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Root>(),
            field_layout::<Slot>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<u64>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Root>(),
            field_layout::<Slot>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<u64>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for ProposerPreferences {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.dependent_root)?;
        encoder.write_field(&self.proposal_slot)?;
        encoder.write_field(&self.validator_index)?;
        encoder.write_field(&self.fee_recipient)?;
        encoder.write_field(&self.target_gas_limit)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for ProposerPreferences {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Root>(),
            field_layout::<Slot>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<u64>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            dependent_root: decoder.deserialize_next::<Root>()?,
            proposal_slot: decoder.deserialize_next::<Slot>()?,
            validator_index: decoder.deserialize_next::<ValidatorIndex>()?,
            fee_recipient: decoder.deserialize_next::<ExecutionAddress>()?,
            target_gas_limit: decoder.deserialize_next::<u64>()?,
        })
    }
}

impl Merkleized for ProposerPreferences {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.dependent_root)?,
            Merkleized::hash_tree_root(&self.proposal_slot)?,
            Merkleized::hash_tree_root(&self.validator_index)?,
            Merkleized::hash_tree_root(&self.fee_recipient)?,
            Merkleized::hash_tree_root(&self.target_gas_limit)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for ProposerPreferences {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SignedProposerPreferences {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ProposerPreferences>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ProposerPreferences>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SignedProposerPreferences {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.message)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SignedProposerPreferences {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ProposerPreferences>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            message: decoder.deserialize_next::<ProposerPreferences>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SignedProposerPreferences {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.message)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SignedProposerPreferences {
    fn is_composite_type() -> bool {
        true
    }
}
