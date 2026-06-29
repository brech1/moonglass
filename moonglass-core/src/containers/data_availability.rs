//! Data-availability sidecars and validation helpers.

use crate::ssz::prelude::*;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::SignedBeaconBlock;
use crate::constants::{
    DATA_COLUMN_SIDECAR_SUBNET_COUNT, MAX_BLOB_COMMITMENTS_PER_BLOCK, MAX_REQUEST_BLOCKS_DENEB,
    NUMBER_OF_COLUMNS, NUMBER_OF_CUSTODY_GROUPS,
};
use crate::crypto::kzg::{
    EthereumKzgSetup, KzgError, compute_cells_and_kzg_proofs, recover_cells_and_kzg_proofs,
    verify_cell_kzg_proof_batch,
};
use crate::primitives::{
    Cell, CellIndex, ColumnIndex, CustodyIndex, KZGCommitment, KZGProof, NodeId, Root, RowIndex,
    Slot, SubnetId,
};

/// Version byte for partial data-column message group identifiers.
pub const PARTIAL_DATA_COLUMN_GROUP_ID_VERSION: u8 = 0x01;

/// Errors returned by pure data-availability helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DataAvailabilityError {
    /// Requested more custody groups than the protocol defines.
    #[error("requested {requested} custody groups but limit is {limit}")]
    TooManyCustodyGroups {
        /// Requested custody group count.
        requested: u64,
        /// Maximum custody group count.
        limit: u64,
    },

    /// Custody group index exceeds the configured group count.
    #[error("custody group {index} out of range, limit {limit}")]
    CustodyGroupOutOfRange {
        /// Supplied custody group index.
        index: u64,
        /// Exclusive upper bound.
        limit: u64,
    },

    /// Decimal node identifier contained a non-digit byte.
    #[error("node identifier must be a decimal uint256")]
    InvalidNodeIdDecimal,

    /// Decimal node identifier exceeded `uint256`.
    #[error("node identifier exceeds uint256")]
    NodeIdOverflow,

    /// More blob rows were supplied than a sidecar list can carry.
    #[error("too many blob rows: {rows}, limit {limit}")]
    TooManyBlobRows {
        /// Supplied row count.
        rows: usize,
        /// Maximum row count.
        limit: usize,
    },

    /// Cell and proof vectors for one row have different lengths.
    #[error("row {row} cell/proof length mismatch: cells {cells}, proofs {proofs}")]
    CellsProofsLengthMismatch {
        /// Row index.
        row: usize,
        /// Cell count.
        cells: usize,
        /// Proof count.
        proofs: usize,
    },

    /// Cell/proof vectors for one row do not cover every column.
    #[error("row {row} column count mismatch: expected {expected}, cells {cells}, proofs {proofs}")]
    CellsProofsColumnCountMismatch {
        /// Row index.
        row: usize,
        /// Expected column count.
        expected: usize,
        /// Cell count.
        cells: usize,
        /// Proof count.
        proofs: usize,
    },

    /// SSZ serialization failed.
    #[error(transparent)]
    SszSerialize(#[from] SerializeError),

    /// SSZ hash-tree-root computation failed.
    #[error(transparent)]
    Merkleization(#[from] MerkleizationError),
}

/// Column sidecar carrying cells and proofs for a beacon block.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct DataColumnSidecar {
    /// Column index. This is also the cell index for every blob commitment.
    pub index: ColumnIndex,
    /// Cells for this column, one per blob commitment.
    pub column: List<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// KZG proofs for the column cells.
    pub kzg_proofs: List<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// Slot of the beacon block this sidecar belongs to.
    pub slot: Slot,
    /// Root of the beacon block this sidecar belongs to.
    pub beacon_block_root: Root,
}

/// Request identifier for data-column sidecars by block root.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct DataColumnsByRootIdentifier {
    /// Beacon block root to request columns for.
    pub block_root: Root,
    /// Requested column indices.
    pub columns: List<ColumnIndex, NUMBER_OF_COLUMNS>,
}

/// Matrix entry pairing one cell with its proof and coordinates.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatrixEntry {
    /// Cell bytes.
    pub cell: Cell,
    /// KZG proof for the cell.
    pub kzg_proof: KZGProof,
    /// Column coordinate.
    pub column_index: ColumnIndex,
    /// Row coordinate.
    pub row_index: RowIndex,
}

/// Partial column sidecar used by partial-message dissemination.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct PartialDataColumnSidecar {
    /// Bitmap marking which blob rows are present.
    pub cells_present_bitmap: Bitlist<MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// Present cells in bitmap order.
    pub partial_column: List<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// Proofs for present cells in bitmap order.
    pub kzg_proofs: List<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
}

/// Group identifier for partial data-column messages.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialDataColumnGroupID {
    /// Slot of the associated beacon block.
    pub slot: Slot,
    /// Root of the associated beacon block.
    pub beacon_block_root: Root,
}

/// A blob row represented by all extended cells and proofs.
pub type CellsAndKzgProofs = (Vec<Cell>, Vec<KZGProof>);

/// Parse a decimal `uint256` node identifier into little-endian bytes.
pub fn node_id_from_decimal(decimal: &str) -> Result<NodeId, DataAvailabilityError> {
    let mut out = [0u8; 32];
    let trimmed = decimal.trim();
    if trimmed.is_empty() {
        return Err(DataAvailabilityError::InvalidNodeIdDecimal);
    }
    for byte in trimmed.bytes() {
        if !byte.is_ascii_digit() {
            return Err(DataAvailabilityError::InvalidNodeIdDecimal);
        }
        let digit = byte - b'0';
        multiply_node_id_by_10_and_add(&mut out, digit)?;
    }
    Ok(NodeId::from_le_bytes(out))
}

/// Return the custody groups assigned to a node identifier.
pub fn get_custody_groups(
    node_id: NodeId,
    custody_group_count: u64,
) -> Result<Vec<CustodyIndex>, DataAvailabilityError> {
    let group_limit = NUMBER_OF_CUSTODY_GROUPS as u64;
    if custody_group_count > group_limit {
        return Err(DataAvailabilityError::TooManyCustodyGroups {
            requested: custody_group_count,
            limit: group_limit,
        });
    }
    if custody_group_count == group_limit {
        return Ok((0..NUMBER_OF_CUSTODY_GROUPS)
            .map(|index| CustodyIndex::new(index as u64))
            .collect());
    }

    let custody_group_len = usize::try_from(custody_group_count).map_err(|_| {
        DataAvailabilityError::TooManyCustodyGroups {
            requested: custody_group_count,
            limit: group_limit,
        }
    })?;
    let mut current_id = node_id.to_le_bytes();
    let mut custody_groups = Vec::with_capacity(custody_group_len);
    while custody_groups.len() < custody_group_len {
        let digest = Sha256::digest(current_id);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        let custody_group = CustodyIndex::new(u64::from_le_bytes(bytes) % group_limit);
        if !custody_groups.contains(&custody_group) {
            custody_groups.push(custody_group);
        }
        increment_node_id(&mut current_id);
    }
    custody_groups.sort_unstable();
    Ok(custody_groups)
}

/// Return the columns assigned to a custody group.
pub fn compute_columns_for_custody_group(
    custody_group: CustodyIndex,
) -> Result<Vec<ColumnIndex>, DataAvailabilityError> {
    let group_limit = NUMBER_OF_CUSTODY_GROUPS as u64;
    if custody_group.as_u64() >= group_limit {
        return Err(DataAvailabilityError::CustodyGroupOutOfRange {
            index: custody_group.as_u64(),
            limit: group_limit,
        });
    }
    let columns_per_group = NUMBER_OF_COLUMNS / NUMBER_OF_CUSTODY_GROUPS;
    Ok((0..columns_per_group)
        .map(|i| ColumnIndex::new(NUMBER_OF_CUSTODY_GROUPS as u64 * i as u64 + custody_group.0))
        .collect())
}

/// Return the maximum number of data-column sidecars in a request.
pub const fn compute_max_request_data_column_sidecars() -> u64 {
    MAX_REQUEST_BLOCKS_DENEB * NUMBER_OF_COLUMNS as u64
}

/// Return the subnet for a data-column sidecar.
pub const fn compute_subnet_for_data_column_sidecar(column_index: ColumnIndex) -> SubnetId {
    SubnetId::new(column_index.0 % DATA_COLUMN_SIDECAR_SUBNET_COUNT)
}

/// Compute the flattened data-availability matrix for blobs.
pub fn compute_matrix<B: AsRef<[u8]>>(
    setup: &EthereumKzgSetup,
    blobs: &[B],
) -> Result<Vec<MatrixEntry>, KzgError> {
    let mut matrix = Vec::new();
    for (blob_index, blob) in blobs.iter().enumerate() {
        let (cells, proofs) = compute_cells_and_kzg_proofs(setup, blob.as_ref())?;
        for (cell_index, (cell, proof)) in cells.into_iter().zip(proofs).enumerate() {
            matrix.push(MatrixEntry {
                cell,
                kzg_proof: proof,
                column_index: ColumnIndex::new(cell_index as u64),
                row_index: RowIndex::new(blob_index as u64),
            });
        }
    }
    Ok(matrix)
}

/// Recover a full flattened matrix from partial entries.
pub fn recover_matrix(
    setup: &EthereumKzgSetup,
    partial_matrix: &[MatrixEntry],
    blob_count: u64,
) -> Result<Vec<MatrixEntry>, KzgError> {
    let mut matrix = Vec::new();
    for blob_index in 0..blob_count {
        let mut row_entries = partial_matrix
            .iter()
            .copied()
            .filter(|entry| entry.row_index.as_u64() == blob_index)
            .collect::<Vec<_>>();
        row_entries.sort_unstable_by_key(|entry| entry.column_index.as_u64());

        let cell_indices = row_entries
            .iter()
            .map(|entry| CellIndex::new(entry.column_index.as_u64()))
            .collect::<Vec<_>>();
        let cells = row_entries
            .iter()
            .map(|entry| entry.cell)
            .collect::<Vec<_>>();
        let (recovered_cells, recovered_proofs) =
            recover_cells_and_kzg_proofs(setup, cell_indices, cells)?;
        for (cell_index, (cell, proof)) in recovered_cells
            .into_iter()
            .zip(recovered_proofs)
            .enumerate()
        {
            matrix.push(MatrixEntry {
                cell,
                kzg_proof: proof,
                column_index: ColumnIndex::new(cell_index as u64),
                row_index: RowIndex::new(blob_index),
            });
        }
    }
    Ok(matrix)
}

/// Assemble data-column sidecars from blob-row cells and proofs.
pub fn get_data_column_sidecars(
    beacon_block_root: Root,
    slot: Slot,
    cells_and_kzg_proofs: &[CellsAndKzgProofs],
) -> Result<Vec<DataColumnSidecar>, DataAvailabilityError> {
    validate_cells_and_kzg_proofs(cells_and_kzg_proofs)?;

    let mut sidecars = Vec::with_capacity(NUMBER_OF_COLUMNS);
    for column_index in 0..NUMBER_OF_COLUMNS {
        let mut column = List::default();
        let mut kzg_proofs = List::default();
        for (cells, proofs) in cells_and_kzg_proofs {
            column.push(cells[column_index]).map_err(|_| {
                DataAvailabilityError::TooManyBlobRows {
                    rows: cells_and_kzg_proofs.len(),
                    limit: MAX_BLOB_COMMITMENTS_PER_BLOCK,
                }
            })?;
            kzg_proofs.push(proofs[column_index]).map_err(|_| {
                DataAvailabilityError::TooManyBlobRows {
                    rows: cells_and_kzg_proofs.len(),
                    limit: MAX_BLOB_COMMITMENTS_PER_BLOCK,
                }
            })?;
        }
        sidecars.push(DataColumnSidecar {
            index: ColumnIndex::new(column_index as u64),
            column,
            kzg_proofs,
            slot,
            beacon_block_root,
        });
    }
    Ok(sidecars)
}

/// Assemble data-column sidecars using a signed block as the block identifier.
pub fn get_data_column_sidecars_from_block(
    signed_block: &SignedBeaconBlock,
    cells_and_kzg_proofs: &[CellsAndKzgProofs],
) -> Result<Vec<DataColumnSidecar>, DataAvailabilityError> {
    let block = signed_block.message.clone();
    let block_root = Root::from(Merkleized::hash_tree_root(&block)?);
    get_data_column_sidecars(block_root, signed_block.message.slot, cells_and_kzg_proofs)
}

/// Rebuild sidecars from one known sidecar and full blob-row cells and proofs.
pub fn get_data_column_sidecars_from_column_sidecar(
    sidecar: &DataColumnSidecar,
    cells_and_kzg_proofs: &[CellsAndKzgProofs],
) -> Result<Vec<DataColumnSidecar>, DataAvailabilityError> {
    get_data_column_sidecars(
        sidecar.beacon_block_root,
        sidecar.slot,
        cells_and_kzg_proofs,
    )
}

/// Verify the shape of a data column sidecar against block commitments.
pub fn verify_data_column_sidecar(
    sidecar: &DataColumnSidecar,
    kzg_commitments: &List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
) -> bool {
    if sidecar.index.as_usize() >= NUMBER_OF_COLUMNS {
        return false;
    }
    if sidecar.column.is_empty() {
        return false;
    }
    if sidecar.column.len() != kzg_commitments.len() {
        return false;
    }
    if sidecar.column.len() != sidecar.kzg_proofs.len() {
        return false;
    }
    true
}

/// Verify the KZG proofs carried by a data column sidecar.
pub fn verify_data_column_sidecar_kzg_proofs(
    sidecar: &DataColumnSidecar,
    kzg_commitments: &List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    setup: &EthereumKzgSetup,
) -> Result<bool, KzgError> {
    let cell_indices = vec![CellIndex::new(sidecar.index.as_u64()); sidecar.column.len()];
    let commitments = kzg_commitments.iter().copied().collect::<Vec<_>>();
    let cells = sidecar.column.iter().copied().collect::<Vec<_>>();
    let proofs = sidecar.kzg_proofs.iter().copied().collect::<Vec<_>>();
    verify_cell_kzg_proof_batch(setup, &commitments, &cell_indices, &cells, &proofs)
}

/// Verify the shape of a partial data column sidecar.
pub fn verify_partial_data_column_sidecar(
    sidecar: &PartialDataColumnSidecar,
    kzg_commitments: &List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
) -> bool {
    if sidecar.cells_present_bitmap.len() != kzg_commitments.len() {
        return false;
    }
    if sidecar.cells_present_bitmap.count_ones() == 0 {
        return false;
    }
    if sidecar.partial_column.len() != sidecar.kzg_proofs.len() {
        return false;
    }
    if sidecar.partial_column.len() != sidecar.cells_present_bitmap.count_ones() {
        return false;
    }
    true
}

/// Verify KZG proofs for a partial data column sidecar.
pub fn verify_partial_data_column_sidecar_kzg_proofs(
    sidecar: &PartialDataColumnSidecar,
    kzg_commitments: &List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    column_index: ColumnIndex,
    setup: &EthereumKzgSetup,
) -> Result<bool, KzgError> {
    if column_index.as_usize() >= NUMBER_OF_COLUMNS {
        return Ok(false);
    }
    if !verify_partial_data_column_sidecar(sidecar, kzg_commitments) {
        return Ok(false);
    }

    let commitments = kzg_commitments
        .iter()
        .copied()
        .zip(sidecar.cells_present_bitmap.iter().copied())
        .filter_map(|(commitment, present)| present.then_some(commitment))
        .collect::<Vec<_>>();
    let cell_indices = vec![CellIndex::new(column_index.as_u64()); commitments.len()];
    let cells = sidecar.partial_column.iter().copied().collect::<Vec<_>>();
    let proofs = sidecar.kzg_proofs.iter().copied().collect::<Vec<_>>();
    verify_cell_kzg_proof_batch(setup, &commitments, &cell_indices, &cells, &proofs)
}

/// Return the encoded partial data-column group identifier.
pub fn partial_data_column_group_id_bytes(
    group_id: &PartialDataColumnGroupID,
) -> Result<Vec<u8>, DataAvailabilityError> {
    let mut bytes = vec![PARTIAL_DATA_COLUMN_GROUP_ID_VERSION];
    group_id.serialize(&mut bytes)?;
    Ok(bytes)
}

/// Validate cell/proof row shape before sidecar construction.
pub fn validate_cells_and_kzg_proofs(
    cells_and_kzg_proofs: &[CellsAndKzgProofs],
) -> Result<(), DataAvailabilityError> {
    if cells_and_kzg_proofs.len() > MAX_BLOB_COMMITMENTS_PER_BLOCK {
        return Err(DataAvailabilityError::TooManyBlobRows {
            rows: cells_and_kzg_proofs.len(),
            limit: MAX_BLOB_COMMITMENTS_PER_BLOCK,
        });
    }
    for (row, (cells, proofs)) in cells_and_kzg_proofs.iter().enumerate() {
        if cells.len() != proofs.len() {
            return Err(DataAvailabilityError::CellsProofsLengthMismatch {
                row,
                cells: cells.len(),
                proofs: proofs.len(),
            });
        }
        if cells.len() != NUMBER_OF_COLUMNS || proofs.len() != NUMBER_OF_COLUMNS {
            return Err(DataAvailabilityError::CellsProofsColumnCountMismatch {
                row,
                expected: NUMBER_OF_COLUMNS,
                cells: cells.len(),
                proofs: proofs.len(),
            });
        }
    }
    Ok(())
}

/// Multiply a little-endian `uint256` by 10 and add one decimal digit.
pub fn multiply_node_id_by_10_and_add(
    bytes: &mut [u8; 32],
    digit: u8,
) -> Result<(), DataAvailabilityError> {
    let mut carry = u16::from(digit);
    for byte in bytes {
        let next = u16::from(*byte) * 10 + carry;
        #[allow(clippy::cast_possible_truncation)]
        {
            *byte = (next & 0xff) as u8;
        }
        carry = next >> 8;
    }
    if carry != 0 {
        return Err(DataAvailabilityError::NodeIdOverflow);
    }
    Ok(())
}

/// Increment a little-endian `uint256`, wrapping to zero on overflow.
pub fn increment_node_id(bytes: &mut [u8; 32]) {
    for byte in bytes {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

impl SszSized for DataColumnSidecar {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ColumnIndex>(),
            field_layout::<List<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<List<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<Slot>(),
            field_layout::<Root>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ColumnIndex>(),
            field_layout::<List<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<List<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<Slot>(),
            field_layout::<Root>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for DataColumnSidecar {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.index)?;
        encoder.write_field(&self.column)?;
        encoder.write_field(&self.kzg_proofs)?;
        encoder.write_field(&self.slot)?;
        encoder.write_field(&self.beacon_block_root)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for DataColumnSidecar {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ColumnIndex>(),
            field_layout::<List<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<List<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<Slot>(),
            field_layout::<Root>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            index: decoder.deserialize_next::<ColumnIndex>()?,
            column: decoder.deserialize_next::<List<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>>()?,
            kzg_proofs: decoder
                .deserialize_next::<List<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>>()?,
            slot: decoder.deserialize_next::<Slot>()?,
            beacon_block_root: decoder.deserialize_next::<Root>()?,
        })
    }
}

impl Merkleized for DataColumnSidecar {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.index)?,
            Merkleized::hash_tree_root(&self.column)?,
            Merkleized::hash_tree_root(&self.kzg_proofs)?,
            Merkleized::hash_tree_root(&self.slot)?,
            Merkleized::hash_tree_root(&self.beacon_block_root)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for DataColumnSidecar {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for DataColumnsByRootIdentifier {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Root>(),
            field_layout::<List<ColumnIndex, NUMBER_OF_COLUMNS>>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Root>(),
            field_layout::<List<ColumnIndex, NUMBER_OF_COLUMNS>>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for DataColumnsByRootIdentifier {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.block_root)?;
        encoder.write_field(&self.columns)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for DataColumnsByRootIdentifier {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Root>(),
            field_layout::<List<ColumnIndex, NUMBER_OF_COLUMNS>>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            block_root: decoder.deserialize_next::<Root>()?,
            columns: decoder.deserialize_next::<List<ColumnIndex, NUMBER_OF_COLUMNS>>()?,
        })
    }
}

impl Merkleized for DataColumnsByRootIdentifier {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.block_root)?,
            Merkleized::hash_tree_root(&self.columns)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for DataColumnsByRootIdentifier {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for MatrixEntry {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Cell>(),
            field_layout::<KZGProof>(),
            field_layout::<ColumnIndex>(),
            field_layout::<RowIndex>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Cell>(),
            field_layout::<KZGProof>(),
            field_layout::<ColumnIndex>(),
            field_layout::<RowIndex>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for MatrixEntry {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.cell)?;
        encoder.write_field(&self.kzg_proof)?;
        encoder.write_field(&self.column_index)?;
        encoder.write_field(&self.row_index)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for MatrixEntry {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Cell>(),
            field_layout::<KZGProof>(),
            field_layout::<ColumnIndex>(),
            field_layout::<RowIndex>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            cell: decoder.deserialize_next::<Cell>()?,
            kzg_proof: decoder.deserialize_next::<KZGProof>()?,
            column_index: decoder.deserialize_next::<ColumnIndex>()?,
            row_index: decoder.deserialize_next::<RowIndex>()?,
        })
    }
}

impl Merkleized for MatrixEntry {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.cell)?,
            Merkleized::hash_tree_root(&self.kzg_proof)?,
            Merkleized::hash_tree_root(&self.column_index)?,
            Merkleized::hash_tree_root(&self.row_index)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for MatrixEntry {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for PartialDataColumnSidecar {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Bitlist<MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<List<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<List<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Bitlist<MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<List<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<List<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for PartialDataColumnSidecar {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.cells_present_bitmap)?;
        encoder.write_field(&self.partial_column)?;
        encoder.write_field(&self.kzg_proofs)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for PartialDataColumnSidecar {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Bitlist<MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<List<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<List<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            cells_present_bitmap: decoder
                .deserialize_next::<Bitlist<MAX_BLOB_COMMITMENTS_PER_BLOCK>>()?,
            partial_column: decoder
                .deserialize_next::<List<Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK>>()?,
            kzg_proofs: decoder
                .deserialize_next::<List<KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK>>()?,
        })
    }
}

impl Merkleized for PartialDataColumnSidecar {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.cells_present_bitmap)?,
            Merkleized::hash_tree_root(&self.partial_column)?,
            Merkleized::hash_tree_root(&self.kzg_proofs)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for PartialDataColumnSidecar {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for PartialDataColumnGroupID {
    fn is_variable_size() -> bool {
        let fields = [field_layout::<Slot>(), field_layout::<Root>()];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [field_layout::<Slot>(), field_layout::<Root>()];
        container_size_hint(&fields)
    }
}

impl Serialize for PartialDataColumnGroupID {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.slot)?;
        encoder.write_field(&self.beacon_block_root)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for PartialDataColumnGroupID {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [field_layout::<Slot>(), field_layout::<Root>()];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            slot: decoder.deserialize_next::<Slot>()?,
            beacon_block_root: decoder.deserialize_next::<Root>()?,
        })
    }
}

impl Merkleized for PartialDataColumnGroupID {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.slot)?,
            Merkleized::hash_tree_root(&self.beacon_block_root)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for PartialDataColumnGroupID {
    fn is_composite_type() -> bool {
        true
    }
}
