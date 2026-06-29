//! SSZ merkleization helpers.

use std::sync::LazyLock;

use sha2::{Digest, Sha256};

use super::{BYTES_PER_CHUNK, DeserializeError, MerkleizationError, Node};

/// Merkleize roots as a vector of already-rooted chunks.
pub fn merkleize_roots(roots: &[Node]) -> Node {
    merkleize_roots_unchecked(roots, roots.len())
}

/// Merkleize roots, padding up to `limit`.
pub fn merkleize_roots_with_limit(
    roots: &[Node],
    limit: usize,
) -> Result<Node, MerkleizationError> {
    if roots.len() > limit {
        return Err(MerkleizationError::ListTooLong {
            len: roots.len(),
            limit,
        });
    }
    Ok(merkleize_roots_unchecked(roots, limit))
}

/// Merkleize roots after the caller has checked length against `limit`.
pub fn merkleize_roots_unchecked(roots: &[Node], limit: usize) -> Node {
    let height = tree_depth_for_limit(limit.max(1));

    if roots.is_empty() {
        return ZERO_HASHES[height];
    }

    let mut depth = 0usize;
    let mut nodes = roots.to_vec();
    while nodes.len() > 1 {
        if !nodes.len().is_multiple_of(2) {
            nodes.push(ZERO_HASHES[depth]);
        }
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
        depth += 1;
    }

    let mut root = nodes[0];
    while depth < height {
        root = hash_pair(root, ZERO_HASHES[depth]);
        depth += 1;
    }
    root
}

/// Merkleize packed serialized basic bytes.
pub fn merkleize_byte_sequence(bytes: &[u8]) -> Node {
    merkleize_byte_sequence_unchecked(bytes, bytes.len())
}

/// Merkleize packed serialized basic bytes, padding to a byte limit.
pub fn merkleize_byte_sequence_with_limit(
    bytes: &[u8],
    byte_limit: usize,
) -> Result<Node, MerkleizationError> {
    if bytes.len() > byte_limit {
        return Err(MerkleizationError::ListTooLong {
            len: bytes.len(),
            limit: byte_limit,
        });
    }
    Ok(merkleize_byte_sequence_unchecked(bytes, byte_limit))
}

/// Merkleize packed serialized basic bytes after checking the byte limit.
pub fn merkleize_byte_sequence_unchecked(bytes: &[u8], byte_limit: usize) -> Node {
    let chunk_limit = chunk_count(byte_limit).max(1);
    merkleize_roots_unchecked(&pack_bytes(bytes), chunk_limit)
}

/// Mix a list length into a merkle root.
pub fn mix_in_length(root: Node, length: usize) -> Node {
    let mut length_chunk = [0u8; BYTES_PER_CHUNK];
    length_chunk[..8].copy_from_slice(&(length as u64).to_le_bytes());
    hash_pair(root, Node(length_chunk))
}

/// Number of 32-byte chunks required to cover `bytes`.
pub const fn chunk_count(bytes: usize) -> usize {
    bytes.div_ceil(BYTES_PER_CHUNK)
}

/// Maximum SSZ tree height the cached zero-hash table spans.
///
/// SSZ list and vector limits stay well under `2**64` elements, so a height of
/// 64 covers every tree depth a merkleization can reach.
pub const MAX_TREE_HEIGHT: usize = 64;

/// SSZ zero-subtree hashes from leaf depth through [`MAX_TREE_HEIGHT`], derived
/// once. Callers index into this rather than rebuilding the chain with SHA256 on
/// every merkleization.
pub static ZERO_HASHES: LazyLock<[Node; MAX_TREE_HEIGHT + 1]> = LazyLock::new(|| {
    let mut table = [Node::default(); MAX_TREE_HEIGHT + 1];
    for depth in 1..=MAX_TREE_HEIGHT {
        let node = table[depth - 1];
        table[depth] = hash_pair(node, node);
    }
    table
});

/// Pack bytes into 32-byte SSZ chunks.
pub fn pack_bytes(bytes: &[u8]) -> Vec<Node> {
    if bytes.is_empty() {
        return vec![Node::default()];
    }
    bytes
        .chunks(BYTES_PER_CHUNK)
        .map(|chunk| {
            let mut out = [0u8; BYTES_PER_CHUNK];
            out[..chunk.len()].copy_from_slice(chunk);
            Node(out)
        })
        .collect()
}

/// Hash two SSZ chunks into their parent node.
pub fn hash_pair(left: Node, right: Node) -> Node {
    let mut hasher = Sha256::new();
    hasher.update(left.0);
    hasher.update(right.0);
    let digest = hasher.finalize();
    let mut bytes = [0u8; BYTES_PER_CHUNK];
    bytes.copy_from_slice(&digest);
    Node(bytes)
}

/// Return the depth needed to cover `limit` leaves.
pub const fn tree_depth_for_limit(limit: usize) -> usize {
    if limit <= 1 {
        0
    } else {
        (usize::BITS - (limit - 1).leading_zeros()) as usize
    }
}

/// Decode exactly `N` bytes.
pub fn deserialize_fixed_bytes<const N: usize>(
    encoding: &[u8],
) -> Result<[u8; N], DeserializeError> {
    if encoding.len() < N {
        return Err(DeserializeError::ExpectedFurtherInput {
            provided: encoding.len(),
            expected: N,
        });
    }
    if encoding.len() > N {
        return Err(DeserializeError::AdditionalInput {
            provided: encoding.len(),
            expected: N,
        });
    }

    let mut bytes = [0u8; N];
    bytes.copy_from_slice(encoding);
    Ok(bytes)
}

/// Return the hash-tree-root node for an SSZ basic value.
pub fn basic_root(bytes: &[u8]) -> Result<Node, MerkleizationError> {
    if bytes.len() > BYTES_PER_CHUNK {
        return Err(MerkleizationError::BasicValueTooLong {
            len: bytes.len(),
            limit: BYTES_PER_CHUNK,
        });
    }

    let mut out = [0u8; BYTES_PER_CHUNK];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(Node(out))
}
