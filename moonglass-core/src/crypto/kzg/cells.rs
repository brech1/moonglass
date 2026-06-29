//! Cell computation, recovery, and batch proof verification for
//! data-availability sampling.

use std::sync::LazyLock;

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::{BigInteger, FftField, Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};

use crate::constants::{
    BYTES_PER_BLOB, BYTES_PER_CELL, BYTES_PER_FIELD_ELEMENT, CELLS_PER_EXT_BLOB,
    FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL, FIELD_ELEMENTS_PER_EXT_BLOB,
    PRIMITIVE_ROOT_OF_UNITY, RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN,
};
use crate::primitives::{
    Cell, CellIndex, CommitmentIndex, KZG_COMMITMENT_BYTES, KZG_PROOF_BYTES, KZGCommitment,
    KZGProof,
};

use super::{EthereumKzgSetup, KzgError};

/// BLS12-381 scalar field element used by KZG.
pub type BLSFieldElement = Fr;

/// Polynomial coefficients in monomial order.
pub type PolynomialCoeff = Vec<BLSFieldElement>;

/// Evaluation domain for one cell.
pub type Coset = Vec<BLSFieldElement>;

/// Evaluations over one cell coset.
pub type CosetEvals = Vec<BLSFieldElement>;

/// Parsed inputs for the cell KZG batch verifier.
#[derive(Clone)]
pub struct ParsedCellKzgProofBatch {
    /// Deduplicated commitment bytes.
    pub commitments_bytes: Vec<KZGCommitment>,
    /// Deduplicated commitment points.
    pub commitments: Vec<G1Projective>,
    /// Indices into the deduplicated commitment list.
    pub commitment_indices: Vec<CommitmentIndex>,
    /// Cell indices for every proof tuple.
    pub cell_indices: Vec<CellIndex>,
    /// Parsed cell evaluations.
    pub cosets_evals: Vec<CosetEvals>,
    /// Serialized proof bytes.
    pub proofs_bytes: Vec<KZGProof>,
    /// Parsed proof points.
    pub proofs: Vec<G1Projective>,
}

/// Compressed G1 point at infinity.
pub const G1_POINT_AT_INFINITY: [u8; KZG_COMMITMENT_BYTES] = {
    let mut bytes = [0; KZG_COMMITMENT_BYTES];
    bytes[0] = 0xC0;
    bytes
};

/// BLS12-381 scalar-field modulus as big-endian bytes.
pub const BLS_MODULUS_BYTES: [u8; BYTES_PER_FIELD_ELEMENT] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// Hash bytes into the scalar field using the spec's challenge conversion.
pub fn hash_to_bls_field(data: &[u8]) -> BLSFieldElement {
    let hashed_data = Sha256::digest(data);
    Fr::from_be_bytes_mod_order(&hashed_data)
}

/// Convert trusted scalar bytes into a field element.
pub fn bytes_to_bls_field(
    bytes: [u8; BYTES_PER_FIELD_ELEMENT],
) -> Result<BLSFieldElement, KzgError> {
    if bytes >= BLS_MODULUS_BYTES {
        return Err(KzgError::InvalidFieldElement);
    }
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

/// Convert a field element into canonical big-endian bytes.
pub fn bls_field_to_bytes(value: BLSFieldElement) -> [u8; BYTES_PER_FIELD_ELEMENT] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; BYTES_PER_FIELD_ELEMENT];
    out[BYTES_PER_FIELD_ELEMENT - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Validate compressed KZG G1 bytes and return the affine point.
pub fn validate_kzg_g1(bytes: &[u8; KZG_COMMITMENT_BYTES]) -> Result<G1Affine, KzgError> {
    if bytes == &G1_POINT_AT_INFINITY {
        return Ok(G1Affine::zero());
    }
    G1Affine::deserialize_compressed(&bytes[..]).map_err(|_| KzgError::InvalidG1)
}

/// Convert commitment bytes into a validated G1 point.
pub fn bytes_to_kzg_commitment(commitment: KZGCommitment) -> Result<G1Projective, KzgError> {
    Ok(validate_kzg_g1(&commitment.0)?.into_group())
}

/// Convert proof bytes into a validated G1 point.
pub fn bytes_to_kzg_proof(proof: KZGProof) -> Result<G1Projective, KzgError> {
    Ok(validate_kzg_g1(&proof.0)?.into_group())
}

/// Convert a G1 proof point into compressed KZG proof bytes.
pub fn g1_to_kzg_proof(proof: G1Projective) -> Result<KZGProof, KzgError> {
    let affine = proof.into_affine();
    let mut bytes = Vec::with_capacity(KZG_PROOF_BYTES);
    affine
        .serialize_compressed(&mut bytes)
        .map_err(|_| KzgError::InvalidG1)?;
    let bytes = bytes.try_into().map_err(|_: Vec<u8>| KzgError::InvalidG1)?;
    Ok(KZGProof(bytes))
}

/// Convert blob bytes into field evaluations.
pub fn blob_to_polynomial(blob: &[u8]) -> Result<PolynomialCoeff, KzgError> {
    if blob.len() != BYTES_PER_BLOB {
        return Err(KzgError::InvalidBlobLength {
            expected: BYTES_PER_BLOB,
            got: blob.len(),
        });
    }
    let mut polynomial = Vec::with_capacity(FIELD_ELEMENTS_PER_BLOB);
    for chunk in blob.chunks_exact(BYTES_PER_FIELD_ELEMENT) {
        let mut bytes = [0u8; BYTES_PER_FIELD_ELEMENT];
        bytes.copy_from_slice(chunk);
        polynomial.push(bytes_to_bls_field(bytes)?);
    }
    Ok(polynomial)
}

/// Convert a cell into field evaluations over its coset.
pub fn cell_to_coset_evals(cell: Cell) -> Result<CosetEvals, KzgError> {
    let mut evals = Vec::with_capacity(FIELD_ELEMENTS_PER_CELL);
    for chunk in cell.0.chunks_exact(BYTES_PER_FIELD_ELEMENT) {
        let mut bytes = [0u8; BYTES_PER_FIELD_ELEMENT];
        bytes.copy_from_slice(chunk);
        evals.push(bytes_to_bls_field(bytes)?);
    }
    Ok(evals)
}

/// Convert field evaluations back into a serialized cell.
pub fn coset_evals_to_cell(coset_evals: &[BLSFieldElement]) -> Result<Cell, KzgError> {
    if coset_evals.len() != FIELD_ELEMENTS_PER_CELL {
        return Err(KzgError::InvalidCosetLength {
            expected: FIELD_ELEMENTS_PER_CELL,
            got: coset_evals.len(),
        });
    }
    let mut bytes = [0u8; BYTES_PER_CELL];
    for (i, value) in coset_evals.iter().copied().enumerate() {
        let start = i * BYTES_PER_FIELD_ELEMENT;
        bytes[start..start + BYTES_PER_FIELD_ELEMENT].copy_from_slice(&bls_field_to_bytes(value));
    }
    Ok(Cell(bytes))
}

/// Return `x` to the powers `0..n`.
pub fn compute_powers(x: BLSFieldElement, n: usize) -> Vec<BLSFieldElement> {
    let mut current_power = Fr::one();
    let mut powers = Vec::with_capacity(n);
    for _ in 0..n {
        powers.push(current_power);
        current_power *= x;
    }
    powers
}

/// Return roots of unity for the requested order.
pub fn compute_roots_of_unity(order: usize) -> Result<Vec<BLSFieldElement>, KzgError> {
    if order == 0 || !order.is_power_of_two() {
        return Err(KzgError::UnsupportedDomainSize(order));
    }
    let root_of_unity =
        Fr::get_root_of_unity(order as u64).ok_or(KzgError::UnsupportedDomainSize(order))?;
    Ok(compute_powers(root_of_unity, order))
}

/// Reverse the low bits needed to index a sequence of `order` items.
pub fn reverse_bits(value: usize, order: usize) -> usize {
    let bit_count = order.trailing_zeros();
    let mut out = 0usize;
    for i in 0..bit_count {
        out = (out << 1) | ((value >> i) & 1);
    }
    out
}

/// Return a bit-reversal permutation of `values`.
pub fn bit_reversal_permutation<T: Clone>(values: &[T]) -> Vec<T> {
    let mut pairs = values
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, value)| (reverse_bits(index, values.len()), value))
        .collect::<Vec<_>>();
    pairs.sort_by_key(|(index, _)| *index);
    pairs.into_iter().map(|(_, value)| value).collect()
}

/// Compute an FFT or inverse FFT over the supplied root domain.
pub fn fft_field(
    vals: &[BLSFieldElement],
    roots_of_unity: &[BLSFieldElement],
    inv: bool,
) -> Result<Vec<BLSFieldElement>, KzgError> {
    if vals.len() != roots_of_unity.len() {
        return Err(KzgError::LengthMismatch {
            context: "FFT domain",
            expected: vals.len(),
            got: roots_of_unity.len(),
        });
    }
    if vals.is_empty() || !vals.len().is_power_of_two() {
        return Err(KzgError::UnsupportedDomainSize(vals.len()));
    }
    if inv {
        let mut inverse_roots = Vec::with_capacity(roots_of_unity.len());
        inverse_roots.push(roots_of_unity[0]);
        inverse_roots.extend(roots_of_unity[1..].iter().rev().copied());
        let inv_len = BLSFieldElement::from(vals.len() as u64)
            .inverse()
            .ok_or(KzgError::DivisionByZero)?;
        let mut out = fft_field_impl(vals, &inverse_roots);
        for value in &mut out {
            *value *= inv_len;
        }
        Ok(out)
    } else {
        Ok(fft_field_impl(vals, roots_of_unity))
    }
}

/// Recursive radix-2 FFT over field values.
pub fn fft_field_impl(
    vals: &[BLSFieldElement],
    roots_of_unity: &[BLSFieldElement],
) -> Vec<BLSFieldElement> {
    if vals.len() == 1 {
        return vals.to_vec();
    }
    let even_vals = vals.iter().copied().step_by(2).collect::<Vec<_>>();
    let odd_vals = vals.iter().copied().skip(1).step_by(2).collect::<Vec<_>>();
    let even_roots = roots_of_unity
        .iter()
        .copied()
        .step_by(2)
        .collect::<Vec<_>>();
    let left = fft_field_impl(&even_vals, &even_roots);
    let right = fft_field_impl(&odd_vals, &even_roots);
    let mut out = vec![Fr::zero(); vals.len()];
    for (i, (x, y)) in left.iter().copied().zip(right.iter().copied()).enumerate() {
        let y_times_root = y * roots_of_unity[i];
        out[i] = x + y_times_root;
        out[i + left.len()] = x - y_times_root;
    }
    out
}

/// Compute an FFT or inverse FFT over a coset of the supplied root domain.
pub fn coset_fft_field(
    vals: &[BLSFieldElement],
    roots_of_unity: &[BLSFieldElement],
    inv: bool,
) -> Result<Vec<BLSFieldElement>, KzgError> {
    let shift_factor = BLSFieldElement::from(PRIMITIVE_ROOT_OF_UNITY);
    if inv {
        let vals = fft_field(vals, roots_of_unity, true)?;
        shift_vals(
            &vals,
            shift_factor.inverse().ok_or(KzgError::DivisionByZero)?,
        )
    } else {
        let shifted = shift_vals(vals, shift_factor)?;
        fft_field(&shifted, roots_of_unity, false)
    }
}

/// Multiply each value by succeeding powers of `factor`.
pub fn shift_vals(
    vals: &[BLSFieldElement],
    factor: BLSFieldElement,
) -> Result<Vec<BLSFieldElement>, KzgError> {
    let mut shifted = Vec::with_capacity(vals.len());
    let mut shift = Fr::one();
    for value in vals {
        shifted.push(*value * shift);
        shift *= factor;
    }
    Ok(shifted)
}

/// Bit-reversed roots of unity over the extended blob domain, derived once. The
/// per-cell coset helpers index into this rather than rebuilding the
/// [`FIELD_ELEMENTS_PER_EXT_BLOB`]-element table on every call. The build is
/// fallible because the domain root must exist, so a failure is cached and
/// surfaced to callers as an error.
static EXT_ROOTS_OF_UNITY_BRP: LazyLock<Result<Vec<BLSFieldElement>, KzgError>> =
    LazyLock::new(|| {
        compute_roots_of_unity(FIELD_ELEMENTS_PER_EXT_BLOB)
            .map(|roots| bit_reversal_permutation(&roots))
    });

/// Get the coset shift for a cell index.
pub fn coset_shift_for_cell(cell_index: CellIndex) -> Result<BLSFieldElement, KzgError> {
    if cell_index.as_usize() >= CELLS_PER_EXT_BLOB {
        return Err(KzgError::CellIndexOutOfRange {
            index: cell_index.as_u64(),
            limit: CELLS_PER_EXT_BLOB,
        });
    }
    let roots_of_unity_brp = EXT_ROOTS_OF_UNITY_BRP.as_ref().map_err(|err| *err)?;
    Ok(roots_of_unity_brp[FIELD_ELEMENTS_PER_CELL * cell_index.as_usize()])
}

/// Get the full coset for a cell index.
pub fn coset_for_cell(cell_index: CellIndex) -> Result<Coset, KzgError> {
    if cell_index.as_usize() >= CELLS_PER_EXT_BLOB {
        return Err(KzgError::CellIndexOutOfRange {
            index: cell_index.as_u64(),
            limit: CELLS_PER_EXT_BLOB,
        });
    }
    let roots_of_unity_brp = EXT_ROOTS_OF_UNITY_BRP.as_ref().map_err(|err| *err)?;
    let start = FIELD_ELEMENTS_PER_CELL * cell_index.as_usize();
    Ok(roots_of_unity_brp[start..start + FIELD_ELEMENTS_PER_CELL].to_vec())
}

/// Add two coefficient-form polynomials.
pub fn add_polynomialcoeff(a: &[BLSFieldElement], b: &[BLSFieldElement]) -> PolynomialCoeff {
    let len = a.len().max(b.len());
    let mut out = vec![Fr::zero(); len];
    for (i, value) in a.iter().copied().enumerate() {
        out[i] += value;
    }
    for (i, value) in b.iter().copied().enumerate() {
        out[i] += value;
    }
    out
}

/// Multiply two coefficient-form polynomials.
pub fn multiply_polynomialcoeff(a: &[BLSFieldElement], b: &[BLSFieldElement]) -> PolynomialCoeff {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = vec![Fr::zero(); a.len() + b.len() - 1];
    for (i, lhs) in a.iter().copied().enumerate() {
        for (j, rhs) in b.iter().copied().enumerate() {
            out[i + j] += lhs * rhs;
        }
    }
    out
}

/// Divide coefficient-form polynomial `a` by `b`.
pub fn divide_polynomialcoeff(
    a: &[BLSFieldElement],
    b: &[BLSFieldElement],
) -> Result<PolynomialCoeff, KzgError> {
    if b.is_empty() {
        return Err(KzgError::EmptyDivisor);
    }
    let Some(leading_inverse) = b[b.len() - 1].inverse() else {
        return Err(KzgError::DivisionByZero);
    };
    if a.len() < b.len() {
        return Ok(Vec::new());
    }
    let mut remainder = a.to_vec();
    let mut quotient = vec![Fr::zero(); a.len() - b.len() + 1];
    for quotient_index in (0..quotient.len()).rev() {
        let remainder_index = quotient_index + b.len() - 1;
        let quotient_value = remainder[remainder_index] * leading_inverse;
        quotient[quotient_index] = quotient_value;
        for (divisor_index, divisor_value) in b.iter().copied().enumerate() {
            remainder[quotient_index + divisor_index] -= divisor_value * quotient_value;
        }
    }
    Ok(quotient)
}

/// Compute a coefficient-form vanishing polynomial over `xs`.
pub fn vanishing_polynomialcoeff(xs: &[BLSFieldElement]) -> PolynomialCoeff {
    let mut out = vec![Fr::one()];
    for x in xs {
        out = multiply_polynomialcoeff(&out, &[-*x, Fr::one()]);
    }
    out
}

/// Evaluate a coefficient-form polynomial at `z`.
pub fn evaluate_polynomialcoeff(
    polynomial_coeff: &[BLSFieldElement],
    z: BLSFieldElement,
) -> BLSFieldElement {
    let mut y = Fr::zero();
    for coefficient in polynomial_coeff.iter().rev().copied() {
        y = y * z + coefficient;
    }
    y
}

/// Convert blob evaluation form into polynomial coefficient form.
pub fn polynomial_eval_to_coeff(
    polynomial: &[BLSFieldElement],
) -> Result<PolynomialCoeff, KzgError> {
    if polynomial.len() != FIELD_ELEMENTS_PER_BLOB {
        return Err(KzgError::LengthMismatch {
            context: "blob polynomial",
            expected: FIELD_ELEMENTS_PER_BLOB,
            got: polynomial.len(),
        });
    }
    let roots_of_unity = compute_roots_of_unity(FIELD_ELEMENTS_PER_BLOB)?;
    fft_field(&bit_reversal_permutation(polynomial), &roots_of_unity, true)
}

/// Interpolate a polynomial in coefficient form from points and evaluations.
pub fn interpolate_polynomialcoeff(
    xs: &[BLSFieldElement],
    ys: &[BLSFieldElement],
) -> Result<PolynomialCoeff, KzgError> {
    if xs.len() != ys.len() {
        return Err(KzgError::LengthMismatch {
            context: "interpolation",
            expected: xs.len(),
            got: ys.len(),
        });
    }
    let mut out = vec![Fr::zero(); xs.len()];
    for (i, x_i) in xs.iter().copied().enumerate() {
        let mut basis = vec![Fr::one()];
        let mut denominator = Fr::one();
        for (j, x_j) in xs.iter().copied().enumerate() {
            if i == j {
                continue;
            }
            basis = multiply_polynomialcoeff(&basis, &[-x_j, Fr::one()]);
            denominator *= x_i - x_j;
        }
        let denominator_inverse = denominator
            .inverse()
            .ok_or(KzgError::DuplicateInterpolationPoint)?;
        let scale = ys[i] * denominator_inverse;
        for (index, coefficient) in basis.iter().copied().enumerate() {
            out[index] += coefficient * scale;
        }
    }
    Ok(out)
}

/// Linearly combine G1 points with scalar weights.
pub fn g1_lincomb(
    points: &[G1Projective],
    scalars: &[BLSFieldElement],
) -> Result<G1Projective, KzgError> {
    if points.len() != scalars.len() {
        return Err(KzgError::LengthMismatch {
            context: "G1 linear combination",
            expected: points.len(),
            got: scalars.len(),
        });
    }
    if points.is_empty() {
        return Ok(G1Projective::zero());
    }
    let affine_points = G1Projective::normalize_batch(points);
    Ok(G1Projective::msm_unchecked(&affine_points, scalars))
}

/// Linearly combine setup G1 affine powers with scalar weights.
pub fn setup_g1_lincomb(
    setup_g1_affine_powers: &[G1Affine],
    scalars: &[BLSFieldElement],
) -> Result<G1Projective, KzgError> {
    if setup_g1_affine_powers.len() < scalars.len() {
        return Err(KzgError::PolynomialTooLarge {
            coefficients: scalars.len(),
            setup_powers: setup_g1_affine_powers.len(),
        });
    }
    Ok(G1Projective::msm_unchecked(
        &setup_g1_affine_powers[..scalars.len()],
        scalars,
    ))
}

/// Compute a KZG multi-proof and the evaluations for one coset.
pub fn compute_kzg_proof_multi_impl(
    setup: &EthereumKzgSetup,
    polynomial_coeff: &[BLSFieldElement],
    zs: &[BLSFieldElement],
) -> Result<(KZGProof, CosetEvals), KzgError> {
    let ys = zs
        .iter()
        .copied()
        .map(|z| evaluate_polynomialcoeff(polynomial_coeff, z))
        .collect::<Vec<_>>();
    let denominator_poly = vanishing_polynomialcoeff(zs);
    let quotient_polynomial = divide_polynomialcoeff(polynomial_coeff, &denominator_poly)?;
    let proof = setup_g1_lincomb(setup.g1_affine_powers(), &quotient_polynomial)?;
    Ok((g1_to_kzg_proof(proof)?, ys))
}

/// Given a blob, extend it and return all cells of the extended blob.
pub fn compute_cells(blob: &[u8]) -> Result<Vec<Cell>, KzgError> {
    let polynomial = blob_to_polynomial(blob)?;
    let polynomial_coeff = polynomial_eval_to_coeff(&polynomial)?;
    compute_cells_polynomialcoeff(&polynomial_coeff)
}

/// Compute all cells from a coefficient-form polynomial.
pub fn compute_cells_polynomialcoeff(
    polynomial_coeff: &[BLSFieldElement],
) -> Result<Vec<Cell>, KzgError> {
    let mut cells = Vec::with_capacity(CELLS_PER_EXT_BLOB);
    for i in 0..CELLS_PER_EXT_BLOB {
        let coset = coset_for_cell(CellIndex::new(i as u64))?;
        let ys = coset
            .iter()
            .copied()
            .map(|z| evaluate_polynomialcoeff(polynomial_coeff, z))
            .collect::<Vec<_>>();
        cells.push(coset_evals_to_cell(&ys)?);
    }
    Ok(cells)
}

/// Compute all cell proofs for a polynomial in coefficient form.
pub fn compute_cells_and_kzg_proofs_polynomialcoeff(
    setup: &EthereumKzgSetup,
    polynomial_coeff: &[BLSFieldElement],
) -> Result<(Vec<Cell>, Vec<KZGProof>), KzgError> {
    let mut cells = Vec::with_capacity(CELLS_PER_EXT_BLOB);
    let mut proofs = Vec::with_capacity(CELLS_PER_EXT_BLOB);
    for i in 0..CELLS_PER_EXT_BLOB {
        let coset = coset_for_cell(CellIndex::new(i as u64))?;
        let (proof, ys) = compute_kzg_proof_multi_impl(setup, polynomial_coeff, &coset)?;
        cells.push(coset_evals_to_cell(&ys)?);
        proofs.push(proof);
    }
    Ok((cells, proofs))
}

/// Compute all cells and cell proofs for an extended blob.
pub fn compute_cells_and_kzg_proofs(
    setup: &EthereumKzgSetup,
    blob: &[u8],
) -> Result<(Vec<Cell>, Vec<KZGProof>), KzgError> {
    let polynomial = blob_to_polynomial(blob)?;
    let polynomial_coeff = polynomial_eval_to_coeff(&polynomial)?;
    compute_cells_and_kzg_proofs_polynomialcoeff(setup, &polynomial_coeff)
}

/// Construct the vanishing polynomial for missing cell indices.
pub fn construct_vanishing_polynomial(
    missing_cell_indices: &[CellIndex],
) -> Result<Vec<BLSFieldElement>, KzgError> {
    // One factor per missing index yields one more coefficient than there are
    // roots, so the spread write below stays inside the extended blob only when
    // fewer than every cell is missing.
    if missing_cell_indices.len() >= CELLS_PER_EXT_BLOB {
        return Err(KzgError::TooManyCells {
            maximum: CELLS_PER_EXT_BLOB - 1,
            got: missing_cell_indices.len(),
        });
    }
    let roots_of_unity_reduced = compute_roots_of_unity(CELLS_PER_EXT_BLOB)?;
    let roots = missing_cell_indices
        .iter()
        .map(|missing_cell_index| {
            let index = missing_cell_index.as_usize();
            if index >= CELLS_PER_EXT_BLOB {
                return Err(KzgError::CellIndexOutOfRange {
                    index: missing_cell_index.as_u64(),
                    limit: CELLS_PER_EXT_BLOB,
                });
            }
            Ok(roots_of_unity_reduced[reverse_bits(index, CELLS_PER_EXT_BLOB)])
        })
        .collect::<Result<Vec<_>, _>>()?;
    let short_zero_poly = vanishing_polynomialcoeff(&roots);
    let mut zero_poly_coeff = vec![Fr::zero(); FIELD_ELEMENTS_PER_EXT_BLOB];
    for (i, coeff) in short_zero_poly.into_iter().enumerate() {
        zero_poly_coeff[i * FIELD_ELEMENTS_PER_CELL] = coeff;
    }
    Ok(zero_poly_coeff)
}

/// Recover a blob polynomial from at least half of its cells.
pub fn recover_polynomialcoeff(
    cell_indices: Vec<CellIndex>,
    cosets_evals: Vec<CosetEvals>,
) -> Result<PolynomialCoeff, KzgError> {
    if cell_indices.len() != cosets_evals.len() {
        return Err(KzgError::LengthMismatch {
            context: "recovery cells",
            expected: cell_indices.len(),
            got: cosets_evals.len(),
        });
    }
    let roots_of_unity_extended = compute_roots_of_unity(FIELD_ELEMENTS_PER_EXT_BLOB)?;
    let mut extended_evaluation_rbo = vec![Fr::zero(); FIELD_ELEMENTS_PER_EXT_BLOB];
    let mut present = [false; CELLS_PER_EXT_BLOB];
    for (cell_index, cell) in cell_indices.into_iter().zip(cosets_evals) {
        if cell.len() != FIELD_ELEMENTS_PER_CELL {
            return Err(KzgError::InvalidCosetLength {
                expected: FIELD_ELEMENTS_PER_CELL,
                got: cell.len(),
            });
        }
        let index = cell_index.as_usize();
        if index >= CELLS_PER_EXT_BLOB {
            return Err(KzgError::CellIndexOutOfRange {
                index: cell_index.as_u64(),
                limit: CELLS_PER_EXT_BLOB,
            });
        }
        let start = index * FIELD_ELEMENTS_PER_CELL;
        extended_evaluation_rbo[start..start + FIELD_ELEMENTS_PER_CELL].copy_from_slice(&cell);
        present[index] = true;
    }
    let extended_evaluation = bit_reversal_permutation(&extended_evaluation_rbo);
    let missing_cell_indices = (0..CELLS_PER_EXT_BLOB)
        .filter(|cell_index| !present[*cell_index])
        .map(|cell_index| CellIndex::new(cell_index as u64))
        .collect::<Vec<_>>();
    let zero_poly_coeff = construct_vanishing_polynomial(&missing_cell_indices)?;
    let zero_poly_eval = fft_field(&zero_poly_coeff, &roots_of_unity_extended, false)?;
    let extended_evaluation_times_zero = zero_poly_eval
        .iter()
        .copied()
        .zip(extended_evaluation.iter().copied())
        .map(|(a, b)| a * b)
        .collect::<Vec<_>>();
    let extended_evaluation_times_zero_coeffs = fft_field(
        &extended_evaluation_times_zero,
        &roots_of_unity_extended,
        true,
    )?;
    let extended_evaluations_over_coset = coset_fft_field(
        &extended_evaluation_times_zero_coeffs,
        &roots_of_unity_extended,
        false,
    )?;
    let zero_poly_over_coset = coset_fft_field(&zero_poly_coeff, &roots_of_unity_extended, false)?;
    let mut reconstructed_poly_over_coset =
        Vec::with_capacity(extended_evaluations_over_coset.len());
    for (numerator, denominator) in extended_evaluations_over_coset
        .iter()
        .copied()
        .zip(zero_poly_over_coset.iter().copied())
    {
        let denominator_inverse = denominator.inverse().ok_or(KzgError::CosetDivisionByZero)?;
        reconstructed_poly_over_coset.push(numerator * denominator_inverse);
    }
    let reconstructed_poly_coeff = coset_fft_field(
        &reconstructed_poly_over_coset,
        &roots_of_unity_extended,
        true,
    )?;
    Ok(reconstructed_poly_coeff[..FIELD_ELEMENTS_PER_BLOB].to_vec())
}

/// Recover all cells and proofs from at least half of a blob's cells.
pub fn recover_cells_and_kzg_proofs(
    setup: &EthereumKzgSetup,
    cell_indices: Vec<CellIndex>,
    cells: Vec<Cell>,
) -> Result<(Vec<Cell>, Vec<KZGProof>), KzgError> {
    validate_recovery_inputs(&cell_indices, &cells)?;
    let cosets_evals = cells
        .into_iter()
        .map(cell_to_coset_evals)
        .collect::<Result<Vec<_>, _>>()?;
    let polynomial_coeff = recover_polynomialcoeff(cell_indices, cosets_evals)?;
    compute_cells_and_kzg_proofs_polynomialcoeff(setup, &polynomial_coeff)
}

/// Validate recovery preconditions.
pub fn validate_recovery_inputs(
    cell_indices: &[CellIndex],
    cells: &[Cell],
) -> Result<(), KzgError> {
    if cell_indices.len() != cells.len() {
        return Err(KzgError::LengthMismatch {
            context: "recovery inputs",
            expected: cell_indices.len(),
            got: cells.len(),
        });
    }
    let minimum = CELLS_PER_EXT_BLOB / 2;
    if cell_indices.len() < minimum {
        return Err(KzgError::NotEnoughCells {
            minimum,
            got: cell_indices.len(),
        });
    }
    if cell_indices.len() > CELLS_PER_EXT_BLOB {
        return Err(KzgError::TooManyCells {
            maximum: CELLS_PER_EXT_BLOB,
            got: cell_indices.len(),
        });
    }
    let mut previous = None;
    let mut seen = [false; CELLS_PER_EXT_BLOB];
    for cell_index in cell_indices {
        let index = cell_index.as_usize();
        if index >= CELLS_PER_EXT_BLOB {
            return Err(KzgError::CellIndexOutOfRange {
                index: cell_index.as_u64(),
                limit: CELLS_PER_EXT_BLOB,
            });
        }
        if previous.is_some_and(|previous| previous > index) {
            return Err(KzgError::CellIndicesNotSorted);
        }
        if seen[index] {
            return Err(KzgError::DuplicateCellIndex {
                index: cell_index.as_u64(),
            });
        }
        previous = Some(index);
        seen[index] = true;
    }
    Ok(())
}

/// Compute the Fiat-Shamir challenge for batch cell-proof verification.
pub fn compute_verify_cell_kzg_proof_batch_challenge(
    commitments: &[KZGCommitment],
    commitment_indices: &[CommitmentIndex],
    cell_indices: &[CellIndex],
    cosets_evals: &[CosetEvals],
    proofs: &[KZGProof],
) -> BLSFieldElement {
    let mut hashinput = Vec::new();
    hashinput.extend_from_slice(RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN);
    hashinput.extend_from_slice(&(FIELD_ELEMENTS_PER_BLOB as u64).to_be_bytes());
    hashinput.extend_from_slice(&(FIELD_ELEMENTS_PER_CELL as u64).to_be_bytes());
    hashinput.extend_from_slice(&(commitments.len() as u64).to_be_bytes());
    hashinput.extend_from_slice(&(cell_indices.len() as u64).to_be_bytes());
    for commitment in commitments {
        hashinput.extend_from_slice(&commitment.0);
    }
    for (k, coset_evals) in cosets_evals.iter().enumerate() {
        hashinput.extend_from_slice(&commitment_indices[k].as_u64().to_be_bytes());
        hashinput.extend_from_slice(&cell_indices[k].as_u64().to_be_bytes());
        for coset_eval in coset_evals {
            hashinput.extend_from_slice(&bls_field_to_bytes(*coset_eval));
        }
        hashinput.extend_from_slice(&proofs[k].0);
    }
    hash_to_bls_field(&hashinput)
}

/// Verify batch cell KZG proofs from serialized commitments, cells, and proofs.
pub fn verify_cell_kzg_proof_batch(
    setup: &EthereumKzgSetup,
    commitments_bytes: &[KZGCommitment],
    cell_indices: &[CellIndex],
    cells: &[Cell],
    proofs_bytes: &[KZGProof],
) -> Result<bool, KzgError> {
    if commitments_bytes.len() != cell_indices.len()
        || commitments_bytes.len() != cells.len()
        || commitments_bytes.len() != proofs_bytes.len()
    {
        return Err(KzgError::BatchLengthMismatch {
            commitments: commitments_bytes.len(),
            cell_indices: cell_indices.len(),
            cells: cells.len(),
            proofs: proofs_bytes.len(),
        });
    }
    for cell_index in cell_indices {
        if cell_index.as_usize() >= CELLS_PER_EXT_BLOB {
            return Err(KzgError::CellIndexOutOfRange {
                index: cell_index.as_u64(),
                limit: CELLS_PER_EXT_BLOB,
            });
        }
    }

    let mut deduplicated_commitments_bytes = Vec::new();
    let mut deduplicated_commitments = Vec::new();
    let mut commitment_indices = Vec::with_capacity(commitments_bytes.len());
    for commitment_bytes in commitments_bytes {
        if let Some(index) = deduplicated_commitments_bytes
            .iter()
            .position(|stored| stored == commitment_bytes)
        {
            commitment_indices.push(CommitmentIndex::new(index as u64));
            continue;
        }
        let commitment = bytes_to_kzg_commitment(*commitment_bytes)?;
        commitment_indices.push(CommitmentIndex::new(
            deduplicated_commitments_bytes.len() as u64
        ));
        deduplicated_commitments_bytes.push(*commitment_bytes);
        deduplicated_commitments.push(commitment);
    }

    let cosets_evals = cells
        .iter()
        .copied()
        .map(cell_to_coset_evals)
        .collect::<Result<Vec<_>, _>>()?;
    let proofs = proofs_bytes
        .iter()
        .copied()
        .map(bytes_to_kzg_proof)
        .collect::<Result<Vec<_>, _>>()?;

    let batch = ParsedCellKzgProofBatch {
        commitments_bytes: deduplicated_commitments_bytes,
        commitments: deduplicated_commitments,
        commitment_indices,
        cell_indices: cell_indices.to_vec(),
        cosets_evals,
        proofs_bytes: proofs_bytes.to_vec(),
        proofs,
    };

    verify_cell_kzg_proof_batch_impl(setup, &batch)
}

/// Verify batch cell KZG proofs from parsed commitments, cells, and proofs.
pub fn verify_cell_kzg_proof_batch_impl(
    setup: &EthereumKzgSetup,
    batch: &ParsedCellKzgProofBatch,
) -> Result<bool, KzgError> {
    let num_cells = batch.cell_indices.len();
    validate_parsed_commitments(batch)?;
    if batch.commitment_indices.len() != num_cells {
        return Err(KzgError::LengthMismatch {
            context: "commitment indices",
            expected: num_cells,
            got: batch.commitment_indices.len(),
        });
    }
    if batch.cosets_evals.len() != num_cells {
        return Err(KzgError::LengthMismatch {
            context: "coset evaluations",
            expected: num_cells,
            got: batch.cosets_evals.len(),
        });
    }
    if batch.proofs_bytes.len() != num_cells || batch.proofs.len() != num_cells {
        return Err(KzgError::LengthMismatch {
            context: "proofs",
            expected: num_cells,
            got: batch.proofs_bytes.len().min(batch.proofs.len()),
        });
    }
    for commitment_index in &batch.commitment_indices {
        if commitment_index.as_usize() >= batch.commitments.len() {
            return Err(KzgError::CommitmentIndexOutOfRange {
                index: commitment_index.as_u64(),
                commitments: batch.commitments.len(),
            });
        }
    }
    for coset_evals in &batch.cosets_evals {
        if coset_evals.len() != FIELD_ELEMENTS_PER_CELL {
            return Err(KzgError::InvalidCosetLength {
                expected: FIELD_ELEMENTS_PER_CELL,
                got: coset_evals.len(),
            });
        }
    }
    if num_cells == 0 {
        return Ok(true);
    }

    let r = compute_verify_cell_kzg_proof_batch_challenge(
        &batch.commitments_bytes,
        &batch.commitment_indices,
        &batch.cell_indices,
        &batch.cosets_evals,
        &batch.proofs_bytes,
    );
    let r_powers = compute_powers(r, num_cells);

    let ll = g1_lincomb(&batch.proofs, &r_powers)?;
    let lr = setup
        .g2_powers()
        .get(FIELD_ELEMENTS_PER_CELL)
        .copied()
        .ok_or(KzgError::MissingG2Power {
            index: FIELD_ELEMENTS_PER_CELL,
            available: setup.g2_powers().len(),
        })?;

    let mut weights = vec![Fr::zero(); batch.commitments.len()];
    for (k, commitment_index) in batch.commitment_indices.iter().copied().enumerate() {
        weights[commitment_index.as_usize()] += r_powers[k];
    }
    let rlc = g1_lincomb(&batch.commitments, &weights)?;

    let mut sum_interp_polys_coeff = vec![Fr::zero(); FIELD_ELEMENTS_PER_CELL];
    for (k, r_power) in r_powers.iter().copied().enumerate().take(num_cells) {
        let interp_poly_coeff = interpolate_polynomialcoeff(
            &coset_for_cell(batch.cell_indices[k])?,
            &batch.cosets_evals[k],
        )?;
        let interp_poly_scaled_coeff = multiply_polynomialcoeff(&[r_power], &interp_poly_coeff);
        sum_interp_polys_coeff =
            add_polynomialcoeff(&sum_interp_polys_coeff, &interp_poly_scaled_coeff);
    }
    let rli = setup_g1_lincomb(setup.g1_affine_powers(), &sum_interp_polys_coeff)?;

    let mut weighted_r_powers = Vec::with_capacity(num_cells);
    for (k, r_power) in r_powers.iter().copied().enumerate().take(num_cells) {
        let h_k = coset_shift_for_cell(batch.cell_indices[k])?;
        weighted_r_powers.push(r_power * h_k.pow([FIELD_ELEMENTS_PER_CELL as u64]));
    }
    let rlp = g1_lincomb(&batch.proofs, &weighted_r_powers)?;
    let rl = rlc - rli + rlp;

    let lhs = Bls12_381::pairing(ll, lr);
    let rhs = Bls12_381::pairing(rl, G2Affine::generator());
    Ok(lhs == rhs)
}

/// Validate the byte and point views of deduplicated commitments.
pub fn validate_parsed_commitments(batch: &ParsedCellKzgProofBatch) -> Result<(), KzgError> {
    if batch.commitments_bytes.len() != batch.commitments.len() {
        return Err(KzgError::CommitmentBytesLengthMismatch {
            bytes: batch.commitments_bytes.len(),
            points: batch.commitments.len(),
        });
    }

    for (index, (commitment_bytes, commitment)) in batch
        .commitments_bytes
        .iter()
        .copied()
        .zip(batch.commitments.iter().copied())
        .enumerate()
    {
        let parsed = bytes_to_kzg_commitment(commitment_bytes)?;
        if parsed != commitment {
            return Err(KzgError::CommitmentBytesPointMismatch { index });
        }
    }

    Ok(())
}
