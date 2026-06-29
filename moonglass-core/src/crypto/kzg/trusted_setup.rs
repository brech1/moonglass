//! Ethereum c-kzg trusted setup parser.
//!
//! The only supported setup format is `trusted_setup.txt` from
//! the upstream Ethereum c-kzg trusted setup text.

use std::{num::IntErrorKind, ops::Range, str};

use ark_ec::{AffineRepr, pairing::Pairing};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};

use super::error::SetupFileError;

/// Vendored Ethereum mainnet `trusted_setup.txt` contents.
pub const ETHEREUM_TRUSTED_SETUP_TEXT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/trusted_setup.txt"
));

/// Number of count lines at the start of Ethereum c-kzg setup text.
pub const TEXT_HEADER_LINES: usize = 2;

/// Non-empty setup text line with its one-based source line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupTextLine {
    /// One-based source line number.
    pub line: usize,
    /// Trimmed setup text.
    pub text: String,
}

/// G1 and G2 monomial powers of tau.
pub type PowersOfTau<E> = (Vec<<E as Pairing>::G1Affine>, Vec<<E as Pairing>::G2Affine>);

/// Ethereum c-kzg `trusted_setup.txt`.
///
/// The file starts with two counts:
/// `n` is the number of G1 points in both bases. `m` is the number of G2
/// monomial points.
///
/// The remaining lines are ordered as:
/// `L_i = [ell_i(tau)]_1` gives the G1 lagrange-basis points.
/// `T_i = [tau^i]_2` gives the G2 monomial powers.
/// `M_i = [tau^i]_1` gives the G1 monomial powers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EthereumTrustedSetup<E: Pairing> {
    /// G1 lagrange-basis points from the setup file.
    pub g1_lagrange: Vec<E::G1Affine>,
    /// G2 monomial powers from the setup file.
    pub g2_monomial: Vec<E::G2Affine>,
    /// G1 monomial powers from the setup file.
    pub g1_monomial: Vec<E::G1Affine>,
}

impl<E: Pairing> EthereumTrustedSetup<E> {
    /// Parse Ethereum c-kzg `trusted_setup.txt` contents.
    pub fn parse(text: &str) -> Result<Self, SetupFileError> {
        let lines = setup_text_lines(text);
        if lines.len() < TEXT_HEADER_LINES {
            return Err(SetupFileError::InvalidTextLineCount {
                expected: TEXT_HEADER_LINES,
                got: lines.len(),
            });
        }

        let g1_count = parse_text_count(&lines[0].text, lines[0].line)?;
        let g2_count = parse_text_count(&lines[1].text, lines[1].line)?;

        let expected_lines = g1_count
            .checked_mul(2)
            .and_then(|count| count.checked_add(g2_count))
            .and_then(|count| count.checked_add(TEXT_HEADER_LINES))
            .ok_or(SetupFileError::SizeOverflow)?;
        if lines.len() != expected_lines {
            return Err(SetupFileError::InvalidTextLineCount {
                expected: expected_lines,
                got: lines.len(),
            });
        }

        let g1_lagrange_start = TEXT_HEADER_LINES;
        let g2_monomial_start = g1_lagrange_start
            .checked_add(g1_count)
            .ok_or(SetupFileError::SizeOverflow)?;
        let g1_monomial_start = g2_monomial_start
            .checked_add(g2_count)
            .ok_or(SetupFileError::SizeOverflow)?;
        let g1_monomial_end = g1_monomial_start
            .checked_add(g1_count)
            .ok_or(SetupFileError::SizeOverflow)?;

        // L_i = [ell_i(tau)]_1. These are for evaluation-form blob commitments.
        let g1_lagrange = parse_g1_range::<E>(&lines, g1_lagrange_start..g2_monomial_start)?;

        // T_i = [tau^i]_2. In particular, T_1 = [tau]_2.
        let g2_monomial = parse_g2_range::<E>(&lines, g2_monomial_start..g1_monomial_start)?;

        // M_i = [tau^i]_1. Coefficient-form KZG commitments use these powers:
        // C = sum_i p_i M_i.
        let g1_monomial = parse_g1_range::<E>(&lines, g1_monomial_start..g1_monomial_end)?;

        Ok(Self {
            g1_lagrange,
            g2_monomial,
            g1_monomial,
        })
    }

    /// G1 lagrange-basis powers.
    pub fn g1_lagrange_powers(&self) -> &[E::G1Affine] {
        &self.g1_lagrange
    }

    /// G1 monomial powers `[tau^i]_1`.
    pub fn g1_monomial_powers(&self) -> &[E::G1Affine] {
        &self.g1_monomial
    }

    /// G2 monomial powers `[tau^i]_2`.
    pub fn g2_monomial_powers(&self) -> &[E::G2Affine] {
        &self.g2_monomial
    }

    /// Consume the parsed setup into the monomial powers KZG code uses.
    pub fn into_monomial_powers(self) -> PowersOfTau<E> {
        (self.g1_monomial, self.g2_monomial)
    }
}

/// Parse G1 and G2 monomial powers from Ethereum c-kzg setup bytes.
pub fn get_powers_from_bytes<E: Pairing>(
    file_data: &[u8],
) -> Result<PowersOfTau<E>, SetupFileError> {
    let text = str::from_utf8(file_data).map_err(|e| SetupFileError::InvalidUtf8 {
        valid_up_to: e.valid_up_to(),
        error_len: e.error_len(),
    })?;
    get_powers_from_text::<E>(text)
}

/// Parse G1 and G2 monomial powers from Ethereum c-kzg setup text.
pub fn get_powers_from_text<E: Pairing>(text: &str) -> Result<PowersOfTau<E>, SetupFileError> {
    Ok(EthereumTrustedSetup::<E>::parse(text)?.into_monomial_powers())
}

/// Normalize setup text into trimmed non-empty lines with one-based numbers.
pub fn setup_text_lines(text: &str) -> Vec<SetupTextLine> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim();
            (!trimmed.is_empty()).then(|| SetupTextLine {
                line: index + 1,
                text: trimmed.to_owned(),
            })
        })
        .collect()
}

/// Parse a setup count line.
pub fn parse_text_count(text: &str, line: usize) -> Result<usize, SetupFileError> {
    text.parse::<usize>().map_err(|e| {
        if matches!(
            e.kind(),
            IntErrorKind::PosOverflow | IntErrorKind::NegOverflow
        ) {
            SetupFileError::TextCountOverflow { line }
        } else {
            SetupFileError::InvalidTextCount { line }
        }
    })
}

/// Parse a range of compressed G1 points from setup text lines.
pub fn parse_g1_range<E: Pairing>(
    lines: &[SetupTextLine],
    range: Range<usize>,
) -> Result<Vec<E::G1Affine>, SetupFileError> {
    let element_size = E::G1Affine::generator().serialized_size(Compress::Yes);
    let mut powers = Vec::with_capacity(range.len());

    for index in range {
        let line = lines[index].line;
        let bytes = parse_hex_line(&lines[index].text, line, element_size)?;
        let element = E::G1Affine::deserialize_compressed(bytes.as_slice())
            .map_err(|_| SetupFileError::InvalidG1Point { line })?;
        powers.push(element);
    }

    Ok(powers)
}

/// Parse a range of compressed G2 points from setup text lines.
pub fn parse_g2_range<E: Pairing>(
    lines: &[SetupTextLine],
    range: Range<usize>,
) -> Result<Vec<E::G2Affine>, SetupFileError> {
    let element_size = E::G2Affine::generator().serialized_size(Compress::Yes);
    let mut powers = Vec::with_capacity(range.len());

    for index in range {
        let line = lines[index].line;
        let bytes = parse_hex_line(&lines[index].text, line, element_size)?;
        let element = E::G2Affine::deserialize_compressed(bytes.as_slice())
            .map_err(|_| SetupFileError::InvalidG2Point { line })?;
        powers.push(element);
    }

    Ok(powers)
}

/// Decode one compressed point line from hex.
pub fn parse_hex_line(
    text: &str,
    line: usize,
    expected_bytes: usize,
) -> Result<Vec<u8>, SetupFileError> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    let expected = expected_bytes
        .checked_mul(2)
        .ok_or(SetupFileError::SizeOverflow)?;
    if text.len() != expected {
        return Err(SetupFileError::InvalidHexLength {
            line,
            expected,
            got: text.len(),
        });
    }

    let mut bytes = Vec::with_capacity(expected_bytes);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0], line)?;
        let low = hex_value(pair[1], line)?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

/// Convert one ASCII hex byte to its nibble value.
pub fn hex_value(byte: u8, line: usize) -> Result<u8, SetupFileError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(SetupFileError::InvalidHexCharacter {
            line,
            value: char::from(byte),
        }),
    }
}
