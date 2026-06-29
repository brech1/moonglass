//! KZG setup material and constructors.

use ark_bls12_381::Bls12_381;
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::Field;

use super::error::SetupFileError;
use super::trusted_setup::{ETHEREUM_TRUSTED_SETUP_TEXT, PowersOfTau, get_powers_from_text};

/// Ethereum's BLS12-381 KZG setup type.
pub type EthereumKzgSetup = KzgSetup<Bls12_381>;

/// KZG setup material.
///
/// For a secret `tau`, the structured reference string contains:
/// G1 powers `[tau^i]_1` and G2 powers `[tau^i]_2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgSetup<E: Pairing> {
    /// G1 powers of tau as projective points for FK operations.
    pub g1_powers: Vec<E::G1>,
    /// G1 powers of tau as affine points for MSM commitment operations.
    pub g1_affine_powers: Vec<E::G1Affine>,
    /// G2 powers of tau as projective points for proof verification.
    pub g2_powers: Vec<E::G2>,
    /// The `[tau]_2` point used to verify KZG openings.
    pub tau_g2: E::G2,
}

impl<E> KzgSetup<E>
where
    E: Pairing,
{
    /// Build setup material from Ethereum c-kzg trusted-setup text.
    pub fn from_trusted_setup_text(text: &str) -> Result<Self, SetupFileError> {
        Self::from_monomial_powers(get_powers_from_text::<E>(text)?)
    }

    /// Build setup material from parsed monomial powers.
    pub fn from_monomial_powers(
        (g1_affine_powers, g2_affine_powers): PowersOfTau<E>,
    ) -> Result<Self, SetupFileError> {
        // `[tau]_2` is the second G2 point because the monomial block starts with `[1]_2`.
        let tau_g2 = g2_affine_powers
            .get(1)
            .copied()
            .ok_or(SetupFileError::MissingTauG2)?
            .into_group();

        let g1_powers = g1_affine_powers
            .iter()
            .copied()
            .map(AffineRepr::into_group)
            .collect();
        let g2_powers = g2_affine_powers
            .iter()
            .copied()
            .map(AffineRepr::into_group)
            .collect();

        Ok(Self {
            g1_powers,
            g1_affine_powers,
            g2_powers,
            tau_g2,
        })
    }

    /// Build setup material from an explicit secret for controlled experiments.
    pub fn setup(secret: E::ScalarField, powers: usize) -> Self {
        let g1_generator = E::G1Affine::generator();
        let mut tau_power = E::ScalarField::ONE;
        let mut g1_powers = Vec::with_capacity(powers);

        // [tau^i]_1 = tau^i * [1]_1 for every supported coefficient index i.
        for _ in 0..powers {
            g1_powers.push(g1_generator * tau_power);
            tau_power *= secret;
        }

        // Keep affine powers for MSM and projective powers for FK convolution.
        let g1_affine_powers = E::G1::normalize_batch(&g1_powers);

        let g2_generator = E::G2Affine::generator();
        let mut tau_power = E::ScalarField::ONE;
        let mut g2_powers = Vec::with_capacity(powers);
        for _ in 0..powers {
            g2_powers.push(g2_generator * tau_power);
            tau_power *= secret;
        }

        // [tau]_2 = tau * [1]_2.
        let tau_g2 = g2_generator * secret;

        Self {
            g1_powers,
            g1_affine_powers,
            g2_powers,
            tau_g2,
        }
    }

    /// Build setup material from G1 powers and a G2 tau point.
    pub fn from_g1_affine_powers(g1_affine_powers: Vec<E::G1Affine>, tau_g2: E::G2) -> Self {
        let g1_powers = g1_affine_powers
            .iter()
            .copied()
            .map(AffineRepr::into_group)
            .collect();
        let g2_powers = vec![E::G2Affine::generator().into_group(), tau_g2];

        Self {
            g1_powers,
            g1_affine_powers,
            g2_powers,
            tau_g2,
        }
    }

    /// Powers of tau in G1 as projective points.
    pub fn g1_powers(&self) -> &[E::G1] {
        &self.g1_powers
    }

    /// Powers of tau in G1 as affine points.
    pub fn g1_affine_powers(&self) -> &[E::G1Affine] {
        &self.g1_affine_powers
    }

    /// Powers of tau in G2 as projective points.
    pub fn g2_powers(&self) -> &[E::G2] {
        &self.g2_powers
    }

    /// Tau in G2.
    pub fn tau_g2(&self) -> E::G2 {
        self.tau_g2
    }
}

impl KzgSetup<Bls12_381> {
    /// Load the vendored Ethereum mainnet KZG trusted setup.
    pub fn mainnet() -> Result<Self, SetupFileError> {
        Self::from_trusted_setup_text(ETHEREUM_TRUSTED_SETUP_TEXT)
    }
}
