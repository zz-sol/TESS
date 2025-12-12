use core::fmt::Debug;

use rand_core::RngCore;

use crate::{
    backend::{PairingBackend, PolynomialCommitment},
    config::ThresholdParameters,
    errors::Error,
};

/// Secret key owned by a participant.
#[derive(Clone, Debug)]
pub struct SecretKey<B: PairingBackend> {
    pub scalar: B::Scalar,
}

/// Public metadata used to verify shares and construct the aggregate key.
#[derive(Clone, Debug)]
pub struct PublicKey<B: PairingBackend> {
    pub participant_id: usize,
    pub bls_key: B::G1,
    pub lagrange_li: B::G1,
    pub lagrange_li_minus0: B::G1,
    pub lagrange_li_x: B::G1,
    pub lagrange_li_lj_z: Vec<B::G1>,
}

/// Aggregated key required for encryption and verification of responses.
#[derive(Clone, Debug)]
pub struct AggregateKey<B: PairingBackend> {
    pub public_keys: Vec<PublicKey<B>>,
    pub ask: B::G1,
    pub z_g2: B::G2,
    pub lagrange_row_sums: Vec<B::G1>,
    pub precomputed_pairing: B::Target,
}

/// Ciphertext produced by the silent threshold encryption scheme.
#[derive(Clone, Debug)]
pub struct Ciphertext<B: PairingBackend> {
    pub gamma_g2: B::G2,
    pub proof_g1: Vec<B::G1>,
    pub proof_g2: Vec<B::G2>,
    pub shared_secret: B::Target,
    pub threshold: usize,
}

/// Output of a participant's partial decryption.
#[derive(Clone, Debug)]
pub struct PartialDecryption<B: PairingBackend> {
    pub participant_id: usize,
    pub response: B::G2,
}

/// Bundle returned by key generation.
#[derive(Clone, Debug)]
pub struct KeyMaterial<B: PairingBackend> {
    pub secret_keys: Vec<SecretKey<B>>,
    pub public_keys: Vec<PublicKey<B>>,
    pub aggregate_key: AggregateKey<B>,
    pub kzg_params: <B::PolynomialCommitment as PolynomialCommitment<B>>::Parameters,
}

/// Result produced after aggregation of enough partial decryptions.
#[derive(Clone, Debug)]
pub struct DecryptionResult<B: PairingBackend> {
    pub shared_secret: B::Target,
    pub opening_proof: Option<Vec<u8>>,
}

/// High-level API required by consumers of the scheme.
pub trait ThresholdScheme<B: PairingBackend>: Debug + Send + Sync + 'static {
    /// Generates key material for all parties using the selected backend.
    fn keygen<R: RngCore + ?Sized>(
        &self,
        rng: &mut R,
        params: &ThresholdParameters,
    ) -> Result<KeyMaterial<B>, Error>;

    /// Recomputes the aggregated key from a slice of public keys (e.g. when members are rotated).
    fn aggregate_public_key(
        &self,
        params: &ThresholdParameters,
        public_keys: &[PublicKey<B>],
    ) -> Result<AggregateKey<B>, Error>;

    /// Encrypts a payload with the aggregated key.
    fn encrypt<R: RngCore + ?Sized>(
        &self,
        rng: &mut R,
        agg_key: &AggregateKey<B>,
        params: &ThresholdParameters,
        payload: &[u8],
    ) -> Result<Ciphertext<B>, Error>;

    /// Computes a participant's contribution to the threshold decryption.
    fn partial_decrypt(
        &self,
        secret_key: &SecretKey<B>,
        ciphertext: &Ciphertext<B>,
    ) -> Result<PartialDecryption<B>, Error>;

    /// Aggregates partial decryptions and recovers the shared secret.
    fn aggregate_decrypt(
        &self,
        ciphertext: &Ciphertext<B>,
        partials: &[PartialDecryption<B>],
        selector: &[bool],
        agg_key: &AggregateKey<B>,
    ) -> Result<DecryptionResult<B>, Error>;
}
