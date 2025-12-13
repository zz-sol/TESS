#[cfg(feature = "ark_bls12381")]
use blake3::Hasher;
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
    pub participant_id: usize,
    pub scalar: B::Scalar,
}

/// Public metadata used to verify shares and construct the aggregate key.
#[derive(Debug)]
pub struct PublicKey<B: PairingBackend> {
    pub participant_id: usize,
    pub bls_key: B::G1,
    pub lagrange_li: B::G1,
    pub lagrange_li_minus0: B::G1,
    pub lagrange_li_x: B::G1,
    pub lagrange_li_lj_z: Vec<B::G1>,
}

impl<B: PairingBackend> Clone for PublicKey<B> {
    fn clone(&self) -> Self {
        Self {
            participant_id: self.participant_id,
            bls_key: self.bls_key.clone(),
            lagrange_li: self.lagrange_li.clone(),
            lagrange_li_minus0: self.lagrange_li_minus0.clone(),
            lagrange_li_x: self.lagrange_li_x.clone(),
            lagrange_li_lj_z: self.lagrange_li_lj_z.clone(),
        }
    }
}

/// Aggregated key required for encryption and verification of responses.
#[derive(Clone, Debug)]
pub struct AggregateKey<B: PairingBackend> {
    pub public_keys: Vec<PublicKey<B>>,
    pub ask: B::G1,
    pub z_g2: B::G2,
    pub lagrange_row_sums: Vec<B::G1>,
    pub precomputed_pairing: B::Target,
    pub commitment_params: <B::PolynomialCommitment as PolynomialCommitment<B>>::Parameters,
}

/// Ciphertext produced by the silent threshold encryption scheme.
#[derive(Clone, Debug)]
pub struct Ciphertext<B: PairingBackend> {
    pub gamma_g2: B::G2,
    pub proof_g1: Vec<B::G1>,
    pub proof_g2: Vec<B::G2>,
    pub shared_secret: B::Target,
    pub threshold: usize,
    pub payload: Vec<u8>,
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
    pub plaintext: Option<Vec<u8>>,
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

#[cfg(feature = "ark_bls12381")]
const PAYLOAD_KDF_DOMAIN: &[u8] = b"TESS::threshold::payload";

#[cfg(feature = "ark_bls12381")]
use crate::backend::TargetGroup;

#[cfg(feature = "ark_bls12381")]
fn derive_keystream<B: PairingBackend>(secret: &B::Target, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    let mut hasher = Hasher::new();
    hasher.update(PAYLOAD_KDF_DOMAIN);
    let repr = secret.to_repr();
    hasher.update(repr.as_ref());
    hasher.update(&(len as u64).to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut keystream = vec![0u8; len];
    reader.fill(&mut keystream);
    keystream
}

#[cfg(feature = "ark_bls12381")]
fn xor_with_keystream(data: &[u8], keystream: &[u8]) -> Vec<u8> {
    data.iter()
        .zip(keystream.iter())
        .map(|(byte, key)| byte ^ key)
        .collect()
}

#[cfg(feature = "ark_bls12381")]
fn encrypt_payload<B: PairingBackend>(secret: &B::Target, payload: &[u8]) -> Vec<u8> {
    let keystream = derive_keystream::<B>(secret, payload.len());
    xor_with_keystream(payload, &keystream)
}

#[cfg(feature = "ark_bls12381")]
fn decrypt_payload<B: PairingBackend>(secret: &B::Target, ciphertext: &[u8]) -> Vec<u8> {
    let keystream = derive_keystream::<B>(secret, ciphertext.len());
    xor_with_keystream(ciphertext, &keystream)
}

#[cfg(feature = "ark_bls12381")]
pub mod arkworks;

#[cfg(feature = "ark_bls12381")]
pub use arkworks::*;
