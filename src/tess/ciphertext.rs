use core::fmt::Debug;

use crate::PairingBackend;

/// Ciphertext output from threshold encryption.
///
/// This structure contains the encrypted payload along with KZG proofs
/// that enable threshold decryption and verification.
#[derive(Clone, Debug)]
pub struct Ciphertext<B: PairingBackend> {
    pub gamma_g2: B::G2,
    pub proof_g1: Vec<B::G1>,
    pub proof_g2: Vec<B::G2>,
    pub shared_secret: B::Target,
    pub threshold: usize,
    pub payload: Vec<u8>,
}

/// Partial decryption share from a single participant.
///
/// Each participant uses their secret key to compute a partial decryption.
/// At least `t` partial decryptions are required to recover the plaintext.
#[derive(Debug)]
pub struct PartialDecryption<B: PairingBackend> {
    pub participant_id: usize,
    pub response: B::G2,
}

impl<B: PairingBackend> Clone for PartialDecryption<B> {
    fn clone(&self) -> Self {
        Self {
            participant_id: self.participant_id,
            response: self.response,
        }
    }
}

/// Decryption result containing the recovered plaintext.
///
/// This structure is returned after successfully aggregating at least `t`
/// partial decryptions.
#[derive(Clone, Debug)]
pub struct DecryptionResult {
    pub plaintext: Option<Vec<u8>>,
}
