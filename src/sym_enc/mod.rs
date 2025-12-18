use std::fmt::Debug;

use blake3::Hasher;

use crate::Error;

/// Trait for symmetric encryption/decryption operations.
///
/// This trait abstracts away the details of symmetric encryption,
/// allowing for flexible implementations (e.g., BLAKE3 XOR, AES-GCM, etc.).
pub trait SymmetricEncryption: Debug + Send + Sync {
    /// Encrypts plaintext with the given secret.
    fn encrypt(&self, secret: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>;

    /// Decrypts ciphertext with the given secret.
    fn decrypt(&self, secret: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
}

/// BLAKE3-based symmetric encryption using XOR.
///
/// This implementation derives a keystream from a secret using BLAKE3's
/// XOF mode and XORs it with the plaintext/ciphertext.
#[derive(Debug, Clone)]
pub struct Blake3XorEncryption {
    /// Domain separation tag for BLAKE3 KDF.
    domain: &'static [u8],
}

impl Blake3XorEncryption {
    /// Creates a new BLAKE3-based encryption with the given domain.
    pub fn new(domain: &'static [u8]) -> Self {
        Self { domain }
    }
}

impl Default for Blake3XorEncryption {
    fn default() -> Self {
        Self::new(b"tess::threshold::payload")
    }
}

impl SymmetricEncryption for Blake3XorEncryption {
    fn encrypt(&self, secret: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }
        let keystream = self.derive_keystream(secret, plaintext.len());
        Ok(xor_bytes(&keystream, plaintext))
    }

    fn decrypt(&self, secret: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.is_empty() {
            return Ok(Vec::new());
        }
        let keystream = self.derive_keystream(secret, ciphertext.len());
        Ok(xor_bytes(&keystream, ciphertext))
    }
}

impl Blake3XorEncryption {
    fn derive_keystream(&self, secret: &[u8], len: usize) -> Vec<u8> {
        if len == 0 {
            return Vec::new();
        }
        let mut hasher = Hasher::new();
        hasher.update(self.domain);
        hasher.update(secret);
        hasher.update(&(len as u64).to_le_bytes());
        let mut reader = hasher.finalize_xof();
        let mut keystream = vec![0u8; len];
        reader.fill(&mut keystream);
        keystream
    }
}

/// XORs two byte slices together.
fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}
