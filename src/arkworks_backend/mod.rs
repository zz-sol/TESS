use ark_ff::PrimeField;
use rand_core::RngCore;

fn sample_field<F: PrimeField, R: RngCore + ?Sized>(rng: &mut R) -> F {
    let mut bytes = vec![0u8; ((F::MODULUS_BIT_SIZE + 7) / 8) as usize];
    rng.fill_bytes(&mut bytes);
    F::from_le_bytes_mod_order(&bytes)
}

#[cfg(feature = "ark_bls12381")]
mod bls12_381;
#[cfg(feature = "ark_bn254")]
mod bn254;

#[cfg(feature = "ark_bls12381")]
pub use bls12_381::*;
#[cfg(feature = "ark_bn254")]
pub use bn254::*;
