#[cfg(feature = "ark_bls12381")]
use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};
#[cfg(feature = "ark_bls12381")]
use std::time::Instant;

#[cfg(feature = "ark_bls12381")]
fn run_arkworks_example() -> Result<(), Box<dyn std::error::Error>> {
    use tess::ThresholdScheme;
    use tess::config::{BackendConfig, BackendId, CurveId, ThresholdParameters};
    use tess::protocol::ark_bls12_381::SilentThresholdScheme;

    const PARTIES: usize = 1 << 4; // 2048
    const THRESHOLD: usize = 3;

    let mut rng = StdRng::seed_from_u64(42);
    let scheme = SilentThresholdScheme::default();
    let params = ThresholdParameters {
        parties: PARTIES,
        threshold: THRESHOLD,
        chunk_size: 32,
        backend: BackendConfig::new(BackendId::Arkworks, CurveId::Bls12_381),
        kzg_tau: None,
    };

    let keygen_start = Instant::now();
    let key_material = scheme.keygen(&mut rng, &params)?;
    println!(
        "Key generation for {} parties (threshold {}): {:?}",
        PARTIES,
        THRESHOLD,
        keygen_start.elapsed()
    );

    let message = vec![0u8; params.chunk_size];
    let enc_start = Instant::now();
    let ciphertext = scheme.encrypt(&mut rng, &key_material.aggregate_key, &params, &message)?;
    println!("Encryption time: {:?}", enc_start.elapsed());

    let mut selector = vec![false; PARTIES];
    let mut signer_ids: Vec<usize> = (0..PARTIES).collect();
    signer_ids.shuffle(&mut rng);
    let chosen = &signer_ids[..=THRESHOLD];

    let mut partials = Vec::with_capacity(chosen.len());
    for &idx in chosen {
        selector[idx] = true;
        let partial = scheme.partial_decrypt(&key_material.secret_keys[idx], &ciphertext)?;
        partials.push(partial);
    }

    let dec_start = Instant::now();
    let result = scheme.aggregate_decrypt(
        &ciphertext,
        &partials,
        &selector,
        &key_material.aggregate_key,
    )?;
    println!("Aggregate decryption time: {:?}", dec_start.elapsed());
    println!(
        "Recovered plaintext matches: {} (len = {})",
        result.plaintext.as_deref() == Some(message.as_slice()),
        result
            .plaintext
            .as_ref()
            .map(|p| p.len())
            .unwrap_or_default()
    );

    Ok(())
}

#[cfg(feature = "ark_bls12381")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_arkworks_example()
}

#[cfg(not(feature = "ark_bls12381"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Enable the `ark_bls12381` feature to run the threshold benchmark example.");
    Ok(())
}
