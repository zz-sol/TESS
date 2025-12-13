use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};
use std::time::Instant;

use tess::{
    ThresholdScheme,
    config::{BackendConfig, BackendId, CurveId, ThresholdParameters},
    protocol::{ProtocolBackend, ProtocolScalar, SilentThreshold},
};

#[cfg(feature = "ark_bls12381")]
use tess::ArkworksBls12;
#[cfg(feature = "ark_bn254")]
use tess::ArkworksBn254;
#[cfg(feature = "blst")]
use tess::BlstBackend;

const PARTIES: usize = 1 << 11; // 16
const THRESHOLD: usize = 3;

fn run_threshold_example<B>(
    backend_name: &str,
    backend_config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>>
where
    B: ProtocolBackend,
    B::Scalar: ProtocolScalar,
{
    let mut rng = StdRng::seed_from_u64(42);
    let scheme = SilentThreshold::<B>::default();
    let params = ThresholdParameters {
        parties: PARTIES,
        threshold: THRESHOLD,
        chunk_size: 32,
        backend: backend_config,
        kzg_tau: None,
    };

    println!("\n== {} ==", backend_name);
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut executed = 0;

    #[cfg(feature = "blst")]
    {
        run_threshold_example::<BlstBackend>(
            "blst (BLS12-381)",
            BackendConfig::new(BackendId::Blst, CurveId::Bls12_381),
        )?;
        executed += 1;
    }

    #[cfg(feature = "ark_bls12381")]
    {
        run_threshold_example::<ArkworksBls12>(
            "arkworks (BLS12-381)",
            BackendConfig::new(BackendId::Arkworks, CurveId::Bls12_381),
        )?;
        executed += 1;
    }

    #[cfg(feature = "ark_bn254")]
    {
        run_threshold_example::<ArkworksBn254>(
            "arkworks (BN254)",
            BackendConfig::new(BackendId::Arkworks, CurveId::Bn254),
        )?;
        executed += 1;
    }

    if executed == 0 {
        eprintln!(
            "Enable at least one backend feature (e.g., `--features blst`) to run the example."
        );
    }

    Ok(())
}
