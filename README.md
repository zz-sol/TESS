# TESS: Threshold Encryption with Silent Setup

[![Crates.io](https://img.shields.io/crates/v/tess.svg)](https://crates.io/crates/tess)
[![Documentation](https://docs.rs/tess/badge.svg)](https://docs.rs/tess)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

A production-grade Rust implementation of threshold encryption with silent (non-interactive) setup based on Knowledge of Exponent (KZG) commitments.

## Overview

Threshold encryption allows a message to be encrypted such that it can only be decrypted when at least `t` out of `n` participants cooperate. TESS implements this using a **silent setup**, meaning the initial setup does not require interactive communication between participants.

### Key Features

- **Non-interactive Setup**: Silent setup eliminates the need for participant coordination during initialization
- **KZG-based**: Leverages Knowledge of Exponent commitments for efficient polynomial operations
- **Multiple Backend Support**: Choose between BLS12-381 (via blstrs or Arkworks) and BN254 (via Arkworks)
- **High Performance**: Parallelized operations using Rayon for MSM, key generation, and FFT
- **Type-Safe**: Strongly typed API with compile-time backend selection
- **Production Ready**: Comprehensive error handling and instrumentation support

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
tess = "0.1"
```

### Feature Flags

TESS supports multiple cryptographic backends:

- **`blst`** (default): blstrs backend for BLS12-381 - fastest and recommended for production
- **`ark_bls12381`**: Arkworks backend for BLS12-381 - more portable, pure Rust
- **`ark_bn254`**: Arkworks backend for BN254 - alternative curve option

To use a different backend:

```toml
[dependencies]
tess = { version = "0.1", default-features = false, features = ["ark_bls12381"] }
```

## Quick Start

```rust
use rand::thread_rng;
use tess::{PairingEngine, SilentThresholdScheme, ThresholdEncryption};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    // Configuration
    const PARTIES: usize = 100;
    const THRESHOLD: usize = 67; // Need 67 out of 100 to decrypt

    // Initialize the scheme
    let scheme = SilentThresholdScheme::<PairingEngine>::new();

    // 1. Generate parameters (one-time trusted setup)
    let params = scheme.param_gen(&mut rng, PARTIES, THRESHOLD)?;

    // 2. Generate keys for all participants
    let key_material = scheme.keygen(&mut rng, PARTIES, &params)?;

    // 3. Encrypt a message
    let message = b"Secret message that requires threshold decryption";
    let ciphertext = scheme.encrypt(
        &mut rng,
        &key_material.aggregate_key,
        &params,
        THRESHOLD,
        message,
    )?;

    // 4. Collect partial decryptions from THRESHOLD + 1 participants
    let share_count = THRESHOLD + 1;
    let mut selector = vec![false; PARTIES];
    let mut partials = Vec::new();

    for i in 0..share_count {
        selector[i] = true;
        let partial = scheme.partial_decrypt(
            &key_material.secret_keys[i],
            &ciphertext,
        )?;
        partials.push(partial);
    }

    // 5. Aggregate and decrypt
    let result = scheme.aggregate_decrypt(
        &ciphertext,
        &partials,
        &selector,
        &key_material.aggregate_key,
    )?;

    // Verify decryption
    assert_eq!(result.plaintext.unwrap(), message);

    Ok(())
}
```

## How It Works

### Protocol Workflow

1. **SRS Generation** (`param_gen`): Generate a Structured Reference String using a trusted setup. This produces KZG commitment parameters and precomputed Lagrange polynomial commitments.

2. **Key Generation** (`keygen`): Each participant generates a secret key share and corresponding public key with Lagrange commitment hints. Keys are generated independently without interaction.

3. **Key Aggregation**: Public keys are combined to create an aggregate public key used for encryption.

4. **Encryption** (`encrypt`): Messages are encrypted using the aggregate public key, producing a ciphertext with KZG proof and BLAKE3-encrypted payload.

5. **Partial Decryption** (`partial_decrypt`): Each participant creates a decryption share using their secret key.

6. **Aggregate Decryption** (`aggregate_decrypt`): Combine at least `t` partial decryptions to recover the plaintext using Lagrange interpolation.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Protocol Layer (tess/)                │
│  ThresholdEncryption trait, Keys, Ciphertext, Params   │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│              Cryptographic Primitives (kzg/)            │
│        KZG Commitments, Polynomial Operations           │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│           Backend Abstraction Layer (arith/)            │
│  FieldElement, CurvePoint, PairingBackend traits        │
└─────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼──────┐   ┌────────▼────────┐   ┌─────▼─────┐
│  blst        │   │ ark_bls12381    │   │ ark_bn254 │
│  (BLS12-381) │   │  (BLS12-381)    │   │  (BN254)  │
└──────────────┘   └─────────────────┘   └───────────┘
```

## Examples

### Basic Usage

See [`examples/threshold_example.rs`](examples/threshold_example.rs) for a complete example with 2048 participants and threshold of 1400.

Run it with:
```bash
cargo run --example threshold_example --release
```

### Choosing Different Backends

```rust
// Using blst (default)
use tess::{PairingEngine, SilentThresholdScheme};
let scheme = SilentThresholdScheme::<PairingEngine>::new();

// Using Arkworks BLS12-381
#[cfg(feature = "ark_bls12381")]
use tess::{ArkBls12381Backend, SilentThresholdScheme};
let scheme = SilentThresholdScheme::<ArkBls12381Backend>::new();

// Using Arkworks BN254
#[cfg(feature = "ark_bn254")]
use tess::{ArkBn254Backend, SilentThresholdScheme};
let scheme = SilentThresholdScheme::<ArkBn254Backend>::new();
```

### With Tracing

```rust
use tracing_subscriber::fmt;

// Initialize logging to see performance metrics
fmt()
    .with_max_level(tracing::Level::INFO)
    .with_span_events(fmt::format::FmtSpan::ENTER | fmt::format::FmtSpan::CLOSE)
    .init();

// Operations will now log timing information
let params = scheme.param_gen(&mut rng, PARTIES, THRESHOLD)?;
```

## Performance

TESS leverages Rayon for parallel processing in performance-critical operations:

- **Multi-scalar multiplication (MSM)**: Parallelized across CPU cores
- **Key generation**: Parallel computation of key shares
- **FFT operations**: Parallel polynomial arithmetic using Radix-2 FFT
- **Lagrange precomputation**: Parallel polynomial basis construction

### Benchmarks

Run benchmarks with:
```bash
cargo bench --bench threshold_bench
```

Expected performance on modern hardware (2048 participants, threshold 1400):
- Parameter generation: ~5-10 seconds
- Key generation: ~3-6 seconds
- Encryption: ~100-200ms
- Partial decryption: ~5-10ms per share
- Aggregate decryption: ~200-400ms

## Security Considerations

### Trusted Setup

The SRS generation (`param_gen`) requires a **trusted setup**. The secret value `tau` used to generate the Structured Reference String must be securely discarded after generation. In production:

1. Use a secure random number generator
2. Ensure `tau` is never stored or logged
3. Consider using a multi-party computation (MPC) ceremony for production deployments
4. The `new_unsafe()` method name indicates this responsibility

### Threshold Security

- The scheme is secure as long as **fewer than `t` participants are compromised**
- Choose `t` based on your threat model (typically `t ≥ ⌈2n/3⌉` for Byzantine fault tolerance)
- Secret keys must be kept confidential and stored securely
- Partial decryptions should be transmitted over secure channels

### Payload Encryption

- Uses BLAKE3 as a KDF to derive symmetric keys from the shared secret
- Domain separation ensures cryptographic independence
- XOR encryption with BLAKE3 in counter mode provides semantic security

### Threat Model

TESS is secure under the following assumptions:
- The discrete logarithm problem is hard in the chosen pairing group
- The KZG assumption holds (knowledge of exponent)
- Fewer than `t` participants collude
- The trusted setup was performed honestly
- Random number generators are cryptographically secure

## API Documentation

For detailed API documentation, run:
```bash
cargo doc --open
```

Or visit [docs.rs/tess](https://docs.rs/tess) (when published).

## Testing

Run the test suite:
```bash
# Run all tests with default backend
cargo test

# Run tests with specific backend
cargo test --no-default-features --features ark_bls12381

# Run with verbose output
cargo test -- --nocapture
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## Acknowledgments

This implementation is based on the research paper:

**"Threshold Encryption with Silent Setup"**
by Sanjam Garg, Guru-Vamsi Policharla, and Mingyuan Wang
ePrint Archive: https://eprint.iacr.org/2024/263

Original implementation by Guru-Vamsi Policharla:
https://github.com/guruvamsi-policharla/silent-threshold-encryption

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## References

- [ePrint Archive Paper](https://eprint.iacr.org/2024/263): "Threshold Encryption with Silent Setup"
- [KZG Commitments](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf): Original KZG polynomial commitment scheme
- [blstrs](https://github.com/supranational/blstrs): High-performance BLS12-381 implementation
- [Arkworks](https://github.com/arkworks-rs): Ecosystem of Rust libraries for zkSNARK programming

## Citation

If you use TESS in your research, please cite the original paper:

```bibtex
@misc{garg2024threshold,
    author = {Sanjam Garg and Guru-Vamsi Policharla and Mingyuan Wang},
    title = {Threshold Encryption with Silent Setup},
    howpublished = {Cryptology ePrint Archive, Paper 2024/263},
    year = {2024},
    url = {https://eprint.iacr.org/2024/263}
}
```
