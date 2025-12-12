//! Core traits, configuration, and API definitions for the TESS threshold encryption project.
//!
//! The crate currently focuses on the abstraction layer that allows multiple
//! cryptographic backends (Arkworks, blstrs, future GPU-enhanced MSM engines)
//! to expose a unified interface to the higher-level protocol logic.

#[cfg(any(feature = "ark_bls12381", feature = "ark_bn254"))]
pub mod arkworks_backend;
pub mod backend;
#[cfg(feature = "blst")]
pub mod blst_backend;
pub mod config;
pub mod errors;
#[cfg(any(feature = "ark_bls12381", feature = "ark_bn254"))]
pub mod lagrange;
pub mod protocol;

#[cfg(any(feature = "ark_bls12381", feature = "ark_bn254"))]
pub use arkworks_backend::*;
pub use backend::*;
#[cfg(feature = "blst")]
pub use blst_backend::*;
pub use config::*;
pub use errors::*;
#[cfg(any(feature = "ark_bls12381", feature = "ark_bn254"))]
pub use lagrange::*;
pub use protocol::*;
