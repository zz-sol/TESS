use serde::{Deserialize, Serialize};

use crate::errors::Error;

/// Supported pairing-friendly curves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CurveId {
    Bn254,
    Bls12_381,
}

/// Supported cryptographic backends.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BackendId {
    Arkworks,
    Blst,
}

/// Configuration that selects both the backend and the curve.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendConfig {
    pub backend: BackendId,
    pub curve: CurveId,
}

impl BackendConfig {
    pub fn new(backend: BackendId, curve: CurveId) -> Self {
        Self { backend, curve }
    }
}

/// High-level parameters for the threshold encryption scheme.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdParameters {
    pub parties: usize,
    pub threshold: usize,
    pub chunk_size: usize,
    pub backend: BackendConfig,
}

impl ThresholdParameters {
    pub fn validate(&self) -> Result<(), Error> {
        if self.parties < 2 {
            return Err(Error::InvalidConfig(
                "need at least two parties for threshold encryption".into(),
            ));
        }
        if self.threshold == 0 || self.threshold > self.parties {
            return Err(Error::InvalidConfig(
                "threshold must be within [1, parties]".into(),
            ));
        }
        if !self.parties.is_power_of_two() {
            return Err(Error::InvalidConfig(
                "current protocol assumes power-of-two domain size".into(),
            ));
        }
        Ok(())
    }
}
