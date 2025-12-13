use serde::{Deserialize, Serialize};

use crate::errors::{BackendError, Error};

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

    pub fn ensure_supported(&self) -> Result<(), BackendError> {
        match (self.backend, self.curve) {
            (BackendId::Arkworks, CurveId::Bls12_381) => {
                if cfg!(feature = "ark_bls12381") {
                    Ok(())
                } else {
                    Err(BackendError::UnsupportedFeature(
                        "compile with `ark_bls12381` feature to use Arkworks BLS12-381",
                    ))
                }
            }
            (BackendId::Arkworks, CurveId::Bn254) => {
                if cfg!(feature = "ark_bn254") {
                    Ok(())
                } else {
                    Err(BackendError::UnsupportedFeature(
                        "compile with `ark_bn254` feature to use Arkworks BN254",
                    ))
                }
            }
            (BackendId::Blst, CurveId::Bls12_381) => {
                if cfg!(feature = "blst") {
                    Ok(())
                } else {
                    Err(BackendError::UnsupportedFeature(
                        "compile with `blst` feature to use the blstrs backend",
                    ))
                }
            }
            (BackendId::Blst, CurveId::Bn254) => Err(BackendError::UnsupportedCurve(
                "bn254 is not yet supported by the blstrs backend",
            )),
        }
    }
}

/// High-level parameters for the threshold encryption scheme.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdParameters {
    pub parties: usize,
    pub threshold: usize,
    pub chunk_size: usize,
    pub backend: BackendConfig,
    pub kzg_tau: Option<Vec<u8>>,
}

impl ThresholdParameters {
    pub fn validate(&self) -> Result<(), Error> {
        self.backend.ensure_supported().map_err(Error::Backend)?;
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
