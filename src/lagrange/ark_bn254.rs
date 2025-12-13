use ark_bn254::Fr as BnFr;
use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;

use crate::errors::BackendError;

use super::{
    interp_mostly_zero_impl, lagrange_poly_impl, lagrange_polys_impl, LagrangeField,
};

impl LagrangeField for BnFr {
    const TWO_ADICITY: u32 = <BnFr as FftField>::TWO_ADICITY;

    fn two_adic_root_of_unity() -> Self {
        <BnFr as FftField>::TWO_ADIC_ROOT_OF_UNITY
    }
}

pub fn lagrange_poly(n: usize, index: usize) -> Result<DensePolynomial<BnFr>, BackendError> {
    lagrange_poly_impl::<BnFr, _, _>(n, index, DensePolynomial::from_coefficients_vec)
}

pub fn lagrange_polys(n: usize) -> Result<Vec<DensePolynomial<BnFr>>, BackendError> {
    lagrange_polys_impl::<BnFr, _, _>(n, DensePolynomial::from_coefficients_vec)
}

pub fn interp_mostly_zero(
    eval: BnFr,
    points: &[BnFr],
) -> Result<DensePolynomial<BnFr>, BackendError> {
    interp_mostly_zero_impl::<BnFr, _, _>(eval, points, DensePolynomial::from_coefficients_vec)
}
