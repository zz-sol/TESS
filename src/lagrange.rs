use ark_ff::{batch_inversion, FftField, Field};
use ark_poly::{
    DenseUVPolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain,
    univariate::DensePolynomial,
};

use crate::errors::BackendError;

/// Return the i-th Lagrange basis polynomial over a radix-2 domain of size `n`.
pub fn lagrange_poly<F: FftField>(
    n: usize,
    index: usize,
) -> Result<DensePolynomial<F>, BackendError> {
    if index >= n {
        return Err(BackendError::Math("lagrange index out of range"));
    }
    if !n.is_power_of_two() {
        return Err(BackendError::Math("domain size must be a power of two"));
    }
    let domain: Radix2EvaluationDomain<F> =
        Radix2EvaluationDomain::new(n).ok_or(BackendError::Math("invalid evaluation domain"))?;
    let mut evals = vec![F::zero(); n];
    evals[index] = F::one();
    let evaluations = Evaluations::from_vec_and_domain(evals, domain);
    Ok(evaluations.interpolate())
}

/// Compute every Lagrange basis polynomial on an n-point radix-2 domain.
pub fn lagrange_polys<F: FftField>(n: usize) -> Result<Vec<DensePolynomial<F>>, BackendError> {
    if !n.is_power_of_two() {
        return Err(BackendError::Math("domain size must be a power of two"));
    }
    let domain: Radix2EvaluationDomain<F> =
        Radix2EvaluationDomain::new(n).ok_or(BackendError::Math("invalid evaluation domain"))?;
    let omega_inv = domain
        .group_gen
        .inverse()
        .ok_or(BackendError::Math("invalid group generator"))?;
    let n_scalar = F::from(n as u64);

    // precompute omega^{-i}
    let mut omega_inv_pows = Vec::with_capacity(n);
    let mut cur = F::one();
    for _ in 0..n {
        omega_inv_pows.push(cur);
        cur *= omega_inv;
    }

    // compute (n * omega^{-i})^{-1} via batch inversion
    let mut denominators: Vec<F> = omega_inv_pows.iter().map(|w| *w * n_scalar).collect();
    batch_inversion(&mut denominators);

    let mut polys = Vec::with_capacity(n);
    for (omega_i_inv, denom_inv) in omega_inv_pows.iter().zip(denominators.iter()) {
        let mut coeffs = Vec::with_capacity(n);
        let mut power = *omega_i_inv;
        for _ in 0..n {
            coeffs.push(power * denom_inv);
            power *= *omega_i_inv;
        }
        polys.push(DensePolynomial::from_coefficients_vec(coeffs));
    }

    Ok(polys)
}

/// Interpolates a polynomial that evaluates to `eval` at `points[0]`
/// and zero at every other point in `points`.
pub fn interp_mostly_zero<F: Field>(
    eval: F,
    points: &[F],
) -> Result<DensePolynomial<F>, BackendError> {
    if points.is_empty() {
        return Ok(DensePolynomial::from_coefficients_vec(vec![F::one()]));
    }

    let mut coeffs = vec![F::one()];
    for &point in points.iter().skip(1) {
        let neg_point = -point;
        coeffs.push(F::zero());
        for i in (0..coeffs.len() - 1).rev() {
            let (head, tail) = coeffs.split_at_mut(i + 1);
            let coef = &mut head[i];
            let next = &mut tail[0];
            *next += *coef;
            *coef *= neg_point;
        }
    }

    let mut scale = *coeffs.last().unwrap();
    for coeff in coeffs.iter().rev().skip(1) {
        scale = scale * points[0] + coeff;
    }
    let scale_inv = scale
        .inverse()
        .ok_or_else(|| BackendError::Math("interpolation scale inversion failed"))?;

    for coeff in coeffs.iter_mut() {
        *coeff *= eval * scale_inv;
    }

    Ok(DensePolynomial::from_coefficients_vec(coeffs))
}
