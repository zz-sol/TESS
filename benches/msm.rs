use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};
use std::cell::RefCell;
use tess::{BackendError, MsmProvider};

fn run_msm_bench<S, G, ScalarFn, PointFn, MsmFn>(
    c: &mut Criterion,
    label: &str,
    size: usize,
    mut next_scalar: ScalarFn,
    mut next_point: PointFn,
    msm: MsmFn,
) where
    S: Clone,
    G: Clone,
    ScalarFn: FnMut() -> S,
    PointFn: FnMut() -> G,
    MsmFn: Fn(&[G], &[S]) -> Result<G, BackendError>,
{
    let scalars: Vec<S> = (0..size).map(|_| next_scalar()).collect();
    let bases: Vec<G> = (0..size).map(|_| next_point()).collect();
    c.bench_function(label, |b| {
        b.iter(|| {
            let res = msm(black_box(&bases), black_box(&scalars)).expect("msm");
            black_box(res);
        });
    });
}

#[cfg(feature = "blst")]
fn bench_blst(c: &mut Criterion) {
    use blstrs::{G1Projective, Scalar};
    use ff::Field;
    use group::Group;
    use tess::{BlstG1, BlstMsm};

    let rng = RefCell::new(StdRng::seed_from_u64(42));
    let size = 1 << 10; // 1024 terms

    run_msm_bench(
        c,
        "blst/msm_g1_1024",
        size,
        || Scalar::random(&mut *rng.borrow_mut()),
        || BlstG1(G1Projective::random(&mut *rng.borrow_mut())),
        BlstMsm::msm_g1,
    );
}

#[cfg(feature = "ark_bls12381")]
fn bench_arkworks(c: &mut Criterion) {
    use ark_bls12_381::{Fr as BlsFr, G1Projective};
    use ark_std::UniformRand;
    use tess::{ArkG1, BlsMsm};

    let rng = RefCell::new(StdRng::seed_from_u64(42));
    let size = 1 << 10;

    run_msm_bench(
        c,
        "arkworks/msm_g1_1024",
        size,
        || BlsFr::rand(&mut *rng.borrow_mut()),
        || ArkG1(G1Projective::rand(&mut *rng.borrow_mut())),
        BlsMsm::msm_g1,
    );
}

#[cfg(feature = "ark_bn254")]
fn bench_ark_bn254(c: &mut Criterion) {
    use ark_bn254::{Fr as BnFr, G1Projective};
    use ark_std::UniformRand;
    use tess::{ArkBnG1, BnMsm};

    let rng = RefCell::new(StdRng::seed_from_u64(42));
    let size = 1 << 10;

    run_msm_bench(
        c,
        "ark_bn254/msm_g1_1024",
        size,
        || BnFr::rand(&mut *rng.borrow_mut()),
        || ArkBnG1(G1Projective::rand(&mut *rng.borrow_mut())),
        BnMsm::msm_g1,
    );
}

fn criterion_benches(c: &mut Criterion) {
    #[cfg(feature = "blst")]
    bench_blst(c);
    #[cfg(feature = "ark_bls12381")]
    bench_arkworks(c);
    #[cfg(feature = "ark_bn254")]
    bench_ark_bn254(c);
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
