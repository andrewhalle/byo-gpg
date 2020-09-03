use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use rand::thread_rng;
use rayon::iter::repeat;
use rayon::prelude::*;
use std::thread;
use std::time::Duration;
use termprogress::prelude::*;

const TRIALS: u32 = 10;
const BIT_SIZE: u64 = 1024;

fn factor_as_multiplication(n: &BigUint) -> (BigUint, BigUint) {
    let mut d = n.clone();
    let mut s = BigUint::new(vec![0]);
    while d.is_even() {
        s = s + 1_u32;
        d = d / 2_u32;
    }

    (d, s)
}

fn miller_rabin(n: &BigUint) -> bool {
    let mut rng = thread_rng();

    if n.is_even() {
        return false;
    }

    let n_minus_one = n.clone() - 1_u32;
    let (d, s) = factor_as_multiplication(&n_minus_one);
    let s_minus_one = s.clone() - 1_u32;

    'witness: for _i in 0..TRIALS {
        let a = rng.gen_biguint_below(&n);
        let mut x = a.modpow(&d, &n);

        let one = BigUint::new(vec![1]);
        if &x == &one || &x == &n_minus_one {
            continue 'witness;
        }

        let mut j = BigUint::new(vec![0]);
        while &j < &s_minus_one {
            let two = BigUint::new(vec![2]);
            x = x.modpow(&two, &n);
            if &x == &n_minus_one {
                continue 'witness;
            }

            j = j + 1_u32;
        }

        return false;
    }

    true
}

fn fermat(n: &BigUint) -> bool {
    let mut rng = thread_rng();

    let one = BigUint::new(vec![1]);
    let n_minus_1 = n.clone() - 1_u32;

    let a = rng.gen_biguint_below(&n_minus_1);

    a.modpow(&n_minus_1, &n) == one
}

fn first_twenty_primes(n: &BigUint) -> bool {
    let primes = &[
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71_u32,
    ];

    let zero = BigUint::new(vec![0]);
    for p in primes.iter() {
        if n % p == zero {
            return false;
        }
    }

    true
}

fn is_probable_prime(n: &BigUint) -> bool {
    first_twenty_primes(n) && fermat(n) && miller_rabin(n)
}

fn gen_prime_candidate() -> (bool, BigUint) {
    let mut rng = thread_rng();
    let num = rng.gen_biguint(BIT_SIZE);

    (is_probable_prime(&num), num)
}

pub fn gen_large_prime() -> BigUint {
    let (_, large_prime) = repeat(())
        .map(|_| gen_prime_candidate())
        .find_any(|(is_prime, _)| *is_prime)
        .unwrap();

    large_prime
}

pub fn gen_key() {
    let estimated = 5.0;

    let mut p_elapsed = 0.0;
    let mut progress = Bar::default();
    progress.set_title("Generating p...");
    let t = thread::spawn(move || {
        while p_elapsed < estimated {
            p_elapsed += 0.2;
            progress.set_progress(f64::min(1.0, p_elapsed / estimated));
            thread::sleep(Duration::from_millis(200));
        }
    });
    let p = gen_large_prime();
    t.join().unwrap();

    let mut q_elapsed = 0.0;
    let mut progress = Bar::default();
    progress.set_title("Generating q...");
    let t = thread::spawn(move || {
        while q_elapsed < estimated {
            q_elapsed += 0.2;
            progress.set_progress(f64::min(1.0, q_elapsed / estimated));
            thread::sleep(Duration::from_millis(200));
        }
    });
    let q = gen_large_prime();
    t.join().unwrap();

    println!("p: {}", p);
    println!("q: {}", q);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_probable_prime_test() {
        let num = BigUint::new(vec![7919]);
        assert!(is_probable_prime(&num));
    }
}
