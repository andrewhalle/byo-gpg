use num_bigint::{BigUint, RandomBits};
use num_integer::Integer;
use rand::distributions::Distribution;
use rand::thread_rng;
use rayon::iter::repeat;
use rayon::prelude::*;

const TRIALS: u32 = 10;
const BIT_SIZE: u64 = 1024;

fn big_uint_gen_range(max: &BigUint) -> BigUint {
    let mut rng = thread_rng();
    let dist = RandomBits::new(BIT_SIZE);
    let mut curr = dist.sample(&mut rng);

    while &curr > max {
        curr = dist.sample(&mut rng);
    }

    curr
}

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
    if n.is_even() {
        return false;
    }

    let n_minus_one = n.clone() - 1_u32;
    let (d, s) = factor_as_multiplication(&n_minus_one);
    let s_minus_one = s.clone() - 1_u32;

    'witness: for _i in 0..TRIALS {
        let a = big_uint_gen_range(&n);
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
    let one = BigUint::new(vec![1]);
    let n_minus_1 = n.clone() - 1_u32;

    let a = big_uint_gen_range(&n_minus_1);

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

fn gen_one_large_prime() -> (bool, BigUint) {
    let mut rng = thread_rng();
    let dist = RandomBits::new(BIT_SIZE);
    let curr: BigUint = dist.sample(&mut rng);

    (is_probable_prime(&curr), curr)
}

pub fn gen_key() {
    let (_, large_prime) = repeat(())
        .map(|_| gen_one_large_prime())
        .find_any(|(is_prime, _)| *is_prime)
        .unwrap();

    println!("{}", large_prime);
}
