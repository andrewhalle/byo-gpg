use num_bigint::{BigUint, RandomBits};
use num_integer::Integer;
use num_traits::cast::FromPrimitive;
use rand::distributions::Distribution;
use rand::thread_rng;

const TRIALS: u32 = 10;
const BIT_SIZE: u64 = 2048;

fn big_uint_gen_range(max: BigUint) -> BigUint {
    let mut rng = thread_rng();
    let dist = RandomBits::new(BIT_SIZE);
    let mut curr = dist.sample(&mut rng);

    while curr > max {
        curr = dist.sample(&mut rng);
    }

    curr
}

fn factor_as_multiplication(mut d: BigUint) -> (BigUint, BigUint) {
    let zero = BigUint::from_u32(0).unwrap();
    let one = BigUint::from_i32(1).unwrap();
    let two = BigUint::from_i32(2).unwrap();

    let mut s = zero.clone();
    while zero == d.clone() % two.clone() {
        s += one.clone();
        d /= two.clone();
    }

    (d, s)
}

fn miller_rabin(n: BigUint) -> bool {
    let zero = BigUint::from_u32(0).unwrap();
    let one = BigUint::from_i32(1).unwrap();
    let two = BigUint::from_i32(2).unwrap();

    if n.is_even() {
        return false;
    }

    let (d, s) = factor_as_multiplication(n.clone() - one.clone());

    'witness: for _i in 0..TRIALS {
        let a = big_uint_gen_range(n.clone());
        let mut x = a.modpow(&d, &n);

        if x == one.clone() || x == n.clone() - one.clone() {
            continue 'witness;
        }

        let mut j = zero.clone();
        while j < s.clone() - one.clone() {
            x = x.modpow(&two, &n);
            if x == n.clone() - one.clone() {
                continue 'witness;
            }

            j += one.clone();
        }

        return false;
    }

    true
}

fn gen_large_prime() -> BigUint {
    let mut rng = thread_rng();
    let dist = RandomBits::new(BIT_SIZE);
    let mut curr: BigUint = dist.sample(&mut rng);

    while !miller_rabin(curr.clone()) {
        curr = dist.sample(&mut rng);
    }

    curr
}

pub fn gen_key() {
    println!("{}", gen_large_prime());
}
