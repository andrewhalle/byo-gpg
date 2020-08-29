use num_bigint::{BigUint, RandomBits};
use num_integer::Integer;
use num_traits::cast::FromPrimitive;
use rand::distributions::Distribution;
use rand::thread_rng;

const TRIALS: u32 = 1000;
const BIT_SIZE: u64 = 128;

fn big_uint_gen_range(max: BigUint) -> BigUint {
    let mut rng = thread_rng();
    let dist = RandomBits::new(BIT_SIZE);
    let mut curr = dist.sample(&mut rng);

    while curr > max {
        curr = dist.sample(&mut rng);
    }

    curr
}

fn miller_rabin(n: BigUint) -> bool {
    let zero = BigUint::from_u32(0).unwrap();
    let one = BigUint::from_i32(1).unwrap();
    let two = BigUint::from_i32(2).unwrap();

    if n.is_even() {
        return false;
    }

    let mut d = n.clone() - one.clone();

    let mut s = zero.clone();
    while d.clone() % two.clone() == zero.clone() {
        s += one.clone();
        d /= two.clone();
    }

    for _i in 0..TRIALS {
        let a = big_uint_gen_range(n.clone());
        let test = a.modpow(&d, &n);
        if test != one.clone() {
            let mut curr = one.clone();
            let mut i = zero.clone();
            while i < s.clone() - one.clone() {
                let test = a.modpow(&(curr.clone() * d.clone()), &n);
                if test != n.clone() - one.clone() {
                    return false;
                }

                i += one.clone();
                curr *= two.clone();
            }
        }
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
