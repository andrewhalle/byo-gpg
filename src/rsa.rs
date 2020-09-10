use crate::output;
use crate::output::{FromFile, ToFile};
use crate::primes;
use num::bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
use num::integer::{ExtendedGcd, Integer};
use num::traits::identities::Zero;

const E: i32 = 65_537;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PublicKey {
    n: BigUint,
    e: BigUint,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PrivateKey {
    n: BigUint,
    e: BigUint,
    d: BigUint,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum Message {
    Ciphertext(Vec<u8>),
    Plaintext(Vec<u8>),
}

impl PublicKey {
    pub fn new<T1: ToBigUint, T2: ToBigUint>(n: T1, e: T2) -> Self {
        PublicKey {
            n: n.to_biguint().unwrap(),
            e: e.to_biguint().unwrap(),
        }
    }
}

impl ToFile for PublicKey {}

impl FromFile for PublicKey {}

impl PrivateKey {
    pub fn new<T1: ToBigUint, T2: ToBigUint, T3: ToBigUint>(n: T1, e: T2, d: T3) -> Self {
        PrivateKey {
            n: n.to_biguint().unwrap(),
            e: e.to_biguint().unwrap(),
            d: d.to_biguint().unwrap(),
        }
    }
}

impl ToFile for PrivateKey {}

impl FromFile for PrivateKey {}

impl Message {
    pub fn from_string(s: String) -> Self {
        Self::Plaintext(s.into_bytes())
    }

    pub fn encrypt(&mut self, key: &PublicKey) {
        if let Self::Plaintext(plaintext) = self {
            let padded = BigUint::from_bytes_be(&plaintext);
            let ciphertext = padded.modpow(&key.e, &key.n);

            *self = Self::Ciphertext(ciphertext.to_bytes_be());
        }
    }

    pub fn decrypt(&mut self, key: &PrivateKey) {
        if let Self::Ciphertext(ciphertext) = self {
            let ciphertext = BigUint::from_bytes_be(&ciphertext);
            let padded = ciphertext.modpow(&key.d, &key.n);

            *self = Self::Plaintext(padded.to_bytes_be());
        }
    }
}

impl ToFile for Message {}

impl FromFile for Message {}

pub fn gen_key() -> (PublicKey, PrivateKey) {
    let p = output::do_task_with_progress(|| primes::gen_large_prime(), 1.0, "Generating p...");
    let q = output::do_task_with_progress(|| primes::gen_large_prime(), 1.0, "Generating q...");

    let n = p.clone() * q.clone();
    let lambda_n = carmichaels_totient_function(&p, &q);
    let e = E.to_bigint().unwrap();

    let ExtendedGcd { y: mut d, .. } = lambda_n.to_bigint().unwrap().extended_gcd(&e);
    if d < BigInt::zero() {
        d += lambda_n.to_bigint().unwrap();
    }

    let public_key = PublicKey::new(n.clone(), e.clone());
    let private_key = PrivateKey::new(n, e, d);

    (public_key, private_key)
}

fn carmichaels_totient_function(p: &BigUint, q: &BigUint) -> BigUint {
    let p_minus_1 = p.clone() - 1_u32;
    let q_minus_1 = q.clone() - 1_u32;

    let mag = p_minus_1.clone() * q_minus_1.clone();

    mag / p_minus_1.gcd(&q_minus_1)
}
