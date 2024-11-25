use num_bigint::{BigInt, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;
use sha2::{Sha256, Digest};
use std::time::Instant;

pub struct ElGamalSignature {
    key_size: u32,
    p: BigInt,        // Prime modulus
    g: BigInt,        // Generator
    private_key: BigInt,
    public_key: BigInt,
}

impl ElGamalSignature {
    pub fn new(key_size: u32) -> Self {
        let mut instance = ElGamalSignature {
            key_size,
            p: BigInt::zero(),
            g: BigInt::from(2),
            private_key: BigInt::zero(),
            public_key: BigInt::zero(),
        };
        instance.generate_keys();
        instance
    }

    fn generate_keys(&mut self) {
        let mut rng = thread_rng();
        
        // Generate prime p
        println!("Generating prime...");
        let start = Instant::now();
        let lower = BigInt::from(2).pow(self.key_size - 1);
        let upper = BigInt::from(2).pow(self.key_size);
        self.p = rng.gen_bigint_range(&lower, &upper);
        while !self.is_prime(&self.p) {
            self.p = rng.gen_bigint_range(&lower, &upper);
        }
        println!("Prime generation took: {:?}", start.elapsed());

        // Find generator
        println!("Finding generator...");
        self.g = BigInt::from(2);
        let p_minus_1_div_2: BigInt = (&self.p - 1) / 2;
        while self.mod_pow(&self.g, &p_minus_1_div_2, &self.p) == One::one() {
            self.g += 1;
        }

        // Generate private key
        self.private_key = rng.gen_bigint_range(&BigInt::one(), &(self.p.clone() - 2));

        // Calculate public key
        self.public_key = self.mod_pow(&self.g, &self.private_key, &self.p);
    }

    fn hash_message(&self, message: &str) -> BigInt {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let result = hasher.finalize();
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &result)
    }

    pub fn sign(&self, message: &str) -> (BigInt, BigInt) {
        let h = self.hash_message(message);
        let mut rng = thread_rng();
        let p_minus_1: BigInt = self.p.clone() - 1;

        // Generate ephemeral key k
        let mut k;
        loop {
            k = rng.gen_bigint_range(&BigInt::one(), &(p_minus_1.clone() - 1));
            if self.gcd(&k, &p_minus_1) == One::one() {
                break;
            }
        }

        // Calculate signature components
        let r = self.mod_pow(&self.g, &k, &self.p);
        let k_inv = self.mod_inverse(&k, &p_minus_1).unwrap();
        let mut s = (&k_inv * (&h - &self.private_key * &r)) % &p_minus_1;
        if s < Zero::zero() {
            s = s + &p_minus_1;
        }

        (r, s)
    }

    pub fn verify(&self, message: &str, signature: &(BigInt, BigInt)) -> bool {
        let (r, s) = signature;
        
        // Check ranges
        if r <= &BigInt::zero() || r >= &self.p || s <= &BigInt::zero() || s >= &(self.p.clone() - 1) {
            return false;
        }

        let h = self.hash_message(message);

        // Verify signature
        let left = self.mod_pow(&self.g, &h, &self.p);
        let right = (self.mod_pow(&self.public_key, r, &self.p) * 
                    self.mod_pow(r, s, &self.p)) % &self.p;

        left == right
    }

    // Helper functions
    fn is_prime(&self, n: &BigInt) -> bool {
        if n <= &BigInt::one() { return false; }
        if n <= &BigInt::from(3) { return true; }
        
        let mut rng = thread_rng();
        let k = 50; // Number of iterations for Miller-Rabin
        
        let n_minus_1: BigInt = n - 1;
        let mut d = n_minus_1.clone();
        let mut s = 0;
        
        while (&d & BigInt::one()) == Zero::zero() {
            d >>= 1;
            s += 1;
        }
        
        'outer: for _ in 0..k {
            let a = rng.gen_bigint_range(&BigInt::from(2), &(n - 2));
            let mut x = self.mod_pow(&a, &d, n);
            
            if x == One::one() || x == n_minus_1 {
                continue;
            }
            
            for _ in 0..s-1 {
                x = (&x * &x) % n;
                if x == n_minus_1 {
                    continue 'outer;
                }
            }
            
            return false;
        }
        
        true
    }

    fn mod_pow(&self, base: &BigInt, exp: &BigInt, modulus: &BigInt) -> BigInt {
        let mut result = BigInt::one();
        let mut base = base.clone();
        let mut exp = exp.clone();

        while exp > Zero::zero() {
            if (&exp & BigInt::one()) == One::one() {
                result = (result * &base) % modulus;
            }
            base = (&base * &base) % modulus;
            exp >>= 1;
        }
        result
    }

    fn gcd(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let mut a = a.clone();
        let mut b = b.clone();
        while !b.is_zero() {
            let t = b.clone();
            b = &a % &b;
            a = t;
        }
        a
    }

    fn mod_inverse(&self, a: &BigInt, m: &BigInt) -> Option<BigInt> {
        let mut t = BigInt::zero();
        let mut newt = BigInt::one();
        let mut r = m.clone();
        let mut newr = a.clone();
        
        while !newr.is_zero() {
            let quotient = &r / &newr;
            let temp_t = t.clone();
            t = newt.clone();
            newt = temp_t - &quotient * newt;
            let temp_r = r.clone();
            r = newr.clone();
            newr = temp_r - quotient * newr;
        }
        
        if r > One::one() {
            return None;
        }
        if t < Zero::zero() {
            t = t + m;
        }
        Some(t)
    }
}

fn main() {
    println!("Initializing ElGamal signature scheme...");
    let start = Instant::now();
    let elgamal = ElGamalSignature::new(512); // Using smaller key size for demo
    println!("Initialization took: {:?}", start.elapsed());

    let message = "Hello, World!";
    println!("\nMessage to sign: {}", message);

    let signature = elgamal.sign(message);
    println!("\nSignature generated:");
    println!("r: {}", signature.0);
    println!("s: {}", signature.1);

    let is_valid = elgamal.verify(message, &signature);
    println!("\nSignature valid: {}", is_valid);

    let tampered = "Hello, World!!";
    let is_valid = elgamal.verify(tampered, &signature);
    println!("\nTampered message verification: {}", is_valid);
}