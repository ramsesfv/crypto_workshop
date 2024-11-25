use num_bigint::{BigInt, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;
use serde::{Serialize, Deserialize};
use std::time::Instant;
use bincode;

pub struct ElGamal {
    key_size: u32,
    p: BigInt,        // Prime modulus
    g: BigInt,        // Generator
    private_key: BigInt,
    public_key: BigInt,
}

impl ElGamal {
    pub fn new(key_size: u32) -> Self {
        let mut instance = ElGamal {
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

    fn encode_message<T: Serialize>(&self, message: &T) -> Result<BigInt, Box<dyn std::error::Error>> {
        let serialized = bincode::serialize(message)?;
        Ok(BigInt::from_bytes_be(num_bigint::Sign::Plus, &serialized))
    }

    fn decode_message<T: for<'de> Deserialize<'de>>(&self, number: &BigInt) -> Result<T, Box<dyn std::error::Error>> {
        let bytes = number.to_bytes_be().1;
        let message = bincode::deserialize(&bytes)?;
        Ok(message)
    }

    pub fn encrypt<T: Serialize>(&self, message: &T) -> Result<(BigInt, BigInt), Box<dyn std::error::Error>> {
        let m = self.encode_message(message)?;
        
        if m >= self.p {
            return Err("Message too large for current key size".into());
        }
        
        let mut rng = thread_rng();
        let p_minus_1: BigInt = self.p.clone() - 1;
        
        // Generate k until we find one coprime with p-1
        let mut k;
        loop {
            k = rng.gen_bigint_range(&BigInt::one(), &(p_minus_1.clone() - 1));
            if self.gcd(&k, &p_minus_1) == One::one() {
                break;
            }
        }
        
        // Calculate ciphertext components
        let c1 = self.mod_pow(&self.g, &k, &self.p);
        let s = self.mod_pow(&self.public_key, &k, &self.p);
        let c2 = (&m * &s) % &self.p;
        
        Ok((c1, c2))
    }

    pub fn decrypt<T: for<'de> Deserialize<'de>>(&self, cipher: &(BigInt, BigInt)) -> Result<T, Box<dyn std::error::Error>> {
        let (c1, c2) = cipher;
        
        if c1 <= &BigInt::zero() || c1 >= &self.p || c2 <= &BigInt::zero() || c2 >= &self.p {
            return Err("Invalid ciphertext".into());
        }
        
        let s = self.mod_pow(c1, &self.private_key, &self.p);
        let s_inv = self.mod_inverse(&s, &self.p).ok_or("Failed to compute modular inverse")?;
        let m = (c2 * &s_inv) % &self.p;
        
        self.decode_message(&m)
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
    println!("Initializing ElGamal cryptosystem...");
    let start = Instant::now();
    let elgamal = ElGamal::new(512); // Using smaller key size for demo
    println!("Initialization took: {:?}", start.elapsed());

    let message = "Hello, World!";
    println!("\nOriginal message: {}", message);

    match elgamal.encrypt(&message) {
        Ok(cipher) => {
            println!("\nEncrypted (c1, c2):");
            println!("c1: {}", cipher.0);
            println!("c2: {}", cipher.1);

            match elgamal.decrypt::<String>(&cipher) {
                Ok(decrypted) => {
                    println!("\nDecrypted message: {}", decrypted);
                    assert_eq!(message, decrypted, "Decryption failed!");
                    println!("\nVerification: Success!");
                }
                Err(e) => println!("Decryption error: {}", e),
            }
        }
        Err(e) => println!("Encryption error: {}", e),
    }
}