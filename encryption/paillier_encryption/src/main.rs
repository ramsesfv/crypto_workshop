use num_bigint::{BigInt, RandBigInt};
use num_traits::{One, Zero};
use num_integer::Integer;
use rand::thread_rng;
use std::io::{self, Write};

#[derive(Debug)]
pub struct Paillier {
    key_size: u64,
    n: BigInt,        
    g: BigInt,        
    lambda_n: BigInt, 
    mu: BigInt,       
}

impl Paillier {
    pub fn new(key_size: u64) -> Self {
        if key_size < 64 {
            panic!("Key size must be at least 64 bits");
        }
        let mut instance = Self {
            key_size,
            n: BigInt::zero(),
            g: BigInt::zero(),
            lambda_n: BigInt::zero(),
            mu: BigInt::zero(),
        };
        instance.generate_keys();
        instance
    }

    fn generate_keys(&mut self) {
        let mut rng = thread_rng();
        
        let bits_per_prime = (self.key_size / 2) as u64;
        
        let p = loop {
            let p_candidate = rng.gen_bigint(bits_per_prime);
            if p_candidate > BigInt::one() && self.is_prime(&p_candidate) {
                break p_candidate;
            }
        };

        let q = loop {
            let q_candidate = rng.gen_bigint(bits_per_prime);
            if q_candidate > BigInt::one() && q_candidate != p && self.is_prime(&q_candidate) {
                break q_candidate;
            }
        };

        println!("\nGenerated prime p: {}", p);
        println!("Generated prime q: {}", q);

        self.n = p.clone() * q.clone();
        println!("Computed n = p * q: {}", self.n);

        self.g = self.n.clone() + 1u32;
        println!("Set g = n + 1: {}", self.g);

        let p_minus_1 = p - 1u32;
        let q_minus_1 = q - 1u32;
        self.lambda_n = lcm(&p_minus_1, &q_minus_1);
        println!("Computed λ(n) = lcm(p-1, q-1): {}", self.lambda_n);

        let n_squared = self.n.clone() * self.n.clone();
        let base = self.g.modpow(&self.lambda_n, &n_squared);
        let l = self.compute_l(&base);
        self.mu = match self.mod_inverse(&l, &self.n) {
            Some(mu) => mu,
            None => panic!("Failed to compute modular inverse"),
        };
        println!("Computed μ = L(g^λ mod n²)^(-1) mod n: {}", self.mu);
    }

    fn is_prime(&self, n: &BigInt) -> bool {
        if n <= &BigInt::from(1) { return false; }
        if n <= &BigInt::from(3) { return true; }
        if n.is_even() { return false; }
        
        let mut rng = thread_rng();
        let k = 50; 
        
        let n_minus_1 = n - 1u32;
        let mut d = n_minus_1.clone();
        let mut s = 0u32;
        
        while (&d & BigInt::one()) == BigInt::zero() {
            d >>= 1;
            s += 1;
        }
        
        'outer: for _ in 0..k {
            let a = rng.gen_bigint_range(&BigInt::from(2), &(n - 2));
            let mut x = a.modpow(&d, n);
            
            if x == BigInt::one() || x == n_minus_1 {
                continue;
            }
            
            for _ in 1..s {
                x = (&x * &x) % n;
                if x == n_minus_1 {
                    continue 'outer;
                }
                if x == BigInt::one() {
                    return false;
                }
            }
            return false;
        }
        true
    }

    fn compute_l(&self, x: &BigInt) -> BigInt {
        (x - 1u32) / &self.n
    }

    fn mod_inverse(&self, a: &BigInt, n: &BigInt) -> Option<BigInt> {
        let mut t = BigInt::zero();
        let mut newt = BigInt::one();
        let mut r = n.clone();
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
        
        if r > BigInt::one() {
            return None;
        }
        if t < BigInt::zero() {
            t += n;
        }
        Some(t)
    }

    pub fn encrypt(&self, message: &BigInt) -> BigInt {
        if message >= &self.n {
            panic!("Message too large for current key size");
        }
        
        println!("\nEncryption process:");
        println!("Message to encrypt: {}", message);
        
        let mut rng = thread_rng();
        let n_squared = &self.n * &self.n;
        println!("n² = {}", n_squared);
        
        let mut r;
        loop {
            r = rng.gen_bigint_range(&BigInt::one(), &self.n);
            if gcd(&r, &self.n) == BigInt::one() {
                break;
            }
        }
        println!("Random r (coprime with n): {}", r);
        
        let term1 = self.g.modpow(message, &n_squared);
        println!("Term1 = g^m mod n² = {}", term1);
        
        let term2 = r.modpow(&self.n, &n_squared);
        println!("Term2 = r^n mod n² = {}", term2);
        
        let ciphertext = (term1 * term2) % n_squared;
        println!("Ciphertext = term1 * term2 mod n² = {}", ciphertext);
        
        ciphertext
    }

    pub fn decrypt(&self, ciphertext: &BigInt) -> BigInt {
        let n_squared = &self.n * &self.n;
        if ciphertext >= &n_squared {
            panic!("Invalid ciphertext");
        }
        
        println!("\nDecryption process:");
        println!("Ciphertext to decrypt: {}", ciphertext);
        
        let x = ciphertext.modpow(&self.lambda_n, &n_squared);
        println!("x = c^λ mod n² = {}", x);
        
        let l = self.compute_l(&x);
        println!("L(x) = {}", l);
        
        let message = (l * &self.mu) % &self.n;
        println!("Message = L(x) * μ mod n = {}", message);
        
        message
    }

    pub fn homomorphic_add(&self, c1: &BigInt, c2: &BigInt) -> BigInt {
        println!("\nHomomorphic addition:");
        println!("c1 = {}", c1);
        println!("c2 = {}", c2);
        
        let n_squared = &self.n * &self.n;
        let result = (c1 * c2) % n_squared;
        println!("Result = c1 * c2 mod n² = {}", result);
        
        result
    }

    pub fn homomorphic_multiply_constant(&self, c: &BigInt, k: &BigInt) -> BigInt {
        println!("\nHomomorphic multiplication by constant:");
        println!("c = {}", c);
        println!("k = {}", k);
        
        let n_squared = &self.n * &self.n;
        let result = c.modpow(k, &n_squared);
        println!("Result = c^k mod n² = {}", result);
        
        result
    }
}

fn gcd(a: &BigInt, b: &BigInt) -> BigInt {
    let mut a = a.clone();
    let mut b = b.clone();
    while !b.is_zero() {
        let t = b.clone();
        b = &a % &b;
        a = t;
    }
    a
}

fn lcm(a: &BigInt, b: &BigInt) -> BigInt {
    (a * b) / gcd(a, b)
}

fn get_number_input(prompt: &str) -> BigInt {
    loop {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read line");
        
        match input.trim().parse::<i64>() {
            Ok(num) => return BigInt::from(num),
            Err(_) => println!("Please enter a valid number"),
        }
    }
}

fn main() {
    println!("Initializing Paillier cryptosystem...");
    println!("This may take a moment...");
    
    let paillier = Paillier::new(128);
    println!("Cryptosystem initialized!");

    let m1 = get_number_input("\nEnter first number: ");
    let m2 = get_number_input("Enter second number: ");

    println!("\nEncrypting messages...");
    let c1 = paillier.encrypt(&m1);
    let c2 = paillier.encrypt(&m2);
    println!("Messages encrypted!");

    loop {
        println!("\nAvailable operations:");
        println!("1. Decrypt first number");
        println!("2. Decrypt second number");
        println!("3. Add numbers homomorphically");
        println!("4. Multiply first number by constant");
        println!("5. Exit");
        
        print!("Choose operation (1-5): ");
        io::stdout().flush().unwrap();
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to read line");
        
        match choice.trim() {
            "1" => {
                let decrypted = paillier.decrypt(&c1);
                println!("\nFirst number: {}", decrypted);
            },
            "2" => {
                let decrypted = paillier.decrypt(&c2);
                println!("\nSecond number: {}", decrypted);
            },
            "3" => {
                let sum_encrypted = paillier.homomorphic_add(&c1, &c2);
                let sum_decrypted = paillier.decrypt(&sum_encrypted);
                println!("\nHomomorphic sum: {}", sum_decrypted);
                println!("Verification: {} + {} = {}", m1, m2, &m1 + &m2);
            },
            "4" => {
                let k = get_number_input("\nEnter multiplier: ");
                let prod_encrypted = paillier.homomorphic_multiply_constant(&c1, &k);
                let prod_decrypted = paillier.decrypt(&prod_encrypted);
                println!("\nHomomorphic product: {}", prod_decrypted);
                println!("Verification: {} * {} = {}", m1, k, &m1 * &k);
            },
            "5" => break,
            _ => println!("\nInvalid choice, please try again"),
        }
    }
}