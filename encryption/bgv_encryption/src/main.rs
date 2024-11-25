use rand::distributions::{Distribution, Bernoulli};
use rand::thread_rng;
use rand::Rng;
use std::vec::Vec;
use std::io::{self, Write};

pub struct BGV {
    t: i64,
    q: i64,
    d: usize,
    pk: Option<Vec<i64>>,
    sk: Option<Vec<i64>>,
    a: Option<Vec<i64>>,
}

impl BGV {
    pub fn new(t: i64, q: i64, d: usize) -> Self {
        BGV {
            t,
            q,
            d,
            pk: None,
            sk: None,
            a: None,
        }
    }

    fn mod_q(&self, x: i64) -> i64 {
        let mut result = x % self.q;
        if result < 0 {
            result += self.q;
        }
        result
    }

    fn poly_mult(&self, a: &[i64], b: &[i64]) -> Vec<i64> {
        let mut result = vec![0; 2 * self.d - 1];
        
        for i in 0..a.len() {
            for j in 0..b.len() {
                result[i + j] = self.mod_q(result[i + j] + a[i] * b[j]);
            }
        }

        let mut reduced = vec![0; self.d];
        for i in 0..result.len() {
            if i < self.d {
                reduced[i] = self.mod_q(reduced[i] + result[i]);
            } else {
                reduced[i - self.d] = self.mod_q(reduced[i - self.d] - result[i]);
            }
        }
        reduced
    }

    pub fn gen_key(&mut self) -> (Vec<i64>, Vec<i64>) {
        let mut rng = thread_rng();
        
        let bernoulli = Bernoulli::new(0.5).unwrap();
        let mut sk = Vec::with_capacity(self.d);
        for _ in 0..self.d {
            sk.push(if bernoulli.sample(&mut rng) { 1 } else { 0 });
        }

        let mut e = Vec::with_capacity(self.d);
        for _ in 0..self.d {
            e.push(rng.gen_range(-1..=1));
        }

        let mut a = Vec::with_capacity(self.d);
        for _ in 0..self.d {
            a.push(rng.gen_range(0..self.q));
        }

        let mut pk = self.poly_mult(&a, &sk);
        for i in 0..self.d {
            pk[i] = self.mod_q(-pk[i] - e[i]);
        }

        self.sk = Some(sk.clone());
        self.pk = Some(pk.clone());
        self.a = Some(a);

        (pk, sk)
    }

    pub fn encrypt(&self, m: &[i64]) -> (Vec<i64>, Vec<i64>) {
        let mut rng = thread_rng();
        
        let mut m_poly = vec![0; self.d];
        for (i, &val) in m.iter().enumerate() {
            if i >= self.d { break; }
            m_poly[i] = val % self.t;
        }

        let mut e1 = Vec::with_capacity(self.d);
        let mut e2 = Vec::with_capacity(self.d);
        let mut u = Vec::with_capacity(self.d);

        for _ in 0..self.d {
            e1.push(rng.gen_range(-1..=1));
            e2.push(rng.gen_range(-1..=1));
            u.push(rng.gen_range(0..=1));
        }

        let pk = self.pk.as_ref().expect("Public key not generated");
        let scale = self.q / self.t;
        let mut c0 = self.poly_mult(pk, &u);
        for i in 0..self.d {
            c0[i] = self.mod_q(c0[i] + e1[i] + m_poly[i] * scale);
        }

        let a = self.a.as_ref().expect("Random polynomial not generated");
        let mut c1 = self.poly_mult(a, &u);
        for i in 0..self.d {
            c1[i] = self.mod_q(c1[i] + e2[i]);
        }

        (c0, c1)
    }

    pub fn decrypt(&self, c: (Vec<i64>, Vec<i64>)) -> Vec<i64> {
        let (c0, c1) = c;
        let sk = self.sk.as_ref().expect("Secret key not generated");

        let mut p = self.poly_mult(&c1, sk);
        for i in 0..self.d {
            p[i] = self.mod_q(c0[i] + p[i]);
        }

        for i in 0..self.d {
            p[i] = ((p[i] as f64 * self.t as f64 / self.q as f64).round() as i64) % self.t;
            if p[i] < 0 {
                p[i] += self.t;
            }
        }

        p
    }
}

fn print_polynomial(poly: &[i64], name: &str) {
    print!("{} = ", name);
    for (i, coeff) in poly.iter().enumerate() {
        if i > 0 {
            print!(" + ");
        }
        print!("{}x^{}", coeff, i);
    }
    println!();
}

fn get_user_message() -> Vec<i64> {
    let mut message = Vec::new();
    
    println!("\nEnter your message (space-separated numbers, press Enter when done):");
    print!("> ");
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    
    for num_str in input.trim().split_whitespace() {
        if let Ok(num) = num_str.parse::<i64>() {
            message.push(num);
        } else {
            println!("Warning: '{}' is not a valid number, skipping", num_str);
        }
    }
    
    if message.is_empty() {
        println!("No valid numbers entered, using default message [5, 10, 15]");
        vec![5, 10, 15]
    } else {
        message
    }
}

fn main() {
    println!("BGV Homomorphic Encryption Demo");
    println!("-------------------------------");
    
    // Set parameters
    let t = 257;    // Plaintext modulus (prime)
    let q = 65537;  // Ciphertext modulus (larger prime)
    let d = 8;      // Polynomial degree
    
    println!("Parameters:");
    println!("  Plaintext modulus (t) = {}", t);
    println!("  Ciphertext modulus (q) = {}", q);
    println!("  Polynomial degree (d) = {}", d);
    println!();
    
    println!("Note: Enter numbers between 0 and {} for best results", t-1);

    // Create BGV instance
    let mut bgv = BGV::new(t, q, d);

    // Generate keys
    let (pk, sk) = bgv.gen_key();
    println!("\nGenerated Key Pair:");
    println!("------------------");
    print_polynomial(&pk, "Public Key (pk)");
    print_polynomial(&sk, "Secret Key (sk)");
    println!();
    
    // Get message from user
    let message = get_user_message();
    println!("\nOriginal message: {:?}", message);

    // Encrypt message
    let (c0, c1) = bgv.encrypt(&message);
    println!("\nEncrypted Ciphertext:");
    println!("-------------------");
    print_polynomial(&c0, "c0");
    print_polynomial(&c1, "c1");
    println!();

    // Decrypt ciphertext
    let decrypted: Vec<i64> = bgv.decrypt((c0, c1)).into_iter().take(message.len()).collect();
    println!("Decrypted message: {:?}", decrypted);
    println!();

    // Verify the decryption
    if message == decrypted {
        println!("✓ Encryption and decryption successful!");
    } else {
        println!("✗ Error: decryption failed!");
    }
}