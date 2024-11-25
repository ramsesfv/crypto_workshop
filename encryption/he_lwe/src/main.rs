use ndarray::{Array1, Array2, s};
use rand::distributions::{Distribution};
use rand_distr::Normal;
use rand::{thread_rng, Rng};

#[derive(Debug, Clone)]
pub struct PublicParams {
    n: usize,                       // Dimension of the lattice
    q: i64,                         // Modulus
    t: i64,                         // Plaintext modulus
    std_dev: f64,                   // Standard deviation for error distribution
    scale: i64,                     // Scaling factor between plaintext and ciphertext spaces
}

#[derive(Debug, Clone)]
pub struct KeyBundle {
    secret_key: Array1<i64>,                     // Secret key
    public_key: (Array2<i64>, Array1<i64>),      // Public key (A, b)
}

pub struct EnhancedLWEBasedFHE {
    params: PublicParams,
}

impl EnhancedLWEBasedFHE {
    pub fn new(n: usize, q: i64, t: i64, std_dev: f64) -> Self {
        EnhancedLWEBasedFHE {
            params: PublicParams {
                n,
                q,
                t,
                std_dev,
                scale: (q as f64 / t as f64).round() as i64, // Corrected scaling factor
            },
        }
    }

    fn mod_q(&self, x: i64) -> i64 {
        let mut result = x % self.params.q;
        if result < 0 {
            result += self.params.q;
        }
        result
    }

    pub fn generate_keys(&self) -> KeyBundle {
        let mut rng = thread_rng();
        
        // Generate secret key
        let mut secret_key = Array1::zeros(self.params.n);
        for i in 0..self.params.n {
            secret_key[i] = rng.gen_range(0..2);
        }

        // Generate public key matrix A
        let mut pub_matrix = Array2::zeros((self.params.n, self.params.n));
        for i in 0..self.params.n {
            for j in 0..self.params.n {
                pub_matrix[[i, j]] = rng.gen_range(0..self.params.q);
            }
        }

        // Generate error vector e
        let gaussian = Normal::new(0.0, self.params.std_dev).unwrap();
        let mut e = Array1::zeros(self.params.n);
        for i in 0..self.params.n {
            e[i] = self.mod_q(gaussian.sample(&mut rng).round() as i64);
        }

        // Compute b = A * s + e mod q
        let mut b = pub_matrix.dot(&secret_key);
        for i in 0..self.params.n {
            b[i] = self.mod_q(b[i] + e[i]);
        }

        KeyBundle {
            secret_key,
            public_key: (pub_matrix, b),
        }
    }

    pub fn encrypt(&self, message: &str, public_key: &(Array2<i64>, Array1<i64>)) 
        -> Vec<Array1<i64>> {
        let mut rng = thread_rng();
        let gaussian = Normal::new(0.0, self.params.std_dev).unwrap();
        let (pub_matrix, b) = public_key;

        let binary: String = message.chars()
            .flat_map(|c| format!("{:08b}", c as u8).chars().collect::<Vec<_>>())
            .collect();

        let mut ciphertexts = Vec::new();

        for bit in binary.chars() {
            let m = bit.to_digit(10).unwrap() as i64;
            
            // Generate randomness vector r
            let mut r = Array1::zeros(self.params.n);
            for i in 0..self.params.n {
                r[i] = rng.gen_range(0..2);
            }

            // Generate error terms e1 and e2
            let mut e1 = Array1::zeros(self.params.n);
            for i in 0..self.params.n {
                e1[i] = self.mod_q(gaussian.sample(&mut rng).round() as i64);
            }
            let e2 = self.mod_q(gaussian.sample(&mut rng).round() as i64);

            // Compute u = rA + e1 mod q
            let mut u = r.dot(pub_matrix);
            for i in 0..self.params.n {
                u[i] = self.mod_q(u[i] + e1[i]);
            }

            // Compute v = rb + e2 + m * scale mod q
            let v = self.mod_q(r.dot(b) + e2 + m * self.params.scale);

            // Combine u and v into ciphertext ct
            let mut ct = Array1::zeros(self.params.n + 1);
            ct.slice_mut(s![..self.params.n]).assign(&u);
            ct[self.params.n] = v;

            ciphertexts.push(ct);
        }

        ciphertexts
    }

    pub fn decrypt(&self, ciphertexts: &[Array1<i64>], secret_key: &Array1<i64>) -> String {
        let mut bits = String::new();

        for ct in ciphertexts {
            let u = ct.slice(s![..self.params.n]);
            let v = ct[self.params.n];

            // Compute phase = v - u ⋅ s mod q
            let mut phase = v;
            for i in 0..self.params.n {
                phase = self.mod_q(phase - u[i] * secret_key[i]);
            }

            // Decrypt message using integer arithmetic
            let scaled_phase = ((phase * self.params.t + self.params.q / 2) / self.params.q)
                .rem_euclid(self.params.t);

            bits.push_str(&scaled_phase.to_string());
        }

        let mut message = String::new();
        for chunk in bits.chars().collect::<Vec<_>>().chunks(8) {
            if chunk.len() == 8 {
                if let Ok(byte) = u8::from_str_radix(&chunk.iter().collect::<String>(), 2) {
                    message.push(byte as char);
                }
            }
        }

        message
    }
}

fn main() {
    println!("Initializing LWE-based FHE scheme...");
    
    let fhe = EnhancedLWEBasedFHE::new(
        256,    // n
        40961,  // q
        2,      // t
        3.2     // std_dev
    );

    let keys = fhe.generate_keys();
    println!("Keys generated successfully");

    let message = "Hello, World!";
    println!("\nOriginal message: {}", message);

    let ciphertext = fhe.encrypt(message, &keys.public_key);
    println!("Message encrypted");

    let decrypted = fhe.decrypt(&ciphertext, &keys.secret_key);
    println!("\nDecrypted message: {}", decrypted);

    if message == decrypted {
        println!("Success: Messages match!");
    } else {
        println!("Failed: Messages don't match!");
        println!("Expected: {}", message);
        println!("Got: {}", decrypted);
    }
}
