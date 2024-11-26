use num_bigint::{BigUint, ToBigUint};
use sha2::{Sha256, Digest};
use rand::Rng;

#[derive(Debug)]
pub struct PedersenCommitment {
    p: BigUint,
    g: BigUint,
    h: BigUint,
}

impl PedersenCommitment {
    /// Create a new instance of the Pedersen commitment scheme
    pub fn new() -> Self {
        println!("\n[Setup] Initializing Pedersen Commitment Scheme");
        
        // Using a smaller prime for testing to ensure all operations are within bounds
        let p = BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
            .expect("Failed to parse prime modulus");
        
        println!("[Setup] Using prime modulus p: {:#x}", p);
        
        let g = Self::hash_to_point("g", &p);
        let h = Self::hash_to_point("h", &p);
        
        println!("[Setup] Generated base point g: {:#x}", g);
        println!("[Setup] Generated base point h: {:#x}", h);
        
        Self { p, g, h }
    }
    
    /// Hash a seed string to a point in our group
    fn hash_to_point(seed: &str, p: &BigUint) -> BigUint {
        let mut attempts = 0;
        let mut current_seed = seed.to_string();
        
        loop {
            attempts += 1;
            let mut hasher = Sha256::new();
            hasher.update(current_seed.as_bytes());
            let hash = hasher.finalize();
            
            let point = BigUint::from_bytes_be(&hash) % p;
            if point != BigUint::from(0u32) {
                println!("[Hash-to-Point] Generated point from seed '{}' in {} attempt(s)", seed, attempts);
                return point;
            }
            current_seed.push('1');
        }
    }
    
    /// Generate a random BigUint below a given bound using rejection sampling
    fn random_below(bound: &BigUint) -> BigUint {
        let mut rng = rand::thread_rng();
        let byte_length = (bound.bits() + 7) / 8;
        
        loop {
            let mut bytes = vec![0u8; byte_length as usize];
            rng.fill(&mut bytes[..]);
            
            // Ensure the number is within the correct range
            let mask = (1u8 << (bound.bits() % 8)) - 1;
            if byte_length > 0 {
                bytes[0] &= mask;
            }
            
            let num = BigUint::from_bytes_be(&bytes);
            if num < *bound && num != BigUint::from(0u32) {
                return num;
            }
        }
    }
    
    /// Create a commitment to a value
    pub fn commit(&self, value: u64) -> (BigUint, BigUint) {
        println!("\n[Commit] Creating commitment for value: {}", value);
        
        // Convert value to BigUint
        let value_big = value.to_biguint().unwrap();
        
        // Generate random value using rejection sampling
        let r = Self::random_below(&self.p);
        println!("[Commit] Generated random blinding factor r: {:#x}", r);
        
        // Calculate intermediate values using modular exponentiation
        let g_v = self.g.modpow(&value_big, &self.p);
        let h_r = self.h.modpow(&r, &self.p);
        
        println!("[Commit] Calculated g^value = {:#x}", g_v);
        println!("[Commit] Calculated h^r = {:#x}", h_r);
        
        // Compute commitment: C = g^value * h^r mod p
        let commitment = (g_v * h_r) % &self.p;
        
        println!("[Commit] Final commitment C = {:#x}", commitment);
        (commitment, r)
    }
    
    /// Verify a commitment opening
    pub fn verify(&self, commitment: &BigUint, value: u64, r: &BigUint) -> bool {
        println!("\n[Verify] Verifying commitment...");
        println!("[Verify] Claimed value: {}", value);
        println!("[Verify] Provided randomness r: {:#x}", r);
        println!("[Verify] Original commitment: {:#x}", commitment);
        
        // Convert value to BigUint
        let value_big = value.to_biguint().unwrap();
        
        // Calculate intermediate values
        let g_v = self.g.modpow(&value_big, &self.p);
        let h_r = self.h.modpow(r, &self.p);
        
        println!("[Verify] Calculated g^value = {:#x}", g_v);
        println!("[Verify] Calculated h^r = {:#x}", h_r);
        
        // Recompute commitment
        let expected = (g_v * h_r) % &self.p;
        println!("[Verify] Recomputed commitment: {:#x}", expected);
        
        let result = commitment == &expected;
        println!("[Verify] Verification result: {}", 
            if result { "SUCCESS" } else { "FAILURE" });
        
        result
    }
    
    /// Demonstrate the homomorphic properties of Pedersen commitments
    pub fn demonstrate_homomorphic(&self, value1: u64, value2: u64) {
        println!("\n[Homomorphic Demo] Starting demonstration of homomorphic properties");
        
        // Create commitments for individual values
        println!("\n[Homomorphic Demo] Creating commitment for first value...");
        let (c1, r1) = self.commit(value1);
        
        println!("\n[Homomorphic Demo] Creating commitment for second value...");
        let (c2, r2) = self.commit(value2);
        
        // Create commitment for sum
        println!("\n[Homomorphic Demo] Creating commitment for sum directly...");
        let (c_sum, _) = self.commit(value1 + value2);
        
        // Compute product of commitments
        println!("\n[Homomorphic Demo] Computing product of individual commitments...");
        let c_product = (c1.clone() * c2.clone()) % &self.p;
        let r_product = (r1 + r2) % &self.p;
        
        println!("[Homomorphic Demo] C1: {:#x}", c1);
        println!("[Homomorphic Demo] C2: {:#x}", c2);
        println!("[Homomorphic Demo] C_product: {:#x}", c_product);
        println!("[Homomorphic Demo] C_sum: {:#x}", c_sum);
        
        // Verify homomorphic property
        let is_homomorphic = self.verify(&c_product, value1 + value2, &r_product);
        println!("\n[Homomorphic Demo] Homomorphic property verification: {}", 
            if is_homomorphic { "SUCCESS" } else { "FAILURE" });
    }
}

fn main() {
    // Initialize the commitment scheme
    let pedersen = PedersenCommitment::new();
    
    // Test basic commitment functionality multiple times to ensure reliability
    for i in 1..=5 {
        println!("\n=== Test Run {} ===", i);
        
        let secret_value = 42;
        let (commitment, randomness) = pedersen.commit(secret_value);
        
        // Verify valid commitment
        println!("\n=== Testing Valid Verification ===");
        let is_valid = pedersen.verify(&commitment, secret_value, &randomness);
        assert!(is_valid, "Verification failed on test run {}", i);
        
        // Try to verify with wrong value
        println!("\n=== Testing Invalid Verification ===");
        let is_valid_fake = pedersen.verify(&commitment, 43, &randomness);
        assert!(!is_valid_fake, "False positive on test run {}", i);
    }
    
    // Demonstrate homomorphic properties
    println!("\n=== Testing Homomorphic Properties ===");
    pedersen.demonstrate_homomorphic(24, 18); // 24 + 18 = 42
}