use num_bigint::BigUint;
use rand::{Rng, thread_rng};
use std::error::Error;
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DHError {
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Security check failed: {0}")]
    SecurityCheckFailed(String),
}

pub struct DiffieHellman {
    prime: BigUint,
    private_key: BigUint,
    public_key: BigUint,
}

// RFC 3526 MODP Group 14 parameters (2048 bits)
const MODP_2048_PRIME: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
const MODP_2048_GENERATOR: &str = "2";

// Security parameters
const MIN_PRIME_BITS: u64 = 2048;
const MIN_PRIVATE_KEY_BITS: u64 = 256;
const MIN_PUBLIC_KEY: u32 = 2;

impl DiffieHellman {
    /// Creates a new DiffieHellman instance using RFC 3526 MODP Group 14 (2048 bits)
    pub fn new() -> Result<Self, DHError> {
        let prime = BigUint::parse_bytes(MODP_2048_PRIME.as_bytes(), 16)
            .ok_or_else(|| DHError::InvalidParameters("Failed to parse prime".to_string()))?;
        
        let generator = BigUint::parse_bytes(MODP_2048_GENERATOR.as_bytes(), 16)
            .ok_or_else(|| DHError::InvalidParameters("Failed to parse generator".to_string()))?;

        Self::new_with_params(prime, &generator)
    }

    /// Creates a new DiffieHellman instance with custom parameters
    pub fn new_with_params(prime: BigUint, generator: &BigUint) -> Result<Self, DHError> {
        // Validate prime size
        if prime.bits() < MIN_PRIME_BITS {
            return Err(DHError::SecurityCheckFailed(
                format!("Prime must be at least {} bits", MIN_PRIME_BITS)
            ));
        }

        // Generate cryptographically secure private key
        let private_key = Self::generate_private_key(&prime)?;
        
        // Calculate public key: g^private_key mod p
        let public_key = generator.modpow(&private_key, &prime);

        // Validate public key
        Self::validate_public_key(&public_key, &prime)?;

        Ok(DiffieHellman {
            prime,
            private_key,
            public_key,
        })
    }

    fn generate_private_key(prime: &BigUint) -> Result<BigUint, DHError> {
        let mut rng = thread_rng();
        
        // Generate random bytes for private key
        let key_size = (MIN_PRIVATE_KEY_BITS / 8) as usize;
        let key_bytes: Vec<u8> = (0..key_size)
            .map(|_| rng.gen())
            .collect();
        
        let mut private_key = BigUint::from_bytes_be(&key_bytes);
        
        // Ensure private key is in range [2, p-2]
        private_key %= prime - BigUint::from(2u32);
        private_key += BigUint::from(MIN_PUBLIC_KEY);
        
        Ok(private_key)
    }

    fn validate_public_key(key: &BigUint, prime: &BigUint) -> Result<(), DHError> {
        let min_value = BigUint::from(MIN_PUBLIC_KEY);
        let max_value = prime - BigUint::from(1u32);

        if key <= &min_value || key >= &max_value {
            return Err(DHError::InvalidPublicKey);
        }
        Ok(())
    }

    /// Returns the public key to be shared with the other party
    pub fn get_public_key(&self) -> &BigUint {
        &self.public_key
    }

    /// Generates the shared secret from the other party's public key
    pub fn generate_shared_secret(&self, other_public_key: &BigUint) -> Result<BigUint, DHError> {
        Self::validate_public_key(other_public_key, &self.prime)?;
        
        let shared_secret = other_public_key.modpow(&self.private_key, &self.prime);
        Self::validate_public_key(&shared_secret, &self.prime)?;
        
        Ok(shared_secret)
    }

    /// Converts the shared secret to bytes suitable for use as a cryptographic key
    pub fn shared_secret_to_bytes(shared_secret: &BigUint) -> Vec<u8> {
        shared_secret.to_bytes_be()
    }
}

impl fmt::Debug for DiffieHellman {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiffieHellman")
            .field("public_key", &self.public_key)
            .field("prime_bits", &self.prime.bits())
            .finish_non_exhaustive()
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("Initializing Diffie-Hellman key exchange using {} bit prime...\n", MIN_PRIME_BITS);
    
    let alice = DiffieHellman::new()?;
    let bob = DiffieHellman::new()?;
    
    println!("Public keys generated:");
    println!("Alice's public key bits: {}", alice.get_public_key().bits());
    println!("Bob's public key bits: {}\n", bob.get_public_key().bits());
    
    let alice_shared_secret = alice.generate_shared_secret(bob.get_public_key())?;
    let bob_shared_secret = bob.generate_shared_secret(alice.get_public_key())?;
    
    let alice_key = DiffieHellman::shared_secret_to_bytes(&alice_shared_secret);
    let bob_key = DiffieHellman::shared_secret_to_bytes(&bob_shared_secret);
    
    assert_eq!(alice_key, bob_key, "Shared secrets don't match!");
    
    println!("Key exchange successful!");
    println!("Shared secret length: {} bits", alice_shared_secret.bits());
    println!("Derived key length: {} bytes", alice_key.len());
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let alice = DiffieHellman::new().unwrap();
        let bob = DiffieHellman::new().unwrap();
        
        let alice_secret = alice.generate_shared_secret(bob.get_public_key()).unwrap();
        let bob_secret = bob.generate_shared_secret(alice.get_public_key()).unwrap();
        
        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_invalid_public_key() {
        let alice = DiffieHellman::new().unwrap();
        let invalid_key = BigUint::from(1u32);
        
        assert!(alice.generate_shared_secret(&invalid_key).is_err());
    }

    #[test]
    fn test_key_size() {
        let dh = DiffieHellman::new().unwrap();
        assert!(dh.get_public_key().bits() >= MIN_PRIME_BITS);
    }

    #[test]
    fn test_private_key_generation() {
        let prime = BigUint::parse_bytes(MODP_2048_PRIME.as_bytes(), 16).unwrap();
        let private_key = DiffieHellman::generate_private_key(&prime).unwrap();
        assert!(private_key >= BigUint::from(MIN_PUBLIC_KEY));
        assert!(private_key < prime - BigUint::from(2u32));
    }
}