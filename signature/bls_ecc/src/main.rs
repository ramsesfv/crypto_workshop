use num_bigint::BigUint;
use sha2::{Sha256, Digest as Sha2Digest};
use std::error::Error;
use std::fmt::{self, Debug, Formatter};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BLSError {
    #[error("Invalid point: {0}")]
    InvalidPoint(String),
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Point not on curve")]
    PointNotOnCurve,
    #[error("Hash to curve failed")]
    HashToCurveFailed,
}

/// Represents a point on an elliptic curve
#[derive(Clone, PartialEq)]
pub struct Point {
    pub x: BigUint,
    pub y: BigUint,
    pub infinity: bool,
}

impl Debug for Point {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.infinity {
            write!(f, "Point::Infinity")
        } else {
            write!(f, "Point {{ x: 0x{:x}, y: 0x{:x} }}", self.x, self.y)
        }
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.infinity {
            write!(f, "∞")
        } else {
            let x_hex = format!("{:x}", self.x);
            let y_hex = format!("{:x}", self.y);
            write!(f, "(0x{}...{}, 0x{}...{})", 
                &x_hex[..4], &x_hex[x_hex.len()-4..],
                &y_hex[..4], &y_hex[y_hex.len()-4..])
        }
    }
}

#[derive(Debug)]
struct CurveParams {
    p: BigUint,     // Field characteristic
    a: BigUint,     // Curve coefficient a
    b: BigUint,     // Curve coefficient b
    g: Point,       // Generator point
    n: BigUint,     // Order of base point
}

impl CurveParams {
    fn new() -> Self {
        // Example parameters - not for production use
        let p = BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", 16).unwrap();
        let a = BigUint::from(0u32);
        let b = BigUint::from(3u32);
        let gx = BigUint::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap();
        let gy = BigUint::parse_bytes(b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap();
        let n = BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();

        let g = Point {
            x: gx,
            y: gy,
            infinity: false,
        };

        CurveParams { p, a, b, g, n }
    }
}

pub struct BLS {
    params: CurveParams,
    private_key: BigUint,
    public_key: Point,
}

impl BLS {
    pub fn new() -> Result<Self, BLSError> {
        let params = CurveParams::new();
        let private_key = Self::generate_private_key(&params.n)?;
        let public_key = params.g.clone();  // Simplified for this example

        Ok(BLS {
            params,
            private_key,
            public_key,
        })
    }

    fn generate_private_key(n: &BigUint) -> Result<BigUint, BLSError> {
        use rand::{RngCore, thread_rng};
        let mut rng = thread_rng();
        let mut bytes = vec![0u8; 32];
        
        loop {
            rng.try_fill_bytes(&mut bytes).map_err(|_| BLSError::InvalidPrivateKey)?;
            let key = BigUint::from_bytes_be(&bytes);
            if key > BigUint::from(0u32) && key < *n {
                return Ok(key);
            }
        }
    }

    pub fn get_public_key(&self) -> &Point {
        &self.public_key
    }

    fn hash_to_curve(&self, message: &[u8]) -> Result<Point, BLSError> {
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        
        let mut counter = 0u32;
        loop {
            if counter > 1000 {
                return Err(BLSError::HashToCurveFailed);
            }

            let mut attempt = hash.to_vec();
            attempt.extend_from_slice(&counter.to_be_bytes());
            
            let mut hasher = Sha256::new();
            hasher.update(&attempt);
            let x_bytes = hasher.finalize();
            
            let x = BigUint::from_bytes_be(&x_bytes);
            let x = x % &self.params.p;

            // Calculate y² = x³ + ax + b
            let x_cubed = x.modpow(&BigUint::from(3u32), &self.params.p);
            let ax = (&self.params.a * &x) % &self.params.p;
            let y_squared = (x_cubed + ax + &self.params.b) % &self.params.p;

            if let Some(y) = self.sqrt_mod_p(&y_squared) {
                let point = Point { x, y, infinity: false };
                if point.is_on_curve(&self.params) {
                    return Ok(point);
                }
            }

            counter += 1;
        }
    }

    fn sqrt_mod_p(&self, n: &BigUint) -> Option<BigUint> {
        if &self.params.p % BigUint::from(4u32) != BigUint::from(3u32) {
            return None;
        }

        let exp = (&self.params.p + BigUint::from(1u32)) / BigUint::from(4u32);
        let root = n.modpow(&exp, &self.params.p);
        
        if (&root * &root) % &self.params.p == *n {
            Some(root)
        } else {
            None
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Point, BLSError> {
        let h = self.hash_to_curve(message)?;
        Point::scalar_mul(&h, &self.private_key, &self.params)
    }

    pub fn verify(&self, message: &[u8], signature: &Point) -> Result<bool, BLSError> {
        if !signature.is_on_curve(&self.params) {
            return Err(BLSError::InvalidSignature);
        }

        let h = self.hash_to_curve(message)?;
        let expected = Point::scalar_mul(&h, &self.private_key, &self.params)?;

        Ok(signature == &expected)
    }
}

impl Debug for BLS {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BLS")
            .field("public_key", &self.public_key)
            .field("curve_order", &format!("0x{:x}", self.params.n))
            .finish_non_exhaustive()
    }
}

// Move scalar multiplication to Point implementation
impl Point {
    pub fn infinity() -> Self {
        Point {
            x: BigUint::from(0u32),
            y: BigUint::from(0u32),
            infinity: true,
        }
    }

    fn is_on_curve(&self, params: &CurveParams) -> bool {
        if self.infinity {
            return true;
        }

        let y_squared = &self.y * &self.y % &params.p;
        let x_cubed = self.x.modpow(&BigUint::from(3u32), &params.p);
        let ax = (&params.a * &self.x) % &params.p;
        let right_side = (x_cubed + ax + &params.b) % &params.p;

        y_squared == right_side
    }

    fn scalar_mul(point: &Point, scalar: &BigUint, params: &CurveParams) -> Result<Point, BLSError> {
        let mut result = Point::infinity();
        let mut temp = point.clone();
        let scalar_bits = scalar.to_bytes_be();

        for byte in scalar_bits {
            for i in (0..8).rev() {
                if !temp.infinity {
                    result = result.double(params)?;
                    if ((byte >> i) & 1) == 1 {
                        if !result.infinity {
                            result = result.add(&temp, params)?;
                        } else {
                            result = temp.clone();
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    fn add(&self, other: &Point, params: &CurveParams) -> Result<Point, BLSError> {
        if self.infinity {
            return Ok(other.clone());
        }
        if other.infinity {
            return Ok(self.clone());
        }

        if self.x == other.x {
            if self.y == other.y {
                return self.double(params);
            }
            return Ok(Point::infinity());
        }

        let p = &params.p;
        
        let dx = (&other.x + p - &self.x) % p;
        let dy = (&other.y + p - &self.y) % p;
        let dx_inv = dx.modpow(&(p - BigUint::from(2u32)), p);
        let s = (&dy * &dx_inv) % p;

        let s_squared = (&s * &s) % p;
        let mut x3 = s_squared;
        x3 = (x3 + p - &self.x) % p;
        x3 = (x3 + p - &other.x) % p;

        let mut y3 = (&self.x + p - &x3) % p;
        y3 = (s * y3) % p;
        y3 = (y3 + p - &self.y) % p;

        let result = Point { x: x3, y: y3, infinity: false };
        if !result.is_on_curve(params) {
            return Err(BLSError::PointNotOnCurve);
        }

        Ok(result)
    }

    fn double(&self, params: &CurveParams) -> Result<Point, BLSError> {
        if self.infinity {
            return Ok(self.clone());
        }

        let p = &params.p;
        
        let x_squared = (&self.x * &self.x) % p;
        let numerator = (BigUint::from(3u32) * &x_squared) % p;
        let denominator = (BigUint::from(2u32) * &self.y) % p;
        let denominator_inv = denominator.modpow(&(p - BigUint::from(2u32)), p);
        let s = (&numerator * &denominator_inv) % p;

        let s_squared = (&s * &s) % p;
        let mut x3 = s_squared;
        x3 = (x3 + p - &self.x) % p;
        x3 = (x3 + p - &self.x) % p;

        let mut y3 = (&self.x + p - &x3) % p;
        y3 = (s * y3) % p;
        y3 = (y3 + p - &self.y) % p;

        let result = Point { x: x3, y: y3, infinity: false };
        if !result.is_on_curve(params) {
            return Err(BLSError::PointNotOnCurve);
        }

        Ok(result)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("Initializing BLS signature scheme...\n");
    
    let bls = BLS::new()?;
    println!("Generated keypair: {:?}\n", bls);
    
    let message = b"Hello, BLS signatures!";
    println!("Signing message: {:?}", String::from_utf8_lossy(message));
    
    let signature = bls.sign(message)?;
    println!("Signature: {}\n", signature);
    
    println!("Verifying signature...");
    let valid = bls.verify(message, &signature)?;
    
    println!("Signature verification: {}", if valid { "SUCCESS" } else { "FAILED" });
    
    // Test with wrong message
    let wrong_message = b"Wrong message!";
    println!("\nTrying to verify with wrong message: {:?}", String::from_utf8_lossy(wrong_message));
    let invalid = bls.verify(wrong_message, &signature)?;
    println!("Invalid message verification (should be false): {}", invalid);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let bls = BLS::new().unwrap();
        let message = b"Test message";
        
        let signature = bls.sign(message).unwrap();
        let valid = bls.verify(message, &signature).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_different_messages() {
        let bls = BLS::new().unwrap();
        let message1 = b"Message 1";
        let message2 = b"Message 2";
        
        let signature = bls.sign(message1).unwrap();
        let valid = bls.verify(message2, &signature).unwrap();
        
        assert!(!valid);
    }

    #[test]
    fn test_hash_to_curve() {
        let bls = BLS::new().unwrap();
        let message = b"Test message";
        
        let point = bls.hash_to_curve(message).unwrap();
        assert!(point.is_on_curve(&bls.params));
    }

    #[test]
    fn test_point_operations() {
        let params = CurveParams::new();
        let p1 = params.g.clone();
        let p2 = p1.double(&params).unwrap();
        
        assert!(p2.is_on_curve(&params));
        
        let p3 = p1.add(&p2, &params).unwrap();
        assert!(p3.is_on_curve(&params));
    }
}