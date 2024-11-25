use num_bigint::BigUint;
use rand::{RngCore, thread_rng};
use std::error::Error;
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ECDHError {
    #[error("Invalid point: {0}")]
    InvalidPoint(String),
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Point not on curve")]
    PointNotOnCurve,
}

/// Represents a point on an elliptic curve
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    /// X coordinate
    pub x: BigUint,
    /// Y coordinate
    pub y: BigUint,
    /// Whether this is the point at infinity
    pub infinity: bool,
}

/// Parameters for the elliptic curve
/// Uses the short Weierstrass form: y² = x³ + ax + b (mod p)
#[derive(Clone)]
struct CurveParams {
    p: BigUint,  // Field characteristic
    a: BigUint,  // Curve coefficient a
    b: BigUint,  // Curve coefficient b
    g: Point,    // Base point
    n: BigUint,  // Order of base point
}

impl CurveParams {
    /// Initialize NIST P-256 curve parameters
    fn p256() -> Self {
        let p = BigUint::parse_bytes(b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16).unwrap();
        let a = BigUint::parse_bytes(b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16).unwrap();
        let b = BigUint::parse_bytes(b"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16).unwrap();
        let gx = BigUint::parse_bytes(b"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16).unwrap();
        let gy = BigUint::parse_bytes(b"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16).unwrap();
        let n = BigUint::parse_bytes(b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16).unwrap();

        let g = Point {
            x: gx,
            y: gy,
            infinity: false,
        };

        CurveParams { p, a, b, g, n }
    }
}

/// Implementation of Elliptic Curve Diffie-Hellman using NIST P-256
pub struct ECDH {
    params: CurveParams,
    private_key: BigUint,
    public_key: Point,
}

impl Point {
    /// Creates a new point at infinity
    pub fn infinity() -> Self {
        Point {
            x: BigUint::from(0u32),
            y: BigUint::from(0u32),
            infinity: true,
        }
    }

    /// Check if the point lies on the curve
    fn is_on_curve(&self, params: &CurveParams) -> bool {
        if self.infinity {
            return true;
        }

        // Calculate left side: y²
        let y_squared = &self.y * &self.y % &params.p;

        // Calculate right side: x³ - 3x + b
        let x_cubed = self.x.modpow(&BigUint::from(3u32), &params.p);
        let three_x = (&self.x * BigUint::from(3u32)) % &params.p;
        let mut right_side = (x_cubed + &params.b) % &params.p;
        if three_x <= right_side {
            right_side -= three_x;
        } else {
            right_side = &params.p - (three_x - right_side);
        }

        y_squared == right_side
    }

    // Add two points on the curve
    fn add(&self, other: &Point, params: &CurveParams) -> Result<Point, ECDHError> {
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

        // Calculate slope = (y2-y1)/(x2-x1)
        let mut dx = (&other.x + &params.p) - &self.x;
        dx %= &params.p;
        let mut dy = (&other.y + &params.p) - &self.y;
        dy %= &params.p;
        
        // Modular multiplicative inverse using Fermat's little theorem
        let dx_inv = dx.modpow(&(&params.p - BigUint::from(2u32)), &params.p);
        let slope = (&dy * &dx_inv) % &params.p;

        // Calculate x3 = slope² - x1 - x2
        let slope_squared = (&slope * &slope) % &params.p;
        let mut x3 = slope_squared;
        x3 = (x3 + &params.p - &self.x) % &params.p;
        x3 = (x3 + &params.p - &other.x) % &params.p;

        // Calculate y3 = slope(x1 - x3) - y1
        let mut y3 = (&self.x + &params.p) - &x3;
        y3 = (y3 * &slope) % &params.p;
        y3 = (y3 + &params.p - &self.y) % &params.p;

        let result = Point { x: x3, y: y3, infinity: false };
        if !result.is_on_curve(params) {
            return Err(ECDHError::PointNotOnCurve);
        }

        Ok(result)
    }

    fn double(&self, params: &CurveParams) -> Result<Point, ECDHError> {
        if self.infinity {
            return Ok(self.clone());
        }

        // Calculate slope = (3x²+a)/(2y)
        let x_squared = (&self.x * &self.x) % &params.p;
        let numerator = (BigUint::from(3u32) * x_squared + &params.a) % &params.p;
        let denominator = (BigUint::from(2u32) * &self.y) % &params.p;
        let denominator_inv = denominator.modpow(&(&params.p - BigUint::from(2u32)), &params.p);
        let slope = (&numerator * &denominator_inv) % &params.p;

        // Calculate x3 = slope² - 2x
        let slope_squared = (&slope * &slope) % &params.p;
        let mut x3 = slope_squared;
        x3 = (x3 + &params.p - &self.x) % &params.p;
        x3 = (x3 + &params.p - &self.x) % &params.p;

        // Calculate y3 = slope(x - x3) - y
        let mut y3 = (&self.x + &params.p) - &x3;
        y3 = (y3 * &slope) % &params.p;
        y3 = (y3 + &params.p - &self.y) % &params.p;

        let result = Point { x: x3, y: y3, infinity: false };
        if !result.is_on_curve(params) {
            return Err(ECDHError::PointNotOnCurve);
        }

        Ok(result)
    }

    fn scalar_mul(&self, scalar: &BigUint, params: &CurveParams) -> Result<Point, ECDHError> {
        let mut result = Point::infinity();
        let temp = self.clone();
        let scalar_bits = scalar.to_bytes_be();

        for byte in scalar_bits {
            for i in (0..8).rev() {
                result = result.double(params)?;
                if ((byte >> i) & 1) == 1 {
                    result = result.add(&temp, params)?;
                }
            }
        }

        Ok(result)
    }
}

impl ECDH {
    /// Creates a new ECDH instance using NIST P-256
    pub fn new() -> Result<Self, ECDHError> {
        let params = CurveParams::p256();
        let private_key = Self::generate_private_key(&params.n)?;
        let public_key = params.g.scalar_mul(&private_key, &params)?;

        Ok(ECDH {
            params,
            private_key,
            public_key,
        })
    }

    fn generate_private_key(n: &BigUint) -> Result<BigUint, ECDHError> {
        let mut rng = thread_rng();
        let mut bytes = vec![0u8; 32];
        
        loop {
            rng.try_fill_bytes(&mut bytes).map_err(|_| ECDHError::InvalidPrivateKey)?;
            let key = BigUint::from_bytes_be(&bytes);
            if key > BigUint::from(0u32) && key < *n {
                return Ok(key);
            }
        }
    }

    /// Returns the public key to share with the other party
    pub fn get_public_key(&self) -> &Point {
        &self.public_key
    }

    /// Generates the shared secret using the other party's public key
    pub fn generate_shared_secret(&self, other_public: &Point) -> Result<Vec<u8>, ECDHError> {
        if !other_public.is_on_curve(&self.params) {
            return Err(ECDHError::InvalidPoint("Public key not on curve".to_string()));
        }

        let shared_point = other_public.scalar_mul(&self.private_key, &self.params)?;
        Ok(shared_point.x.to_bytes_be())
    }
}

impl fmt::Debug for ECDH {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ECDH")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("Initializing ECDH key exchange using NIST P-256...\n");
    
    let alice = ECDH::new()?;
    let bob = ECDH::new()?;
    
    println!("Public keys generated successfully");
    
    let alice_shared = alice.generate_shared_secret(bob.get_public_key())?;
    let bob_shared = bob.generate_shared_secret(alice.get_public_key())?;
    
    assert_eq!(alice_shared, bob_shared, "Shared secrets don't match!");
    
    println!("Key exchange successful!");
    println!("Shared secret length: {} bytes", alice_shared.len());
    println!("First few bytes of shared secret: {:02x?}", &alice_shared[..4]);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let alice = ECDH::new().unwrap();
        let bob = ECDH::new().unwrap();
        
        let alice_shared = alice.generate_shared_secret(bob.get_public_key()).unwrap();
        let bob_shared = bob.generate_shared_secret(alice.get_public_key()).unwrap();
        
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_point_on_curve() {
        let params = CurveParams::p256();
        assert!(params.g.is_on_curve(&params));
    }

    #[test]
    fn test_point_addition() {
        let params = CurveParams::p256();
        let result = params.g.add(&params.g, &params).unwrap();
        assert!(result.is_on_curve(&params));
    }

    #[test]
    fn test_scalar_multiplication() {
        let params = CurveParams::p256();
        let scalar = BigUint::from(2u32);
        let double_g = params.g.scalar_mul(&scalar, &params).unwrap();
        let add_g = params.g.add(&params.g, &params).unwrap();
        assert_eq!(double_g, add_g);
    }
}