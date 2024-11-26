from typing import Tuple
import secrets
from hashlib import sha256

class PedersenCommitment:
    """
    Implementation of Pedersen Commitment Scheme with detailed output.
    """
    
    def __init__(self, bits: int = 256):
        """Initialize the commitment scheme with detailed output."""
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        
        print(f"\n[Setup] Using prime modulus p: {hex(self.p)}")
        
        # Generator points
        self.g = self._hash_to_point("g")
        self.h = self._hash_to_point("h")
        
        print(f"[Setup] Generated base point g: {hex(self.g)}")
        print(f"[Setup] Generated base point h: {hex(self.h)}")
        
    def _hash_to_point(self, seed: str) -> int:
        """Hash a seed string to a point with output."""
        attempts = 0
        while True:
            attempts += 1
            hash_bytes = sha256(seed.encode()).digest()
            point = int.from_bytes(hash_bytes, 'big') % self.p
            if point != 0:
                print(f"[Hash-to-Point] Generated point from seed '{seed}' in {attempts} attempt(s)")
                return point
            seed += '1'
    
    def commit(self, value: int) -> Tuple[int, int]:
        """Create a commitment with detailed output."""
        print(f"\n[Commit] Creating commitment for value: {value}")
        
        # Generate random blinding factor
        r = secrets.randbelow(self.p)
        print(f"[Commit] Generated random blinding factor r: {hex(r)}")
        
        # Calculate intermediate values for educational purposes
        g_v = pow(self.g, value, self.p)
        h_r = pow(self.h, r, self.p)
        print(f"[Commit] Calculated g^value = {hex(g_v)}")
        print(f"[Commit] Calculated h^r = {hex(h_r)}")
        
        # Compute commitment: C = g^value * h^r mod p
        commitment = (g_v * h_r) % self.p
        
        print(f"[Commit] Final commitment C = {hex(commitment)}")
        return commitment, r
    
    def verify(self, commitment: int, value: int, r: int) -> bool:
        """Verify a commitment opening with detailed output."""
        print(f"\n[Verify] Verifying commitment...")
        print(f"[Verify] Claimed value: {value}")
        print(f"[Verify] Provided randomness r: {hex(r)}")
        print(f"[Verify] Original commitment: {hex(commitment)}")
        
        # Calculate intermediate values
        g_v = pow(self.g, value, self.p)
        h_r = pow(self.h, r, self.p)
        print(f"[Verify] Calculated g^value = {hex(g_v)}")
        print(f"[Verify] Calculated h^r = {hex(h_r)}")
        
        # Recompute commitment
        expected = (g_v * h_r) % self.p
        print(f"[Verify] Recomputed commitment: {hex(expected)}")
        
        # Check if they match
        result = commitment == expected
        print(f"[Verify] Verification result: {'SUCCESS' if result else 'FAILURE'}")
        
        return result

    def demonstrate_homomorphic(self, value1: int, value2: int) -> None:
        """Demonstrate the homomorphic properties of Pedersen commitments."""
        print("\n[Homomorphic Demo] Starting demonstration of homomorphic properties")
        
        # Create commitments for individual values
        print("\n[Homomorphic Demo] Creating commitment for first value...")
        c1, r1 = self.commit(value1)
        
        print("\n[Homomorphic Demo] Creating commitment for second value...")
        c2, r2 = self.commit(value2)
        
        # Create commitment for sum
        print("\n[Homomorphic Demo] Creating commitment for sum directly...")
        c_sum, r_sum = self.commit(value1 + value2)
        
        # Compute product of commitments
        print("\n[Homomorphic Demo] Computing product of individual commitments...")
        c_product = (c1 * c2) % self.p
        r_product = (r1 + r2) % self.p
        
        print(f"[Homomorphic Demo] C1: {hex(c1)}")
        print(f"[Homomorphic Demo] C2: {hex(c2)}")
        print(f"[Homomorphic Demo] C_product: {hex(c_product)}")
        print(f"[Homomorphic Demo] C_sum: {hex(c_sum)}")
        
        # Verify homomorphic property
        is_homomorphic = self.verify(c_product, value1 + value2, r_product)
        print(f"\n[Homomorphic Demo] Homomorphic property verification: {'SUCCESS' if is_homomorphic else 'FAILURE'}")


def main():
    # Initialize the commitment scheme
    print("\n=== Initializing Pedersen Commitment Scheme ===")
    pedersen = PedersenCommitment()
    
    # Test basic commitment functionality
    print("\n=== Testing Basic Commitment ===")
    secret_value = 42
    commitment, randomness = pedersen.commit(secret_value)
    
    # Verify valid commitment
    print("\n=== Testing Valid Verification ===")
    is_valid = pedersen.verify(commitment, secret_value, randomness)
    
    # Try to verify with wrong value
    print("\n=== Testing Invalid Verification ===")
    is_valid_fake = pedersen.verify(commitment, 43, randomness)
    
    # Demonstrate homomorphic properties
    print("\n=== Testing Homomorphic Properties ===")
    pedersen.demonstrate_homomorphic(24, 18)  # 24 + 18 = 42

if __name__ == "__main__":
    main()
