from typing import Tuple
import secrets
import sympy
import hashlib

class ElGamalSignature:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self._generate_keys()
    
    def _generate_keys(self) -> None:
        self.p = sympy.randprime(2**(self.key_size-1), 2**self.key_size)
        
        # Find generator
        self.g = 2
        while pow(self.g, (self.p-1)//2, self.p) == 1:
            self.g += 1
        
        # Private key
        self.private_key = secrets.randbelow(self.p - 2) + 1
        # Public key
        self.public_key = pow(self.g, self.private_key, self.p)
    
    def _hash_message(self, message: str) -> int:
        """Hash the message and convert to integer."""
        h = hashlib.sha256(message.encode()).hexdigest()
        return int(h, 16)
    
    def sign(self, message: str) -> Tuple[int, int]:
        """Sign a message using ElGamal signature scheme."""
        h = self._hash_message(message)
        
        # Generate ephemeral key k
        while True:
            k = secrets.randbelow(self.p - 2) + 1
            if sympy.gcd(k, self.p - 1) == 1:
                break
        
        # Calculate signature components
        r = pow(self.g, k, self.p)
        k_inv = pow(k, -1, self.p - 1)
        s = (k_inv * (h - self.private_key * r)) % (self.p - 1)
        
        return (r, s)
    
    def verify(self, message: str, signature: Tuple[int, int]) -> bool:
        """Verify an ElGamal signature."""
        r, s = signature
        if not (0 < r < self.p and 0 < s < self.p - 1):
            return False
        
        h = self._hash_message(message)
        
        # Verify signature: g^h ≡ y^r * r^s (mod p)
        left = pow(self.g, h, self.p)
        right = (pow(self.public_key, r, self.p) * pow(r, s, self.p)) % self.p
        
        return left == right

def demo():
    print("Initializing ElGamal signature scheme...")
    elgamal = ElGamalSignature(key_size=2048)
    
    message = "Hello, World!"
    print(f"\nMessage to sign: {message}")
    
    signature = elgamal.sign(message)
    print(f"\nSignature (r,s): {signature}")
    
    is_valid = elgamal.verify(message, signature)
    print(f"\nSignature valid: {is_valid}")
    
    # Test with tampered message
    tampered = message + "!"
    is_valid = elgamal.verify(tampered, signature)
    print(f"\nTampered message verification: {is_valid}")

if __name__ == "__main__":
    demo()
