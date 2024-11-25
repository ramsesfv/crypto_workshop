from typing import Tuple, Any
import pickle
import secrets
from math import gcd
import sympy

class ElGamal:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self._generate_keys()
    
    def _generate_keys(self) -> None:
        """Generate public and private keys using pre-generated primes."""
        # Use sympy's built-in prime generation
        self.p = sympy.randprime(2**(self.key_size-1), 2**self.key_size)
        
        # Find generator (smaller range for efficiency)
        self.g = 2
        while pow(self.g, (self.p-1)//2, self.p) == 1:
            self.g += 1
        
        # Generate private and public keys
        self.private_key = secrets.randbelow(self.p - 2) + 1
        self.public_key = pow(self.g, self.private_key, self.p)
    
    def _encode_message(self, message: Any) -> int:
        message_bytes = pickle.dumps(message)
        return int.from_bytes(message_bytes, byteorder='big')
    
    def _decode_message(self, number: int) -> Any:
        try:
            message_bytes = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')
            return pickle.loads(message_bytes)
        except (OverflowError, pickle.UnpicklingError) as e:
            raise ValueError(f"Failed to decode message: {e}")
    
    def encrypt(self, message: Any) -> Tuple[int, int]:
        m = self._encode_message(message)
        if m >= self.p:
            raise ValueError("Message too large for current key size")
        
        k = secrets.randbelow(self.p - 2) + 1
        while gcd(k, self.p - 1) != 1:
            k = secrets.randbelow(self.p - 2) + 1
        
        c1 = pow(self.g, k, self.p)
        s = pow(self.public_key, k, self.p)
        c2 = (m * s) % self.p
        
        return (c1, c2)
    
    def decrypt(self, cipher: Tuple[int, int]) -> Any:
        c1, c2 = cipher
        if not (0 < c1 < self.p and 0 < c2 < self.p):
            raise ValueError("Invalid ciphertext")
        
        s = pow(c1, self.private_key, self.p)
        s_inv = pow(s, -1, self.p)
        m = (c2 * s_inv) % self.p
        
        return self._decode_message(m)

def demo():
    print("Initializing ElGamal cryptosystem...")
    elgamal = ElGamal(key_size=2048)
    
    message = "Hello, World!"
    print(f"\nOriginal message: {message}")
    
    cipher = elgamal.encrypt(message)
    print(f"\nEncrypted (c1, c2):\nc1: {cipher[0]}\nc2: {cipher[1]}")
    
    decrypted = elgamal.decrypt(cipher)
    print(f"\nDecrypted message: {decrypted}")
    
    assert decrypted == message, "Decryption failed!"
    print("\nVerification: Success!")

if __name__ == "__main__":
    demo()
