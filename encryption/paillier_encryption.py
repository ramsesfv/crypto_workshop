from typing import Tuple, Any
import pickle
import secrets
import sympy
import math

class Paillier:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self._generate_keys()
    
    def _generate_keys(self) -> None:
        p = sympy.randprime(2**(self.key_size//2-1), 2**(self.key_size//2))
        q = sympy.randprime(2**(self.key_size//2-1), 2**(self.key_size//2))
        
        self.n = p * q
        self.g = self.n + 1
        self.lambda_n = math.lcm(p - 1, q - 1)
        self.mu = pow(self._L(pow(self.g, self.lambda_n, self.n**2), self.n), -1, self.n)
    
    def _L(self, x: int, n: int) -> int:
        return (x - 1) // n
    
    def _encode_message(self, message: Any) -> int:
        if isinstance(message, int):
            return message
        message_bytes = pickle.dumps(message)
        return int.from_bytes(message_bytes, byteorder='big')
    
    def _decode_message(self, number: int, expect_pickle: bool = True) -> Any:
        if not expect_pickle:
            return number
        try:
            message_bytes = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')
            return pickle.loads(message_bytes)
        except (OverflowError, pickle.UnpicklingError) as e:
            raise ValueError(f"Failed to decode message: {e}")
    
    def encrypt(self, message: Any) -> int:
        m = self._encode_message(message)
        if m >= self.n:
            raise ValueError("Message too large for current key size")
        
        while True:
            r = secrets.randbelow(self.n - 1) + 1
            if math.gcd(r, self.n) == 1:
                break
        
        n_sq = self.n * self.n
        c = (pow(self.g, m, n_sq) * pow(r, self.n, n_sq)) % n_sq
        
        return c
    
    def decrypt(self, ciphertext: int, expect_pickle: bool = True) -> Any:
        if not (0 < ciphertext < self.n * self.n):
            raise ValueError("Invalid ciphertext")
        
        n_sq = self.n * self.n
        m = (self._L(pow(ciphertext, self.lambda_n, n_sq), self.n) * self.mu) % self.n
        
        return self._decode_message(m, expect_pickle)
    
    def homomorphic_add(self, c1: int, c2: int) -> int:
        return (c1 * c2) % (self.n * self.n)
    
    def homomorphic_add_constant(self, c: int, k: int) -> int:
        return (c * pow(self.g, k, self.n * self.n)) % (self.n * self.n)
    
    def homomorphic_multiply_constant(self, c: int, k: int) -> int:
        return pow(c, k, self.n * self.n)

def demo():
    print("Initializing Paillier cryptosystem...")
    paillier = Paillier(key_size=2048)
    
    # Test basic encryption/decryption
    message = "Hello, World!"
    print(f"\nOriginal message: {message}")
    
    cipher = paillier.encrypt(message)
    print(f"\nEncrypted: {cipher}")
    
    decrypted = paillier.decrypt(cipher)
    print(f"\nDecrypted: {decrypted}")
    
    # Test homomorphic properties with integers
    m1, m2 = 30, 12
    c1 = paillier.encrypt(m1)
    c2 = paillier.encrypt(m2)
    
    # Addition
    c_sum = paillier.homomorphic_add(c1, c2)
    sum_decrypted = paillier.decrypt(c_sum, expect_pickle=False)
    print(f"\nHomomorphic addition: {m1} + {m2} = {sum_decrypted}")
    
    # Multiplication by constant
    k = 3
    c_mult = paillier.homomorphic_multiply_constant(c1, k)
    mult_decrypted = paillier.decrypt(c_mult, expect_pickle=False)
    print(f"\nHomomorphic multiplication: {k} * {m1} = {mult_decrypted}")

if __name__ == "__main__":
    demo()
