import numpy as np
from typing import Tuple, List, Optional
from dataclasses import dataclass

@dataclass
class PublicParams:
    """Public parameters for the FHE scheme"""
    n: int       # Dimension of the lattice (security parameter)
    q: int       # Modulus for ciphertext space (large prime number)
    t: int       # Plaintext modulus (typically 2 for binary operations)
    std_dev: float  # Standard deviation for error distribution (noise)
    scale: int      # Scaling factor for encoding messages
    bootstrap_precision: int  # Number of bits of precision in bootstrapping

@dataclass
class KeyBundle:
    """Container for all keys used in the scheme"""
    secret_key: np.ndarray                    # Private key for decryption
    public_key: Tuple[np.ndarray, np.ndarray] # Public key for encryption
    eval_key: np.ndarray                      # Key for homomorphic operations
    bootstrap_key: np.ndarray                 # Key for bootstrapping procedure

class EnhancedLWEBasedFHE:
    def __init__(self, n: int = 256, q: int = 40961, t: int = 2, std_dev: float = 3.2, 
                 bootstrap_precision: int = 8):
        """Initialize the FHE scheme with specified parameters"""
        # Store all parameters in a PublicParams object for easy access
        self.params = PublicParams(
            n=n,                    # Lattice dimension (higher = more secure but slower)
            q=q,                    # Ciphertext modulus (prime number)
            t=t,                    # Plaintext modulus (2 for binary)
            std_dev=std_dev,        # Controls noise level
            scale=q // t,           # Scaling factor for encoding
            bootstrap_precision=bootstrap_precision  # Precision for bootstrapping
        )
        
    def generate_keys(self) -> KeyBundle:
        """Generate all necessary keys for the FHE scheme"""
        # Generate secret key as random binary vector
        s = np.random.randint(0, 2, size=self.params.n)
        
        # Generate public key components
        # Matrix A is uniformly random
        A = np.random.randint(0, self.params.q, size=(self.params.n, self.params.n))
        # Error vector from Gaussian distribution
        e = np.random.normal(0, self.params.std_dev, size=self.params.n)
        e = np.round(e) % self.params.q
        # Public key is (A, As + e)
        b = (A @ s + e) % self.params.q
        
        # Generate evaluation key for bootstrapping operations
        eval_key = self._generate_evaluation_key(s)
        
        # Generate bootstrap key for noise reduction
        bootstrap_key = self._generate_bootstrap_key(s)
        
        # Return all keys bundled together
        return KeyBundle(s, (A, b), eval_key, bootstrap_key)
    
    def _generate_evaluation_key(self, secret_key: np.ndarray) -> np.ndarray:
        """Generate evaluation key for homomorphic operations"""
        n = self.params.n
        q = self.params.q
        
        # Create tensor for storing key switching matrices
        eval_key = np.zeros((n, n, int(np.log2(q)) + 1), dtype=np.int64)
        # Generate powers of 2 for binary decomposition
        powers_of_two = [2**i for i in range(int(np.log2(q)) + 1)]
        
        # Generate key switching matrices for each bit position
        for i in range(n):
            for j, power in enumerate(powers_of_two):
                # Generate random error vector
                error = np.random.normal(0, self.params.std_dev, size=n)
                error = np.round(error) % q
                # Generate random vector for encryption
                random_vec = np.random.randint(0, q, size=n)
                # Create encrypted version of secret key bit
                eval_key[i, :, j] = (random_vec + 
                                   power * secret_key[i] * secret_key) % q
                
        return eval_key
    
    def _generate_bootstrap_key(self, secret_key: np.ndarray) -> np.ndarray:
        """Generate key for bootstrapping procedure"""
        n = self.params.n
        q = self.params.q
        
        # Create matrix for storing encrypted secret key bits
        bootstrap_key = np.zeros((n, n), dtype=np.int64)
        
        # Encrypt each bit of secret key
        for i in range(n):
            # Generate error for LWE
            error = np.random.normal(0, self.params.std_dev, size=n)
            error = np.round(error) % q
            # Generate random vector
            random_vec = np.random.randint(0, q, size=n)
            # Encrypt bit of secret key
            bootstrap_key[i] = (random_vec + 
                              self.params.scale * secret_key[i] * secret_key) % q
            
        return bootstrap_key
    
    def encrypt(self, message: str, public_key: Tuple[np.ndarray, np.ndarray]) -> List[np.ndarray]:
        """Encrypt a string message into ciphertexts"""
        A, b = public_key
        # Convert string to binary representation
        binary = ''.join(format(ord(c), '08b') for c in message)
        ciphertexts = []
        
        # Encrypt each bit separately
        for bit in binary:
            # Generate error vectors for LWE
            e1 = np.random.normal(0, self.params.std_dev, size=self.params.n)
            e2 = np.random.normal(0, self.params.std_dev)
            e1 = np.round(e1) % self.params.q
            e2 = round(e2) % self.params.q
            
            # Generate random vector for encryption
            r = np.random.randint(0, 2, size=self.params.n)
            
            # Compute LWE encryption: (rA + e1, rb + e2 + m⋅⌊q/t⌉)
            u = (r @ A + e1) % self.params.q
            v = (r @ b + e2 + self.params.scale * int(bit)) % self.params.q
            
            # Store ciphertext
            ciphertexts.append(np.concatenate([u, [v]]))
            
        return ciphertexts
    
    def decrypt(self, ciphertexts: List[np.ndarray], secret_key: np.ndarray) -> str:
        """Decrypt ciphertexts back to original message"""
        bits = []
        # Decrypt each ciphertext
        for ct in ciphertexts:
            # Split ciphertext into vector and scalar parts
            u, v = ct[:-1], ct[-1]
            # Compute noisy plaintext: v - u⋅s
            noise = (v - u @ secret_key) % self.params.q
            # Scale back to get bit
            bit = round(noise * self.params.t / self.params.q) % self.params.t
            bits.append(str(bit))
        
        # Convert binary string back to text
        binary = ''.join(bits)
        message = ''
        # Process 8 bits at a time (one character)
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if len(byte) == 8:  # Ensure complete byte
                message += chr(int(byte, 2))
        return message
    
    def bootstrap(self, ciphertext: np.ndarray, keys: KeyBundle) -> np.ndarray:
        """Refresh ciphertext by running decryption circuit homomorphically"""
        # Split ciphertext into components
        u, v = ciphertext[:-1], ciphertext[-1]
        
        # Step 1: Scale down ciphertext to reduce noise
        scale_factor = 2**self.params.bootstrap_precision
        u_scaled = (u * scale_factor // self.params.q) % scale_factor
        v_scaled = (v * scale_factor // self.params.q) % scale_factor
        
        # Step 2: Build homomorphic accumulator
        acc = np.zeros(self.params.n, dtype=np.int64)
        # Accumulate scaled ciphertext components
        for i in range(self.params.n):
            if u_scaled[i] != 0:
                acc = self.add_ciphertexts(acc, 
                    keys.bootstrap_key[i] * u_scaled[i] % self.params.q)
        
        # Step 3: Switch key to reduce noise
        new_ct = self._key_switch(acc, v_scaled, keys.eval_key)
        
        return new_ct
    
    def _key_switch(self, acc: np.ndarray, v_scaled: float, 
                   eval_key: np.ndarray) -> np.ndarray:
        """Switch ciphertext to reduce noise during bootstrapping"""
        n = self.params.n
        q = self.params.q
        
        # Decompose accumulator into binary representation
        bits = int(np.log2(q)) + 1
        decomp = np.zeros((n, bits), dtype=np.int64)
        for i in range(n):
            val = acc[i]
            for j in range(bits):
                decomp[i, j] = (val % 2)
                val //= 2
        
        # Apply key switching transformation
        result = np.zeros(n + 1, dtype=np.int64)
        for i in range(n):
            for j in range(bits):
                if decomp[i, j] == 1:
                    result[:-1] = (result[:-1] + eval_key[i, :, j]) % q
        
        # Add scaled value back
        result[-1] = v_scaled
        return result
    
    def add_ciphertexts(self, ct1: np.ndarray, ct2: np.ndarray) -> np.ndarray:
        """Add two ciphertexts homomorphically"""
        return (ct1 + ct2) % self.params.q
    
    def multiply_ciphertexts(self, ct1: np.ndarray, ct2: np.ndarray, 
                            keys: KeyBundle) -> np.ndarray:
        """Multiply two ciphertexts homomorphically"""
        # Compute tensor product of ciphertexts
        result = (ct1.reshape(-1, 1) @ ct2.reshape(1, -1)).flatten() % self.params.q
        
        # Bootstrap to reduce noise from multiplication
        result = self.bootstrap(result, keys)
        
        return result

def demonstrate_enhanced_fhe():
    """Demonstrate the FHE scheme with a simple example"""
    # Create new FHE instance
    fhe = EnhancedLWEBasedFHE()
    
    # Generate all necessary keys
    keys = fhe.generate_keys()
    
    # Example message
    message = "Hello"
    print(f"Original message: {message}")
    
    # Encrypt the message
    ciphertext = fhe.encrypt(message, keys.public_key)
    print(f"Encrypted (first block): {ciphertext[0][:10]}...")
    
    print("\nPerforming homomorphic operations...")
    
    # Demonstrate homomorphic addition
    if len(ciphertext) >= 2:
        # Add first two blocks
        added = fhe.add_ciphertexts(ciphertext[0], ciphertext[1])
        print("Performed homomorphic addition")
        
        # Bootstrap to reduce noise
        bootstrapped = fhe.bootstrap(added, keys)
        print("Performed bootstrapping to reduce noise")
    
    # Decrypt and verify
    decrypted = fhe.decrypt(ciphertext, keys.secret_key)
    print(f"\nDecrypted message: {decrypted}")

if __name__ == "__main__":
    demonstrate_enhanced_fhe()
