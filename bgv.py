import numpy as np  # Import NumPy for efficient array operations and mathematical functions

class BGV:
    def __init__(self, t, q, d):
        # t: plaintext modulus - defines the message space Z_t
        # q: ciphertext modulus - larger than t, affects noise growth
        # d: polynomial degree - defines the ring R = Z[X]/(X^d + 1)
        self.t = t  # Store plaintext modulus
        self.q = q  # Store ciphertext modulus
        self.d = d  # Store polynomial degree
        
    def poly_mult(self, a, b):
        """Multiply polynomials and reduce modulo X^d + 1"""
        # Initialize array for polynomial multiplication result
        # Size is 2*len(a)-1 to accommodate full multiplication before reduction
        result = np.zeros(2 * len(a) - 1, dtype=int)
        
        # Perform polynomial multiplication
        for i in range(len(a)):
            for j in range(len(b)):
                # Multiply coefficients and add to existing coefficient
                # Reduce modulo q to keep coefficients in the correct range
                result[i + j] = (result[i + j] + a[i] * b[j]) % self.q
                
        # Reduce result modulo X^d + 1
        reduced = np.zeros(self.d, dtype=int)  # Initialize array for reduced polynomial
        for i in range(len(result)):
            if i < self.d:
                # Copy coefficients directly for degrees less than d
                reduced[i] = (reduced[i] + result[i]) % self.q
            else:
                # For degrees >= d, subtract coefficient due to X^d = -1
                # This implements the reduction by X^d + 1
                reduced[i - self.d] = (reduced[i - self.d] - result[i]) % self.q
        return reduced
        
    def gen_key(self):
        # Generate secret key as binary polynomial
        self.sk = np.random.binomial(1, 0.5, self.d)  
        
        # Generate error polynomial from discrete Gaussian distribution
        e = np.random.normal(0, 2, self.d).astype(int)  
        
        # Generate random polynomial a
        self.a = np.random.randint(0, self.q, self.d)  
        
        # Compute public key: pk = -(a*sk + e) mod q
        # This follows the Ring-LWE problem structure
        self.pk = (-self.poly_mult(self.a, self.sk) + e) % self.q
        return self.pk, self.sk
    
    def encrypt(self, m):
        # Handle single integer input by converting to list
        if isinstance(m, int):
            m = [m]
            
        # Convert message to polynomial
        m_poly = np.zeros(self.d, dtype=int)  # Initialize polynomial
        m_poly[:len(m)] = np.array(m) % self.t  # Set coefficients from message
        
        # Generate encryption randomness and noise
        e1 = np.random.normal(0, 2, self.d).astype(int)  # Error polynomial 1
        e2 = np.random.normal(0, 2, self.d).astype(int)  # Error polynomial 2
        u = np.random.binomial(1, 0.5, self.d)  # Random binary polynomial
        
        # Compute first ciphertext component
        # c0 = pk*u + e1 + m*(q/t)
        c0 = (self.poly_mult(self.pk, u) + e1 + m_poly * (self.q // self.t)) % self.q
        
        # Compute second ciphertext component
        # c1 = a*u + e2
        c1 = (self.poly_mult(self.a, u) + e2) % self.q
        
        return c0, c1
    
    def decrypt(self, c):
        c0, c1 = c  # Unpack ciphertext components
        
        # Compute c0 + c1*sk mod q
        p = (c0 + self.poly_mult(c1, self.sk)) % self.q
        
        # Scale back to message space and round
        p = np.round(p * self.t / self.q) % self.t
        return p.astype(int)

# Test code
if __name__ == "__main__":
    # Set parameters
    t = 257    # Plaintext modulus (prime for message space)
    q = 65537  # Ciphertext modulus (larger prime)
    d = 8      # Polynomial degree (power of 2 for efficient FFT)
    
    # Create BGV instance
    bgv = BGV(t, q, d)
    
    # Generate keys
    pk, sk = bgv.gen_key()
    
    # Test message
    message = [5, 10, 15]
    print(f"Original message: {message}")
    
    # Encrypt message
    ct = bgv.encrypt(message)
    print("Encrypted!")
    
    # Decrypt ciphertext
    decrypted = bgv.decrypt(ct)[:len(message)]
    print(f"Decrypted message: {decrypted}")
