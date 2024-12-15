import random

def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

# Menghasilkan bilangan prima acak dengan panjang 8 bit
def generate_prime(bits=8):  # Reduced bit size for demonstration
    while True:
        num = random.getrandbits(bits) | (1 << (bits - 1)) | 1 # buat bilangan ganjil
        if is_prime(num): # cek prima
            return num

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keys(bits=8):
    p, q = generate_prime(bits), generate_prime(bits)
    while p == q:
        q = generate_prime(bits)
    N = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(1, phi)
    while gcd(e, phi) != 1:
        e = random.randint(1, phi)
    d = mod_inverse(e, phi)
    return (e, N), (d, N)

def encrypt_rsa(message, e, N):
    return [pow(ord(char), e, N) for char in message]

def decrypt_rsa(encrypted_msg, d, N):
    return ''.join(chr(pow(char, d, N)) for char in encrypted_msg)

