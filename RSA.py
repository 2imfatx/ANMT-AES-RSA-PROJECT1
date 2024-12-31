from sympy import nextprime
import random

#generate a random prime number
def generate_prime():
    return nextprime(random.randint(10, 100 ** 2))

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
    
def encrypt(message, PUBLIC_KEY):
    return pow(message, PUBLIC_KEY[0], PUBLIC_KEY[1])

def decrypt(cipher, PRIVATE_KEY):
    return pow(cipher, PRIVATE_KEY[0], PRIVATE_KEY[1])

def encrypt_message(message, PUBLIC_KEY):
    cipher = ""
    for c in message:
        cipher += str(encrypt(ord(c), PUBLIC_KEY))
        if c != message[-1]:
            cipher += "-"
    return cipher

def decrypt_message(cipher, PRIVATE_KEY):
    message = ""
    for c in cipher.split("-"):
        message += chr(decrypt(int(c), PRIVATE_KEY))
    return message

def create_keys():
    P = generate_prime()
    Q = generate_prime()
    while P == Q:
        Q = generate_prime()
    N = P * Q
    PHI = (P - 1) * (Q - 1)
    E = random.randint(1, PHI)
    while gcd(E, PHI) != 1:
        E = random.randint(1, PHI)
    for D in range(1, PHI):
        if (E * D) % PHI == 1:
            break
    return (E, N), (D, N)

P = generate_prime()
Q = generate_prime()
while P == Q:
    Q = generate_prime()
PUBLIC_KEY, PRIVATE_KEY = create_keys() 
message = "Hello, World!"

#PUBLIC_KEY = (E, N)
#PRIVATE_KEY = (D, N)

print("P: ", P)
print("Q: ", Q)
print("Public key: ", PUBLIC_KEY)
print("Private key: ", PRIVATE_KEY)

cipher = encrypt_message(message, PUBLIC_KEY)
print("Cipher: ", cipher)
print("Decrypted message: ", decrypt_message(cipher, PRIVATE_KEY))


