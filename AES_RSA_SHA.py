import hashlib
import random
import json

s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

inv_s_box = [  # inverse s-box
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

#=======================================================================================================================================================

def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    return [s_box[b] for b in word]

def rcon(index):
    rcon_value = 1
    for _ in range(index - 1):
        rcon_value = (rcon_value << 1) ^ (0x11b & -(rcon_value >> 7))
    return rcon_value

def expand_key(key):
    expanded_key = list(key)
    current_size = len(key)
    rcon_iteration = 1

    while current_size < 16 * (NUM_ROUNDS + 1):
        temp = expanded_key[current_size - 4:current_size]

        if current_size % KEY_SIZE == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= rcon(rcon_iteration)
            rcon_iteration += 1

        for i in range(4):
            temp[i] ^= expanded_key[current_size - KEY_SIZE + i]

        expanded_key += temp
        current_size += 4

    return expanded_key

#=======================================================================================================================================================

def aes_encrypt(plain_text, key):
    key_schedule = expand_key(key)
    state = plain_text[:]

    # Initial round
    add_round_key(state, key_schedule[:KEY_SIZE])

    '''  # for debug
    original_hex = []
    for item in state:
        original_hex.append(hex(item))
    print("after add roundkey: ", original_hex)
    '''
    
    # Rounds 1 to 9
    for round_num in range(1, NUM_ROUNDS):
        """ print("round_num", round_num)
        print("state: ", state) """
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule[round_num * KEY_SIZE:(round_num + 1) * KEY_SIZE])

    # Final round
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule[NUM_ROUNDS * KEY_SIZE:(NUM_ROUNDS + 1) * KEY_SIZE])

    return state

# Helper functions

def add_round_key(state, key):
    for i in range(16):
        state[i] ^= key[i]

    """ original_hex = []
    for item in state:
        original_hex.append(hex(item))
    print("after add roundkey: ", original_hex) """

def sub_bytes(state):
    """ original_hex = []
    for item in state:
        original_hex.append(hex(item))
    print("before sub: ", original_hex) """
    
    for i in range(len(state)):
        state[i] = s_box[state[i]]
        
    """ original_hex = []
    for item in state:
        original_hex.append(hex(item))
    print("after sub: ", original_hex) """

def shift_rows(state):
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
"""     original_hex = []
    for item in state:
        original_hex.append(hex(item))
    print("after shift: ", original_hex) """

def mix_columns(state):
    for i in range(0, 16, 4):
        a = state[i]
        b = state[i + 1]
        c = state[i + 2]
        d = state[i + 3]

        state[i] = (mul2(a) ^ mul3(b) ^ c ^ d) % 256
        state[i + 1] = (a ^ mul2(b) ^ mul3(c) ^ d) % 256
        state[i + 2] = (a ^ b ^ mul2(c) ^ mul3(d)) % 256
        state[i + 3] = (mul3(a) ^ b ^ c ^ mul2(d)) % 256
    """ original_hex = []
    for item in state:
        original_hex.append(hex(item))
    print("after mix: ", original_hex) """

def mul2(num):
    return (num << 1) ^ (0x1b if num & 0x80 else 0x00)

def mul3(num):
    return mul2(num) ^ num


#=======================================================================================================================================================

def aes_decrypt(ciphertext, key):
    key_schedule = expand_key(key)
    state = ciphertext[:]

    # Final round
    add_round_key(state, key_schedule[NUM_ROUNDS * KEY_SIZE:(NUM_ROUNDS + 1) * KEY_SIZE])
    inv_shift_rows(state)
    inv_sub_bytes(state)

    # Rounds 1 to 9
    for round_num in range(NUM_ROUNDS - 1, 0, -1):
        add_round_key(state, key_schedule[round_num * KEY_SIZE:(round_num + 1) * KEY_SIZE])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    # Initial round
    add_round_key(state, key_schedule[:KEY_SIZE])

    return state

# Helper functions for decryption

def inv_shift_rows(state):
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

def inv_sub_bytes(state):
    for i in range(len(state)):
        state[i] = inv_s_box[state[i]]

def inv_mix_columns(state):
    for i in range(0, 16, 4):
        a = state[i]
        b = state[i + 1]
        c = state[i + 2]
        d = state[i + 3]

        state[i] = (mul14(a) ^ mul11(b) ^ mul13(c) ^ mul9(d)) % 256
        state[i + 1] = (mul9(a) ^ mul14(b) ^ mul11(c) ^ mul13(d)) % 256
        state[i + 2] = (mul13(a) ^ mul9(b) ^ mul14(c) ^ mul11(d)) % 256
        state[i + 3] = (mul11(a) ^ mul13(b) ^ mul9(c) ^ mul14(d)) % 256

def mul9(num):
    return (mul2(mul2(mul2(num))) ^ num) % 256

def mul11(num):
    return (mul2(mul2(mul2(num))) ^ mul2(num) ^ num) % 256

def mul13(num):
    return (mul2(mul2(mul2(num))) ^ mul2(mul2(num)) ^ num) % 256

def mul14(num):
    return (mul2(mul2(mul2(num))) ^ mul2(mul2(num)) ^ mul2(num)) % 256

#=======================================================================================================================================================

NUM_ROUNDS = 10
KEY_SIZE = 16

#=======================================================================================================================================================

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (
            u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3

    return u1 % m

def is_prime(n, k=5):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False

    return True

def generate_prime(bits):
    while True:
        p = random.randint(2**(bits-1), 2**bits - 1)
        if is_prime(p):
            return p

def generate_rsa_key_pair(bit_size):
    p = generate_prime(bit_size // 2)
    q = generate_prime(bit_size // 2)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    while True:
        e = random.randint(2, phi_n - 1)
        if gcd(e, phi_n) == 1:
            break

    d = mod_inverse(e, phi_n)

    return (e, n), (d, n)

def encrypt_rsa(msg, public_key):
    e, n = public_key
    encrypted = [pow(m, e, n) for m in msg]
    return encrypted

def decrypt_rsa(encrypted, private_key):
    d, n = private_key[0], private_key[1]
    decrypted = [pow(c, d, n) for c in encrypted]
    return decrypted

def sha1(msg):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(msg.encode('utf-8'))
    return sha1_hash.hexdigest()

def sha256(msg):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(msg.encode('utf-8'))
    return sha256_hash.hexdigest()

#=======================================================================================================================================================

def read_hex_file(file_path):
    with open(file_path, "r") as file:
        hex_string = file.read()
    hex_list = hex_string.split()
    data = [int(val, 16) for val in hex_list]
    return data


def read_file(file_path):
    with open(file_path, "r") as file:
        data = file.read()
    return data

def read_json_file(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    return data

def write_file(file_path, data):
    with open(file_path, "w") as file:
        file.write(data)

def write_file_hex(file_path, data):
    with open(file_path, "w") as file:
        hex_string = ' '.join([hex(val)[2:] for val in data])
        file.write(hex_string)

def save_metadata_to_file(file_name, Kx, HKprivate):
    metadata = {
        "Kx": Kx,
        "HKprivate": HKprivate
    }

    with open(file_name, 'w') as file:
        json.dump(metadata, file)

def save_key_to_file(file_name, d, n):
    metadata = {
        "d": d,
        "n": n
    }
    with open(file_name, 'w') as file:
        json.dump(metadata, file)

def convert_to_hex(text):
    hex_text = []
    for char in text:
        hex_text.append(ord(char))
    return hex_text

def generate_aes_key():
    Ks = [random.randint(0, 255) for _ in range(16)]
    return Ks

def encrypt_file_with_aes(file_path, output_path, key):
    plaintext = read_file(file_path)
    plaintext = convert_to_hex(plaintext)
    encrypted = aes_encrypt(plaintext,key)
    write_file_hex(output_path, encrypted)