"""
    CBC and PKCS#7
"""
import sys
import os
from Crypto.Cipher import AES
import argparse
import random

# Parse arguments
parser = argparse.ArgumentParser(description="Solves Set 2 of Cryptopals")
parser.add_argument("assignment",type=str, help="which assignment in the set, possible 'cbc', 'ecb', '9'...'11'")
parser.add_argument("-b", "--bytesmode", help="byte mode reading of file", action="store_true")
parser.add_argument("-i", "--input", type=str, help="input data as string")
parser.add_argument("--iv", type=str, help="initialisation vector, hexstr")
parser.add_argument("-k", "--key", type=str, default='YELLOW SUBMARINE', help="key, defaults to YELLOW SUBMARINE")
parser.add_argument("-f", "--file", type=str, help="input file")
parser.add_argument("-o", "--output", type=str)
parser.add_argument("-x", "--hex", help="output and force-read hex", action="store_true")
parser.add_argument("-d", "--decrypt", action="store_true", help="decryption mode for ECB/CBC assignment")
parser.add_argument("-e", "--encrypt", action="store_true", help="encryption mode for ECB/CBC assignment")
args = parser.parse_args()

def is_hex(s: str):
    value = True
    try:
        int(s, 16)
    except ValueError:
        value = False
    return value and len(s) % 2 == 0

def read_str(s: str):
    if type(s) in [bytes, bytearray]:
        return s
    if args.hex and is_hex(s):
        return bytes.fromhex(s)
    return s.encode('ascii')

def get_output(data: bytes):
    if args.hex:
        return data.hex()
    else:
        try:
            return data.decode('ascii')
        except UnicodeDecodeError:
            return data.decode('utf-8', 'backslashreplace')

def pkcs_pad(data: bytes, block_length: int=20) -> bytes:
    if len(data) > block_length:
        return data[:block_length]
    diff = block_length - len(data)
    return data + bytes([diff] * diff)

def pkcs_unpad(data: bytes) -> bytes:
    # Does not anticipate block length
    if len(data) < 1:
        return data
    for i in range(len(data)-data[-1], len(data)):
        if i < 0 or i > len(data)-1 or data[i] != data[-1]:
            return data
    return data[:-data[-1]]

def xor(*arrs: bytes):
    """
        XORs any amount of byte arrays and returns
        the resulting vector.
    """
    max_len = -1
    for arr in arrs:
        if max_len < len(arr):
            max_len = len(arr)
    out = []
    for i in range(max_len):
        val = 0
        for arr in arrs:
            if len(arr)-1 < i:
                continue
            val ^= arr[i]
        out.append(val)
    return bytes(out)

def ecb_encrypt(data: bytes, key: bytes):
    return AES.new(key, AES.MODE_ECB).encrypt(pkcs_pad(data, block_length=AES.block_size))

def ecb_decrypt(data: bytes, key: bytes):
    return pkcs_unpad(AES.new(key, AES.MODE_ECB).decrypt(data))

def cbc_decrypt(data: bytes, key: bytes, iv: bytes, block_length: int = AES.block_size):
    plain = bytes()
    previous_block_xor = iv
    for i in range(0, len(data), block_length):
        encrypted = data[i:i+block_length]
        plain += xor(previous_block_xor, ecb_decrypt(encrypted, key))
        previous_block_xor = encrypted
    return pkcs_unpad(plain)

def cbc_encrypt(data: bytes, key: bytes, iv: bytes, block_length: int=AES.block_size):
    cipher = bytes()
    previous_input = iv
    for i in range(0, len(data), block_length):
        plaintext = pkcs_pad(data[i:i+block_length], block_length=block_length)
        previous_input = ecb_encrypt(xor(previous_input, plaintext), key)
        cipher += previous_input
    return cipher

def encoding_oracle(data, key, iv):
    """
        Randomise encryption of ECB / CBC
    """
    prefix = os.urandom(random.randint(5, 10))
    suffix = os.urandom(random.randint(5, 10))
    data = prefix + data + suffix
    if random.randint(0, 1) == 0:
        return cbc_encrypt(data, key, iv)
    else:
        return ecb_encrypt(data, key)

def initialise():
    """
        Initialise data, key and iv
    """
    data = b''
    if args.input:
        data = read_str(args.input)
    elif args.file:
        # Read file
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} does not exist", file=sys.stderr)
            exit(1)
        if args.bytesmode:
            data = open(args.file, 'rb').read()
        else:
            data = read_str(open(args.file, 'r').read())
    if args.key:
        key = args.key.encode('ascii')
        if len(key) != AES.block_size:
            key = pkcs_pad(key)
    if args.iv:
        iv = pkcs_pad(read_str(args.iv))
    else:
        iv = os.urandom(AES.block_size)
    return data, key, iv

def main():
    # Seed PRNG
    random.seed(int.from_bytes(os.urandom(4), 'little'))
    # Set data
    data, key, iv = initialise()
    # Check assignment
    if args.assignment == 'cbc':
        if args.decrypt:
            out = cbc_decrypt(data, key, iv)
        else:
            out = cbc_encrypt(data, key, iv)
        print(get_output(out))
    if args.assignment == 'ecb':
        if args.decrypt:
            out = ecb_decrypt(data, key)
        else:
            out = ecb_encrypt(data, key)
        print(get_output(out))
    if args.assignment == '9':
        new = pkcs_pad(data)
        print(f"Length {len(new)}, data: '{new}'")
        print(f"Unpadded: {pkcs_unpad(new)}")
    if args.assignment == '10':
        print(f"IV used, in hexstr: {iv.hex()}")
        enc = cbc_encrypt(data, key, iv)
        dec = cbc_decrypt(enc, key, iv)
        assert data == dec
    if args.assignment == '11':
        out = encoding_oracle(data, key, iv)
        print(get_output(out))

if __name__ == "__main__":
    main()