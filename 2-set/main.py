"""
    CBC and PKCS#7
"""
import sys
import time
import os
from Crypto.Cipher import AES
import argparse
import random
import base64

# Parse arguments
parser = argparse.ArgumentParser(description="Solves Set 2 of Cryptopals")
parser.add_argument("assignment",type=str, help="which assignment in the set, possible 'cbc', 'ecb', '9'...'11'")
parser.add_argument("-b", "--bytesmode", help="byte mode reading of file", action="store_true")
parser.add_argument("-i", "--input", type=str, help="input data as string")
parser.add_argument("--iv", type=str, help="initialisation vector, hexstr")
parser.add_argument("-k", "--key", type=str, default='YELLOW SUBMARINE', help="key, defaults to YELLOW SUBMARINE")
parser.add_argument("-v", "--verbose", help="verbose print to stdout", action="store_true")
parser.add_argument("--times", type=int, default=100, help="times to run oracle")
parser.add_argument("-f", "--file", type=str, help="input file")
parser.add_argument("-o", "--output", type=str)
parser.add_argument("--random", nargs='?', type=int, help="random data", const=128, default=0)
parser.add_argument("-x", "--hex", help="output and force-read hex", action="store_true")
parser.add_argument("-d", "--decrypt", action="store_true", help="decryption mode for ECB/CBC assignment")
parser.add_argument("-e", "--encrypt", action="store_true", help="encryption mode for ECB/CBC assignment")
parser.add_argument('-l', "--len", type=int, help="size of random hex key", default=16)
parser.add_argument('-w', "--wait", type=float, help="wait seconds between instructions", default=0.1)
args = parser.parse_args()

def wait():
    time.sleep(args.wait)

def random_hex(length: int=16, upper: bool=False) -> str:
    """
        Returns a random hex string.
    """
    res = os.urandom(length).hex()[:length]
    if upper:
        return res.upper()
    return res

RANDOM_KEY = random_hex(args.len).encode('ascii')
ASSIGNMENT_TWELVE_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

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

def pkcs_pad(data: bytes, block_length: int=AES.block_size) -> bytes:
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
    cipher = AES.new(key, AES.MODE_ECB)
    out = bytes()
    for i in range(0, len(data), AES.block_size):
        block = data[i:i+AES.block_size]
        out += cipher.encrypt(pkcs_pad(block, block_length=AES.block_size))
    return out

def ecb_decrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    out = bytes()
    for i in range(0, len(data), AES.block_size):
        block = data[i:i+AES.block_size]
        out += pkcs_unpad(AES.new(key, AES.MODE_ECB).decrypt(block))
    return out

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

def is_ecb(data: bytes, block_length: int=AES.block_size) -> bool:
    """
        Returns true if the data provided
        is encrypted with ecb.
        Higher probability of correctness if data set
        is large
    """
    occurrences = dict()
    for i in range(0, len(data), block_length):
        block = data[i:i+block_length].hex()
        if block in occurrences:
            occurrences[block] += 1
        else:
            occurrences[block] = 1
    for (block, times) in occurrences.items():
        if times > 1:
            return True
    return False


def encrypting_oracle(data, key=RANDOM_KEY, iv=b'00000000', random_bytes=False, span=(5,10)):
    """
        Randomise encryption of ECB / CBC
        Returns (data_encrypted, is_encrypted_with_cbc)
        If Assignment == '12', it encrypts with ECB
    """
    if args.assignment == '12':
        new = bytes(base64.b64decode(ASSIGNMENT_TWELVE_STRING))
        data += new
        out = ecb_encrypt(data, key)
        return out, True
    else:
        if random_bytes:
            prefix = os.urandom(random.randint(span[0], span[1]))
            suffix = os.urandom(random.randint(span[0], span[1]))
        else:
            prefix = b'0' * random.randint(span[0], span[1])
            suffix = b'0' * random.randint(span[0], span[1])
        data = prefix + data + suffix
    is_ecb_encrypted = random.randint(0, 1) == 0
    if is_ecb_encrypted:
        return ecb_encrypt(data, key), True
    else:
        return cbc_encrypt(data, key, iv), False
        

def initialise():
    """
        Initialise data, key and iv
    """
    data = b''
    if args.random:
        data = os.urandom(args.random)
    elif args.input:
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

def run_tests(data, key, iv):
    print("Running tests!\n")
    print("is_ecb",end="")
    assert is_ecb(b'000000000000000000000000000000000000000000000000')
    print("...OK")
    print("not is_ecb",end="")
    assert not is_ecb(b'0djwadokcndwadiwoajdowa9d291jdw')
    print("...OK")
    random_data = os.urandom(128)
    encrypted_data = cbc_encrypt(random_data, key, iv)
    print("random",end="")
    assert cbc_decrypt(encrypted_data, key, iv) == random_data
    print("...OK")
    print("\nAll tests OK!")

def single_byte(i: int):
    return int.to_bytes(i, 1, 'little')

def main():
    # Seed PRNG
    random.seed(int.from_bytes(os.urandom(4), 'little'))
    # Set data
    data, key, iv = initialise()
    # Check assignment
    if args.assignment in ['hex', 'hexlen']:
        print(RANDOM_KEY)
    if args.assignment == 'tests':
        run_tests(data, key, iv)
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
    # Oracle assignment
    if args.assignment == '11':
        guessed_correct = 0
        count_ecb_guesses = 0
        count_ecb_actuals = 0
        for _ in range(args.times):
            encrypted_data, actual = encrypting_oracle(data, key, iv)
            guessed = is_ecb(encrypted_data)
            if guessed:
                count_ecb_guesses += 1
            if actual:
                count_ecb_actuals += 1
            if guessed == actual:
                guessed_correct += 1
        print(f"Guessed correct {guessed_correct} / {args.times} ({100*guessed_correct/float(args.times)}%)")
        print(f"...where {count_ecb_guesses} guesses were ECB")
        print(f"...where {count_ecb_actuals} actuals were ECB")
    if args.assignment == '12':
        # Check data
        prev_len = -1
        curr_input = b'A'
        block_len = None
        # Find block length
        while block_len is None:
            encrypted, _ = encrypting_oracle(curr_input)
            if len(encrypted) > prev_len and prev_len > 0:
                block_len = len(encrypted) - prev_len
                break
            else:
                prev_len = len(encrypted)
            curr_input += b'A'
        print(f"Block length {block_len}")
        # Min blocks
        encrypted, _ = encrypting_oracle(b'')
        min_blocks = len(encrypted) // block_len
        print(f"Encrypted len: {len(encrypted)}")
        print(f"Minimum blocks: {min_blocks}")
        # Check ECB encoding
        is_ecb_encoded = is_ecb(encrypting_oracle(b'A'*2*block_len)[0])
        print(f"Is ECB encoded: {is_ecb_encoded}")
        # Trying to find key on last pos
        total = b''
        for round in range(0, min_blocks):
            filler = b'A' * block_len * round
            get_block = lambda x : x[block_len*(min_blocks-1):block_len*min_blocks]
            result = b''
            for n in range(1, block_len):
                nfew_bytes = filler + total + b'A' * (block_len - n)
                tracker = {}
                # Go through all possible bytes
                for i in range(256):
                    byte_val = single_byte(i)
                    curr_input = nfew_bytes + result + byte_val
                    encrypted, _ = encrypting_oracle(curr_input)
                    tracker[curr_input] = encrypted
                output, _ = encrypting_oracle(nfew_bytes)
                found = False
                for (curr_input, encrypted) in tracker.items():
                    if get_block(encrypted) == get_block(output):
                        found = True
                        result += single_byte(curr_input[-1])
                        break
                if args.verbose and not found:
                    print(f"Not found for {n}")
            print(f"\nResult: {result.decode('ascii')}")
            total += result
        print(f"\nTotal: {total.decode('ascii')}")



if __name__ == "__main__":
    main()