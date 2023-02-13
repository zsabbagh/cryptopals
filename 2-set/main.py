"""
    CBC and PKCS#7
"""
import sys
import re
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
parser.add_argument("--char", help="filler char", type=str, default='.')
parser.add_argument("--times", type=int, default=100, help="times to run oracle")
parser.add_argument("-f", "--file", type=str, help="input file")
parser.add_argument("-o", "--output", type=str)
parser.add_argument("--random", nargs='?', type=int, help="random data", const=128, default=0)
parser.add_argument("-x", "--hex", help="output and force-read hex", action="store_true")
parser.add_argument("-d", "--decrypt", action="store_true", help="decryption mode for ECB/CBC assignment")
parser.add_argument("-e", "--encrypt", action="store_true", help="encryption mode for ECB/CBC assignment")
parser.add_argument('-l', "--len", type=int, help="size of random hex key", default=16)
parser.add_argument('-w', "--wait", type=float, help="wait seconds between instructions", default=0.1)
parser.add_argument("--prefix", type=int, help="prefix length", default=0)
args = parser.parse_args()

def wait(amount: float=args.wait):
    time.sleep(amount)

def key_generator(length: int = AES.block_size) -> bytes:
    """
        Returns a random byte sequence of 'length'
    """
    return os.urandom(length)

def random_hex(length: int=AES.block_size, upper: bool=False) -> str:
    """
        Returns a random hex string.
    """
    res = os.urandom(length).hex()[:length]
    if upper:
        return res.upper()
    return res

RANDOM_KEY = key_generator()
if args.prefix:
    RANDOM_PREFIX = os.urandom(args.prefix)
else:
    RANDOM_PREFIX = os.urandom(random.randint(0, 128))
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

def pkcs_validate(data: bytes) -> bool:
    # Does not anticipate block length
    if len(data) < 1:
        raise ValueError
    for i in range(len(data)-data[-1], len(data)):
        if i < 0 or i > len(data)-1 or data[i] != data[-1]:
            raise ValueError
    return True

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
    if type(data) == str:
        try:
            data = data.encode('ascii')
        except:
            print("Failed to decode string", file=sys.stderr)
            exit(1)
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
        out += pkcs_unpad(cipher.decrypt(block))
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
    for (_, times) in occurrences.items():
        if times > 1:
            return True
    return False


def encrypting_oracle(data, key=RANDOM_KEY, iv=b'00000000', random_bytes=False, span=(5,10)):
    """
        Randomise encryption of ECB / CBC
        Returns (data_encrypted, is_encrypted_with_cbc)
        If Assignment == '12', it encrypts with ECB
    """
    if args.assignment in ['12', '14']:
        # Assignment 12 specification of the oracle
        new = bytes(base64.b64decode(ASSIGNMENT_TWELVE_STRING))
        input_data = RANDOM_PREFIX if args.assignment == '14' else b''
        input_data += data + new
        out = ecb_encrypt(input_data, key)
        return out, True
    elif args.assignment == '13':
        # Assignment 13 specification of the oracle
        if type(data) == bytes:
            data = profile_for(data.decode('ascii'))
        else:
            data = profile_for(data)
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
    return cbc_encrypt(data, key, iv), False

def find_block_length(algorithm):
    """
        Find block length of ECB algorithm
    """
    prev_len = -1
    block_len = None
    # Current input
    start = b''
    # Find block length
    while block_len is None:
        length = len(algorithm(start))
        if length > prev_len and prev_len > 0:
            block_len = length - prev_len
            break
        else:
            prev_len = length
        start += b'A'
    return block_len

def break_ecb_aglorithm(algorithm, random_prefix=False):

    block_len = find_block_length(algorithm)
    # We need to find block offset
    char_offset = None
    block_offset = 0
    prefix_len = None
    if random_prefix:
        # iterate till we find two repetitions
        for offset in range(0, block_len):
            repetition = algorithm(b'A' * (2 * block_len + offset))
            for i in range(block_len, len(repetition), block_len):
                if repetition[i-block_len:i] == repetition[i:i+block_len]:
                    char_offset = offset
                    block_offset = i - block_len
                    prefix_len = block_offset - char_offset
                    if args.verbose:
                        print(f"Offset found {char_offset}")
                        print(f"Prefix length {block_offset-char_offset}")
                        print(f"Block offset: {block_offset}")
                    break
            if char_offset is not None:
                break


    # Min blocks
    encrypted = algorithm(b'')
    if prefix_len is None:
        min_blocks = len(encrypted) // block_len
    else:
        min_blocks = (len(encrypted) - prefix_len) // block_len
    # Check ECB encoding
    is_ecb_encoded = is_ecb(algorithm(b'A'*2*block_len))
    if args.verbose:
        print(f"Block length {block_len}")
        print(f"Encrypted len: {len(encrypted)}")
        print(f"Minimum blocks: {min_blocks}")
        print(f"Is ECB encoded: {is_ecb_encoded}")

    # Trying to find key on last pos
    filler = b'A' * char_offset
    total = b''
    for r in range(0, min_blocks):
        round = r * block_len
        result = b''
        for n in range(1, block_len+1):
            # Add filler to fill out to next block
            # Then add 'A's until byte is checked
            nfew_bytes = filler + b'A' * (block_len - n)
            tracker = {}
            # Go through all possible bytes
            for i in range(256):
                byte = single_byte(i)
                # Must offset byteval to last position
                curr_input = nfew_bytes + total + result + byte
                encrypted = algorithm(curr_input)
                tracker[byte] = encrypted[block_offset + round:block_offset + round+block_len]
            output = algorithm(nfew_bytes)
            # Search for a match
            for (byte, encrypted) in tracker.items():
                if encrypted == output[block_offset+round:block_offset+round+block_len]:
                    result += byte
                    break
        if args.verbose:
            print(f"\nResult: {result.decode('ascii')}")
        total += result

    if args.verbose:
        print(f"\nTotal:\n{total.decode('ascii')}")
    return total

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
    print("random",end="")
    random_data = os.urandom(128)
    encrypted_data = cbc_encrypt(random_data, key, iv)
    assert cbc_decrypt(encrypted_data, key, iv) == random_data
    print("...OK")
    print("email",end='')
    email = 'correct@email.com'
    assert profile_for(email) != ''
    print("...OK")
    print("\nAll tests OK!")

def single_byte(i: int):
    return int.to_bytes(i, 1, 'little')

def parse_cookie(cookie: str, delim: str='&', eq: str='=') -> dict:
    """
        Cuts a cookie by the delimiter 'delim' and 'eq' to a dictionary
    """
    first =  filter(len, cookie.split(delim))
    res = dict(filter(lambda x : len(x) == 2, map(lambda x : x.split(eq), first)))
    return res

def unparse_cookie(parsed_cookie: dict):
    out = []
    items = parsed_cookie.items()
    i = 0
    for (k, v) in items:
        out.append(k + '=' + v)
        i += 1
        if i < len(items):
            out.append('&')
    return ''.join(out)

def profile_for(email: str) -> str:
    """
        Generates a profile for an email
        Returns None if email is invalid
    """
    email = re.sub('[&=]', '', email)
    uid = str(random.randint(0, 1024))
    uid = '0' * (4 - len(uid)) + uid
    return f"email={email}&uid={uid}&role=user"

def decrypting_oracle(encrypted_data: bytes, key=RANDOM_KEY):
    if args.verbose:
        print(f"entering decryptor")
        print(f"input: {encrypted_data.hex()} ({len(encrypted_data)})")
    decrypted = ecb_decrypt(encrypted_data, key)
    out = decrypted.decode('ascii')
    if args.verbose:
        print(out)
    return parse_cookie(out)

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
        # Set algorithm
        algorithm = lambda x : encrypting_oracle(x)[0]
        result = break_ecb_aglorithm(algorithm)
        print("--- RESULT ---")
        print(result.decode('ascii'))
    if args.assignment == '13':
        if not args.input:
            print("Error: Requires input -i", file=sys.stderr)
            exit(1)
        filler_char = args.char
        # random key
        print(f"key: \t{RANDOM_KEY.hex()} (length {len(RANDOM_KEY)})")
        # An entire block of a padded admin
        oracle = lambda x : encrypting_oracle(x)[0]
        # We want admin to end up on a block of itself
        other = 'email=&uid=xxxx&role='
        print(f"other:\t{other} ({len(other)})")
        email_const = args.input
        # pad to the next block
        # we need to get an "admin" block encrypted
        email = email_const + filler_char * (AES.block_size - len(email_const) - len('email=') )
        print(f"email:\t{email} ({len(email)})")
        # admin will be added directly after ..&role=<HERE!>
        admin = pkcs_pad(b'admin')
        # data to input
        data = email.encode('ascii') + admin
        # the admin block to replace with
        admin_block = oracle(data)[AES.block_size:AES.block_size*2]
        email = email_const + filler_char * ((2 * AES.block_size) - len(email_const) - len(other))
        print(f"email:\t{email} ({len(email)})")
        expected = "email=" + email + other[6:]
        print(f"expected: {expected} ({len(expected)})")
        print(f"total:\t({len(other)}, {len(email)})")
        out_block = oracle(email)
        print(f"out_block: ({len(out_block)})")
        crack_block = out_block[:2*AES.block_size] + admin_block
        print(f"crack_block: ({len(crack_block)})")
        parsed = decrypting_oracle(crack_block)
        print("\n--- OUTPUT ---")
        print(unparse_cookie(parsed))
    if args.assignment == '14':
        algorithm = lambda x : encrypting_oracle(x)[0]
        result = break_ecb_aglorithm(algorithm, random_prefix=True)
        print("--- RESULT ---")
        print(result.decode('ascii'))
        pass
    if args.assignment == '15':
        true_input = b"ICE ICE BABY\x04\x04\x04\x04"
        assert pkcs_validate(true_input)
        try:
            false_input = b"ICE ICE BABY\x05\x05\x05\x05"
            pkcs_validate(false_input)
            assert False
        except ValueError:
            pass
        try: 
            false_input = b"ICE ICE BABY\x01\x02\x03\x04"
            pkcs_validate(false_input)
            assert False
        except ValueError:
            pass
        print("Success.")

if __name__ == "__main__":
    main()