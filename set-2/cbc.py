"""
    CBC and PKCS#7
"""
import sys
import os
from Crypto.Cipher import AES

def pkcs_pad(data: bytes, block_length: int=20) -> bytes:
    if len(data) > block_length:
        return data[:block_length]
    diff = block_length - len(data)
    return data + bytes([diff] * diff)

def pkcs_unpad(data: bytes) -> bytes:
    # Does not anticipate block length
    for i in range(len(data)-data[-1], len(data)):
        if data[i] != data[-1]:
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

def cbc_decrypt(data: bytes, iv: bytes, key: bytes, block_length: int = AES.block_size):
    plain = bytes()
    previous_block = iv
    for i in range(0, len(data), block_length):
        previous_block = data[i:i+block_length]
        decrypted = ecb_decrypt(previous_block, key)
        plain += xor(previous_block, decrypted)
    return plain

def cbc_encrypt(data: bytes, iv: bytes, key: bytes, block_length: int=AES.block_size):
    cipher = bytes()
    previous_cipher = iv
    for i in range(0, len(data), block_length):
        previous_block = pkcs_pad(data[i:i+block_length], block_length=block_length)
        previous_cipher = ecb_encrypt(xor(previous_cipher, previous_block), key)
        cipher += previous_cipher
    return cipher

def main():
    args = sys.argv[1:]
    if '-9' in sys.argv:
        new = pkcs_pad(args[0].encode('ascii'))
        print(f"Length {len(new)}, data: '{new}'")
        print(f"Unpadded: {pkcs_unpad(new)}")
    if '-10' in sys.argv:
        data = args[0].encode('ascii')

if __name__ == "__main__":
    main()
