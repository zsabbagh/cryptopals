"""
    AES decryption
"""
import sys
import os
import re
import time # .sleep(), .time(), .time_ns()
import numpy as np
from Crypto.Cipher import AES
import argparse

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ENGLISH = ALPHABET+"\n.,'!? -0123456789:()&%$\""

parser = argparse.ArgumentParser(
                    prog = 'AES cipher',
                    description = 'Uses library to decrypt and encrypt AES',
                    epilog = 'See ya.')
parser.add_argument('filename')           # positional argument
parser.add_argument('-k', '--key', type=str, default="YELLOW SUBMARINE")      # option that takes a value
parser.add_argument('--detect', action='store_true')      # option that takes a value
args = parser.parse_args()

def is_hex(s: str) -> bool:
    for c in s.lower():
        if not ((c >= 'a' and c <= 'f') or (c >= '0' and c <= '9')):
            return False
    return True

def get_bytes(data):
    out = None
    if type(data) == str:
        if is_hex(data):
            out = bytes.fromhex(data)
        else:
            out = data.encode('ascii')
    elif type(data) in [bytes, bytearray]:
        out = bytes(data)
    elif type(data) == list:
        if len(data) < 1:
            return None
        elif type(data[0]) == int:
            out = bytes(data)
    return out

def aes_decipher(data, key, mode=AES.MODE_ECB):
    key = get_bytes(key)
    data = get_bytes(data)
    cipher = AES.new(key, mode)
    plaintext = cipher.decrypt(data)
    return plaintext.decode('ascii')

def detect_block_repetition(data_lines: list):
    out = []
    for linenr in range(len(data_lines)):
        data = data_lines[linenr]
        previous = {}
        for i in range(0, len(data), 16):
            block = data[i:i+16].hex()
            if block in previous:
                previous[block] += 1
            else:
                previous[block] = 1
        for (k, v) in previous.items():
            if v > 1:
                out.append((linenr, k, v))
    return out

def main():
    file = args.filename
    if args.detect:
        lines = open(file, 'r').read().split('\n')
        data_lines = [ bytes.fromhex(line) for line in lines ]
        res = detect_block_repetition(data_lines)
        print(res)
        exit(0)
    key = args.key
    if key is None:
        print("No key provided.")
        exit(1)
    data = open(file, 'rb').read()
    print(aes_decipher(data, key))

if __name__ == "__main__":
    main()
