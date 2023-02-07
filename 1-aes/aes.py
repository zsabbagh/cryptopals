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

parser = argparse.ArgumentParser(
                    prog = 'AES cipher',
                    description = 'Uses library to decrypt and encrypt AES',
                    epilog = 'See ya.')
parser.add_argument('filename')           # positional argument
parser.add_argument('-k', '--key', type=str, default="YELLOW SUBMARINE")      # option that takes a value
args = parser.parse_args()

def aes_decipher(data, key, mode=AES.MODE_ECB):
    cipher = AES.new(key, mode)
    plaintext = cipher.decrypt(data)
    return plaintext.decode('ascii')

def main():
    key = args.key
    file = args.filename
    if key is None:
        print("No key provided.")
        exit(1)
    if type(key) == str:
        key = key.encode('ascii')
    data = open(file, 'rb').read()
    print(aes_decipher(data, key))

if __name__ == "__main__":
    main()
