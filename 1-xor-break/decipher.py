"""
    Repeating XOR
"""
import sys
import os

def xor_key(line, key):
    out = bytearray()
    i = 0
    for a in line:
        c = ord(a)
        c ^= ord(key[i])
        i = i+1 if (i+1) % len(key) != 0 else 0
        out.append(c)
    return out

def hamming_distance(a, b):
    if len(a) != len(b):
        return None 
    arr = bytearray()
    for i in range(len(a)):
        arr.append((ord(a[i]) ^ ord(b[i])).bit_count())
    return sum(arr)

def hamming_normalised(splits):
    out = []
    for i in range(len(splits)):
        for j in range(i+1, len(splits)):
            value = hamming_distance(splits[i], splits[j])
            if value is not None:
                out.append(value)
    return sum(out) / float(len(splits))

def find_keylen(data):
    candidates = []
    for keylen in range(1, len(data)):
        splits = []
        for i in range(0, len(data), keylen):
            splits.append(data[i:i+keylen])
        candidates.append([keylen, hamming_normalised(splits)])
        print(splits)

def main():
    if len(sys.argv) < 2:
        print("No arguments input")
        exit(1)
    test = "this is a test"
    wokka = "wokka wokka!!!"
    assert(hamming_distance(test, wokka) == 37)
    file = open(sys.argv[1], 'r').read().rstrip()
    if "-d" in sys.argv:
        # decrypt
        data = bytearray.fromhex(file)
        find_keylen(data)
        pass
    else:
        print(xor_key(file, "KEYFACTS").hex())

if __name__ == "__main__":
    main()