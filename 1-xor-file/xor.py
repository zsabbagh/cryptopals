"""
    Find a string encrypted with single XOR
"""
import sys
import numpy as np

DELIM = ' '

def hex2ints(line):
    out = []
    for i in range(0, len(line), 2):
        out.append(int(line[i:i+2], 16))
    return out

def get_alpha_proportion(line):
    count = 0
    for c in line:
        if c.isalpha():
            count += 1
    return float(count) / len(line)


def xor_map(line, key):
    return ''.join(list(map(lambda x : chr(x ^ key), line)))

def average_wordlen(line, delimiter=DELIM):
    out = line.split(delimiter)
    return float(len(line)) / len(out)

def find_key_candidates(line):
    ints = hex2ints(line)
    out = []
    for key in range(256):
        res = xor_map(ints, key)
        if get_alpha_proportion(res) < 0.8:
            continue
        avg = average_wordlen(res)
        if avg >= 2.0 and avg <= 6:
            out.append(key)
    return out

def xor_hex(line, key):
    return xor_map(hex2ints(line), key)

def main():
    args = sys.argv[1:]
    if len(args) < 1:
        print("Error: Input file as argument", file=sys.stderr)
        exit(1)
    file = open(args[0], 'r').read().rstrip().split('\n')
    for line in file:
        candidates = find_key_candidates(line)
        if len(candidates) > 0:
            print()
            print(line)
            for key in candidates:
                print(f"XOR:ed with {key}, '{chr(key)}': {xor_hex(line, key)}")


if __name__ == "__main__":
    main()
