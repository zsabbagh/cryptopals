"""
    Repeating XOR
"""
import sys
import os
import copy
import time

DELIMITERS = " _"

def xor_key(data, key):
    out = bytearray()
    i = 0
    if type(data[0]) == str:
        data = list(map(ord, data))
    if type(key[0]) == str:
        key = list(map(ord, key))
    for a in data:
        c = a
        c ^= key[i]
        i = i+1 if (i+1) % len(key) != 0 else 0
        out.append(c)
    return out

def hamming_distance(a, b):
    if len(a) != len(b):
        return None 
    if type(a) == str:
        a = a.encode('ascii')
    if type(b) == str:
        b = b.encode('ascii')
    res = 0
    for i in range(len(a)):
        res += (a[i] ^ b[i]).bit_count()
    return res

def hamming_normalised(splits):
    if len(splits) == 0 or len(splits[0]) == 0:
        return None
    res = 0
    counted = 0
    for i in range(len(splits)):
        for j in range(i+1, len(splits)):
            value = hamming_distance(splits[i], splits[j])
            if value is not None:
                res += value
                counted += 1
    res /= counted
    return res / float(len(splits[0]))

def find_keylen(data, limit=40):
    candidates = []
    for keylen in range(2, len(data)):
        if keylen > limit:
            break
        splits = []
        for i in range(0, len(data), keylen):
            if i + keylen > len(data):
                break
            splits.append(data[i:i+keylen])
        candidates.append([keylen, hamming_normalised(splits)])
    candidates = list(filter(lambda x : x[1] > 0, candidates))
    for i in range(len(candidates)):
        for j in range(len(candidates)):
            if i == j:
                continue
            if candidates[i][0] % candidates[j][0] == 0:
                candidates[i][1] *= 0.95
    candidates = sorted(candidates, key=lambda x : x[1])
    return candidates

def xor(group, key):
    out = []
    for i in range(len(group)):
        out.append(group[i] ^ key)
    return out

def alpha_prop(group):
    if group is None or len(group) == 0:
        return 0
    res = 0
    for c in group:
        if type(c) != str:
            c = chr(c)
        if c.isalpha():
            res += 1
    return float(res) / len(group)

def split_groups(data, keylen):
    out = [None] * keylen
    for i in range(len(data)):
        groupnr = i % keylen
        if out[groupnr] is None:
            out[groupnr] = [data[i]]
        else:
            out[groupnr].append(data[i])
    return out

def average_wordlen(data, delimiters):
    out = []
    if type(data) == list:
        if len(data) == 0:
            return None
        if type(data[0]) == str:
            data = ''.join(data)
        elif type(data[0]) == int:
            data = ''.join(list(map(chr, data)))
    for delim in delimiters:
        words = data.split(delim)
        out.append(sum(list(map(len, words))) / float(len(words)))
    return out

def key_candidates(alphabet, groups, keylen, min_prop=0.1, nmost_prob=3):
    candidates = []
    for nr in range(len(groups)):
        candidates.append([])
        for a in alphabet:
            if type(a) == str:
                a = ord(a)
            group = xor(groups[nr], a)
            prop = alpha_prop(group)
            if prop < min_prop:
                continue
            candidates[nr].append([chr(a), prop])
    candidates = list(map(lambda x : sorted(x, key=lambda x : x[1], reverse=True)[:nmost_prob], candidates))
    return candidates

def key_trier(data, candidates):
    for nr in range(len(candidates)):
        key = []
        key.append(candidates[nr][0][0])
    key = ''.join(key)
    res = ''.join(list(map(chr, xor_key(data, key))))
    avg =  average_wordlen(res, " _")
    if avg[0] < 50 or avg[1] < 40:
        print(res)

def decipher(data):
    cand_keylens = find_keylen(data)
    for cand_keylen in cand_keylens:
        keylen = cand_keylen[0]
        groups = split_groups(data, keylen)
        print(f"Keylen: {keylen}")
        keys = key_candidates("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ", groups, keylen)
        key_trier(data, keys)

def main():
    if len(sys.argv) < 2:
        print("No arguments input")
        exit(1)
    if "-d" in sys.argv:
        # decrypt
        data = open(sys.argv[1], 'rb').read()
        decipher(data)
        pass
    else:
        file = open(sys.argv[1], 'r').read().rstrip()
        print(xor_key(file, "KEYFACTS").hex())

if __name__ == "__main__":
    main()
