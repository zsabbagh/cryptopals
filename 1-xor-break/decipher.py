"""
    Repeating XOR
"""
import sys
import os
import copy
import time


DELIMITERS = " _"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ENGLISH = ALPHABET+"\n.,'!? -0123456789:"

def in_alphabet(a, alphabet=None):
    if alphabet is not None:
        if type(a) != str:
            a = chr(a)
        return True if a in alphabet else False
    val = a
    if type(a) == str:
        val = ord(a)
    return (val >= 65 and val <= 90) or (val >= 97 and val <= 122)

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

def find_keylen(data, n_most_likely=5, limit=40, give_bonus=False):
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
    candidates = sorted(candidates, key=lambda x : x[1])
    if give_bonus:
        for i in range(n_most_likely):
            for j in range(n_most_likely+5):
                if i == j:
                    continue
                if candidates[i][0] % candidates[j][0] == 0:
                    candidates[j][1] *= 0.95
        candidates = sorted(candidates, key=lambda x : x[1])
    return candidates

def xor_single(group: bytearray, key) -> list:
    if type(key) == str:
        if len(key) == 1:
            key = ord(key)
        else:
            key = int(key, 16)
    out = bytearray()
    for i in range(len(group)):
        out.append(group[i] ^ key)
    return out

def alpha_prop(group, alphabet = None):
    if group is None or len(group) == 0:
        return 0
    res = 0
    for c in group:
        if in_alphabet(c, alphabet=alphabet):
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

def key_finder(groups, alpha_proportion=0.98):
    """
        int is exit code
    """
    print()
    print(f"Keylen: {len(groups)}")
    potentials = []
    for nr in range(len(groups)):
        potentials.append([])
        group = groups[nr]
        for char in ENGLISH:
            res = xor_single(group, char)
            prop = alpha_prop(res, alphabet=ENGLISH)
            if prop >= alpha_proportion:
                potentials[nr].append((char, prop))
    key = []
    for arr in potentials:
        if len(arr) > 1:
            print("ERROR: Multiple key candidates found.", file=sys.stderr)
            key.append('{')
        for (c, _) in arr:
            key.append(c)
        if len(arr) > 1:
            key.append('}')
    ok = True if len(key) == len(groups) else False
    return (''.join(key), ok)

def most_common(data, n=3):
    counter = {}
    for c in data:
        if c in counter:
            counter[c] += 1
        else:
            counter[c] = 1
    return list(map(lambda x : x[0], sorted(counter.items(), key=lambda x : x[1])[:n]))


def decipher(data, key=None, nkeylens=3):
    if key is not None:
        return xor_key(data, key).decode('ascii')
    cand_keylens = find_keylen(data)[:nkeylens]
    for cand_keylen in cand_keylens:
        keylen = cand_keylen[0]
        groups = split_groups(data, keylen)
        (key, ok) = key_finder(groups)
        if ok:
            print()
            print(f"--- Potential key found ---")
            print(f"\nKey, with length {keylen}: <<{key}>>")
            print(xor_key(data, key)[:2*keylen].decode('ascii'))

def main():
    if len(sys.argv) < 2:
        print("No arguments input")
        exit(1)
    key = None
    for i in range(len(sys.argv)):
        if sys.argv[i] == '-k' and i+1 < len(sys.argv):
            key = sys.argv[i+1]
    if "-d" in sys.argv:
        # decrypt
        data = open(sys.argv[1], 'rb').read()
        print(decipher(data, key=key))
        pass
    else:
        file = open(sys.argv[1], 'r').read().rstrip()
        print(xor_key(file, "KEYFACTS").hex())

if __name__ == "__main__":
    main()
