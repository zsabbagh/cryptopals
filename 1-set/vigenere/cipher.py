"""
    Repeating XOR
"""
import sys
import os
import copy
import time


DELIMITERS = " _"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ENGLISH = ALPHABET+"\n.,'!? -0123456789:()&%$\""

def in_alphabet(a, alphabet=None):
    if alphabet is not None:
        # If alphabet is given, check if in it
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
    if len(data) > 0 and type(data[0]) == str:
        data = list(map(ord, data))
    if type(key[0]) == str:
        key = list(map(ord, key))
    for a in data:
        c = a
        c ^= key[i]
        i = (i+1) % len(key)
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
        # Count bits set to 1
        res += (a[i] ^ b[i]).bit_count()
    return res

def hamming_normalised(splits):
    if len(splits) == 0 or len(splits[0]) == 0:
        return None
    res = 0
    counted = 0
    for i in range(len(splits)):
        for j in range(i+1, len(splits)):
            # Get hamming distance for each pair
            value = hamming_distance(splits[i], splits[j])
            if value is not None:
                res += value
                counted += 1
    if counted == 0:
        return None
    # Divide with valid pairs
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
            # Add each split
            splits.append(data[i:i+keylen])
        # Get hamming distance normalised
        norm = hamming_normalised(splits)
        candidates.append([keylen, norm])
    # Remove None's and those with value zero
    candidates = list(filter(lambda x : x[1] is not None and x[1] > 0, candidates))
    candidates = sorted(candidates, key=lambda x : x[1])
    # Give bonus gives bonus to modulo groups
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
    if len(group) > 0 and type(group[0]) == str:
        group = list(map(ord, group))
    # XOR with key
    for i in range(len(group)):
        out.append(group[i] ^ key)
    return out

def alpha_prop(group, alphabet=None) -> float:
    """
        Get proportion of alphabet occurrences
    """
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

def key_finder(groups, min_alpha_prop=0.99):
    """
        int is exit code
    """
    potentials = []
    for nr in range(len(groups)):
        potentials.append([])
        group = groups[nr]
        # Assuming the key is english
        for char in ENGLISH:
            res = xor_single(group, char)
            prop = alpha_prop(res, alphabet=ENGLISH)
            # See proportion of alphabets
            if prop >= min_alpha_prop:
                potentials[nr].append((char, prop))
    key = []
    for arr in potentials:
        if len(arr) > 1:
            key.append('[')
        for (c, _) in arr:
            key.append(c)
        if len(arr) > 1:
            key.append(']')
    # ok marks if the key is valid
    ok = True if len(key) == len(groups) else False
    return (''.join(key), ok)

def decipher(data, key=None, cand_keylens=None, nkeylens=3, give_mod_bonus=True):
    if key is not None:
        return xor_key(data, key).decode('ascii')
    if cand_keylens is None:
        cand_keylens = [x[0] for x in find_keylen(data, give_bonus=give_mod_bonus)[:nkeylens]]
    for keylen in cand_keylens:
        groups = split_groups(data, keylen)
        (key, ok) = key_finder(groups)
        if ok:
            print()
            print(f"--- POTENTIAL key found ---")
            print(f"\nKey, with length {keylen}: <<{key}>>")
            print(xor_key(data, key)[:2*keylen].decode('ascii'))
        elif len(key) < keylen:
            print(f"ERROR: No key with length {keylen} found.", file=sys.stderr)
        else:
            print(f"ERROR: Multiple key candidates found for {keylen}. Too low min_alpha_prop?", file=sys.stderr)
            print()
            print(f"--- CONFLICTING key found ---")
            print(f"\nKey, with length {keylen}: <<{key}>>")

def main():
    if len(sys.argv) < 2:
        print("No arguments input")
        exit(1)
    key = None
    use_hex = True if "--hex" in sys.argv else False
    cand_keylens = None
    for i in range(len(sys.argv)):
        if sys.argv[i] == '-k' and i+1 < len(sys.argv):
            key = sys.argv[i+1]
        if sys.argv[i] == '-l' and i+1 < len(sys.argv):
            cand_keylens = list(map(int, sys.argv[i+1].split(',')))
    if "-d" in sys.argv:
        # decrypt
        file = open(sys.argv[1], 'r').read()
        if alpha_prop(file, "0123456789abcdefABCDEF") >= 0.99:
            data = bytes.fromhex(file).decode('ascii')
        else:
            data = file.encode('ascii')
        decrypted = decipher(data, key=key, cand_keylens=cand_keylens)
        if decrypted is not None:
            print(decrypted)
        pass
    else:
        file = open(sys.argv[1], 'r').read().rstrip()
        if key is None:
            print("NO KEY PROVIDED. Exiting.")
            exit(1)
        res = xor_key(file, key)
        if use_hex:
            print(res.hex())
        else:
            sys.stdout.buffer.write(res)

if __name__ == "__main__":
    main()
