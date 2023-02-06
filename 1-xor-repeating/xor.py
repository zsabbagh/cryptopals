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

def main():
    file = []
    key = input().rstrip()
    for line in sys.stdin:
        print(line, end='')
        file.append(line)
    file = ''.join(file).rstrip()
    got = xor_key(file, key).hex()
    expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    assert(got == expected)
    print(f'\nXOR:ed with {key}')
    print(got)

if __name__ == "__main__":
    main()
