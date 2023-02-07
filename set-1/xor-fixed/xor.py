"""
    Fixed XOR from Set 1
"""

def main():
    line = input().rstrip()
    xor = input().rstrip()
    assert(len(line) == len(xor))
    out = []
    for i in range(0, len(line), 2):
        out.append(chr(int(line[i:i+2], 16) ^ int(xor[i:i+2], 16)))
    print(''.join(out))

if __name__ == "__main__":
    main()
