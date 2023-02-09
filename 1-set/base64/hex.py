"""
    Hex to ASCII = Hex to Base64
"""
import sys

def main():
    out = []
    for line in sys.stdin:
        line = line.rstrip()
        for i in range(0, len(line), 2):
            out.append(chr(int(line[i:i+2], 16)))
    print(''.join(out))

if __name__ == "__main__":
    main()
