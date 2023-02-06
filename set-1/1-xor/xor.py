"""
    Single XOR from Set 1
"""

def main():
    line = input().rstrip()
    line = [ int(line[i:i+2], 16) for i in range(0, len(line), 2) ]
    for i in range(256):
        res = ''.join(list(map(lambda x : chr(x ^ i), line))).rstrip()
        res = res.split(' ')
        # Get average word length
        word_length =  sum(list(map(len, res))) / float(len(res))
        if word_length > 2 and word_length < 6:
            print(f"\nAlternative key: {i}, '{chr(i)}'")
            print(' '.join(res))

if __name__ == "__main__":
    main()
