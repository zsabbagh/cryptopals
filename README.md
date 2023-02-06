# Cryptopals

---

[https://github.com/zsabbagh/cryptopals](https://github.com/zsabbagh/cryptopals)

> by Zakaria Sabbagh, zsabbagh@kth.se
> 

# Set 1

---

### Hex to Base64

This assignment was solved by simply translating each two hex-digits to their corresponding value as a byte, then converting it to ASCII.

```python
out = []
for line in sys.stdin:
    line = line.rstrip()
    for i in range(0, len(line), 2):
        out.append(chr(int(line[i:i+2], 16)))
print(''.join(out))
```

The solution was `I'm killing your brain like a poisonous mushroom` for the test data.

### Fixed XOR

The solution works by reading two lines, then for each two hex-digits, convert them to integer and then XOR them. Store them in an out-array then join the characters created and output the result.

```python
line = input().rstrip()
xor = input().rstrip()
assert(len(line) == len(xor))
out = []
for i in range(0, len(line), 2):
    out.append(chr(int(line[i:i+2], 16) ^ int(xor[i:i+2], 16)))
print(''.join(out))
```

The solution was `the kid don't play` for the test data.

### Single XOR

The purpose of the code below was assuming that space was the delimiter, what was the average word length? It would be reasonable that it would be somewhere between $3 \le w \le 6$. When run, there was only two alternatives, where only one of them was English.

```python
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
```

The solution was that the key for the test data was `X` and the resulting text was `Cooking MC's like a pound of bacon`.

Note that a more efficient version was counting the amount of alpha-characters with `str.isalpha()`. This solution was used in the next assignment.

### File XOR

Similar to the previous, but now with a focus on alpha proportion in the string after single XOR:ing with the potential key. This was more efficient. The core function used was the following:

```python
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
```

The above basically checks the proportion of alpha characters and average word length, still assuming that space is space, and only gives candidates if they are reasonable.

The following line was found amongst the test data `Now that the party is jumping` that was the line `7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f` XOR:ed with the character `5`.

### Repeating XOR

The implementation was basically to go through each character in the input line and XOR it with the character in the key’s turn. See code below.

```python
def xor_key(line, key):
    out = bytearray()
    i = 0
    for a in line:
        c = ord(a)
        c ^= ord(key[i])
        i = i+1 if (i+1) % len(key) != 0 else 0
        out.append(c)
    return out
```

The resulting hexstring matched the test data. See GitHub repo if necessary.
