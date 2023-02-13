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

### Decipher Repeating XOR

This solution was not very simple, so for more detailed explanation, check GitHub repo. First of all, I performed an analysis of the hamming distance given certain key lengths. This is according to the description of the assignment. 

Secondly, when the key-length candidates was found, I went through them one by one. For each, I split the data into groups. And for each group I did the following:

1. I tried to XOR the group with each character from the characters I thought was reasonable being in an English text. When done, I checked that the percentage of English characters was at least 98 percent. This would mean that the projected text could be English.
2. For each such character, I then concatenated it to a key and returned it.

As the key finder is the most important, I display it here:

```python
def key_finder(groups, minimum_alpha=0.98):
	potentials = []
	for nr in range(len(groups)):
	    potentials.append([])
	    group = groups[nr]
	    for char in ENGLISH:
	        res = xor_single(group, char)
	        prop = alpha_prop(res, alphabet=ENGLISH)
	        if prop >= minimum_alpha:
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
```

The result was `Terminator X: Bring the noise` as a key, with a key length of 29, and the first 56 characters (2 times the key length) of the decrypted text is:

> *I'm back and I'm ringin' the bell
A rockin' on the mike while the fly girls yell
In ecstasy in the back of me
Well that's my DJ Deshay cuttin' all them Z's
Hittin' hard and the girlies goin' crazy
Vanilla's on the mike, man I'm not lazy.*
> 

For the full text, see the GitHub repository.’

### AES in Code

See decrypted. Used `Crypto.Cipher`.

```python
cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(data)
```

An implementation of AES could be found here https://github.com/zsabbagh/acry-aes.

### Detect AES

For each line, I created a dictionary and counted the occurrence of each 16 byte block. For line 132, there was 4 re-occurrences of the byte-sequence `08649af70dc06f4fd5d2d69c744cd283`. Thus, it is reasonable to say that line 132 was encrypted with AES mode ECB.

```python
def detect_block_repetition(data_lines: list):
    out = []
    for linenr in range(len(data_lines)):
        data = data_lines[linenr]
        previous = {}
        for i in range(0, len(data), 16):
            block = data[i:i+16].hex()
            if block in previous:
                previous[block] += 1
            else:
                previous[block] = 1
        for (k, v) in previous.items():
            if v > 1:
                out.append((linenr, k, v))
    return out
```

For full information about implementation, see GitHub repo code. Note that both AES are located under `set-1/aes` directory.

# Set 2

---

### PKCS#7 padding

For PKCS#7 padding, the code below did the job. The behaviour of when the length of the data is bigger than the `block_length,` is not clearly specified. Hence, I decided to return the slice (copy) of the first `block_length` bytes.

```python
def pkcs_pad(data: bytes, block_length: int=20) -> bytes:
    if len(data) > block_length:
        return data[:block_length]
    diff = block_length - len(data)
    return data + bytes([diff] * diff)
```

Default parameter is here set to 20, but in the code it is set to 16 as it is the default `AES.block_size`.

### CBC

Quite straight-forward solution. Each block gets XOR:ed with the previous block, where the first round gets XOR:ed with the Initialisation Vector.

```python

def cbc_encrypt(data: bytes, key: bytes, iv: bytes, block_length: int=AES.block_size):
    cipher = bytes()
    previous_input = iv
    for i in range(0, len(data), block_length):
        plaintext = pkcs_pad(data[i:i+block_length], block_length=block_length)
        previous_input = ecb_encrypt(xor(previous_input, plaintext), key)
        cipher += previous_input
    return cipher
```

Similarly does the decryption function work:

```python
def cbc_decrypt(data: bytes, key: bytes, iv: bytes, block_length: int = AES.block_size):
    plain = bytes()
    previous_block_xor = iv
    for i in range(0, len(data), block_length):
        encrypted = data[i:i+block_length]
        plain += xor(previous_block_xor, ecb_decrypt(encrypted, key))
        previous_block_xor = encrypted
    return pkcs_unpad(plain)
```

### Encryption Oracle

The encrypting oracle basically randomises the encryption:

```python
def encrypting_oracle(data, key, iv):
	is_ecb_encrypted = random.randint(0, 1) == 0
	if is_ecb_encrypted:
	  return ecb_encrypt(data, key), True
	return cbc_encrypt(data, key, iv), False
```

Probabilistically speaking, if one block is detected to occur more than once, it is deemed to be ECB:

```python
def is_ecb(data: bytes, block_length: int=AES.block_size) -> bool:
    occurrences = dict()
    for i in range(0, len(data), block_length):
        block = data[i:i+block_length].hex()
        if block in occurrences:
            occurrences[block] += 1
        else:
            occurrences[block] = 1
    for (_, times) in occurrences.items():
        if times > 1:
            return True
    return False
```

When there are no repetitions in the plaintext, the chance of guessing correct is expected to be 50%.

### **Byte-at-a-time ECB decryption (Simple)**

The first important function is to find the block length of the ECB encryption.

```python
def find_block_length(algorithm):
    prev_len = -1
    block_len = None
    # Current input
    start = b''
    # Find block length
    while block_len is None:
        length = len(algorithm(start))
        if length > prev_len and prev_len > 0:
            block_len = length - prev_len
            break
        else:
            prev_len = length
        start += b'A'
    return block_len
```

Input is an algorithm which encrypts using ECB. Start with an empty byte-sequence to encrypt, and for each iteration append a byte. When the length changes of the encryption, record that change and return the difference between the encrypted data lengths.

What the algorithm later does, is to check for minimum blocks to check:

```python
# Min blocks
encrypted = algorithm(b'')
# Floor division
min_blocks = len(encrypted) // block_len
```

When this is done, we enter the main loop:

```python
total = b''
for r in range(0, min_blocks):
    round = r * block_len
    result = b''
    for n in range(1, block_len+1):
        nfew_bytes = b'A' * (block_len - n)
        tracker = {}
        # Go through all possible bytes
        for i in range(256):
            byte = single_byte(i)
            # Must offset byteval to last position
            curr_input = nfew_bytes + total + result + byte
            encrypted = algorithm(curr_input)
            tracker[byte] = encrypted[round:round+block_len]
        output = algorithm(nfew_bytes)
        # Search for a match
        for (byte, encrypted) in tracker.items():
            if encrypted == output[round:round+block_len]:
                result += byte
                break
    total += result
```

What this does basically, is go through each block, and for each block, go through each and every single character starting with the last one. Try every single byte for that character, then when a match occurs on that block, that byte must be the first of the “key” that we are searching for. 

When the first byte is found, one then does the same by adding `curr_input = nfew_bytes + total + result + byte` as input, i.e. add the previous result to the input. Then we check equality for the current round’s block with the expected value of the encryption with `output = algorithm(nfew_bytes)`, by checking `if encrypted == output[round:round+block_len]`. 

The result is then added to the `total`, for each block that will be tested.

### ECB cut-and-paste

The first function is the parser:

```python
def parse_cookie(cookie: str, delim: str='&', eq: str='=') -> dict:
    first =  filter(len, cookie.split(delim))
    res = dict(filter(lambda x : len(x) == 2, map(lambda x : x.split(eq), first)))
    return res
```

The second one is:

```python
def profile_for(email: str) -> str:
    """
        Generates a profile for an email
        Returns None if email is invalid
    """
    email = re.sub('[&=]', '', email)
    uid = str(random.randint(0, 1024))
    uid = '0' * (4 - len(uid)) + uid
    return f"email={email}&uid={uid}&role=user"
```

And the other utility is:

```python
def unparse_cookie(parsed_cookie: dict):
    out = []
    items = parsed_cookie.items()
    i = 0
    for (k, v) in items:
        out.append(k + '=' + v)
        i += 1
        if i < len(items):
            out.append('&')
    return ''.join(out)
```

The assignment is solved by doing several steps. We need to get a padded `admin` block, so that we could input it directly after the `role=` plaintext in the encoded profile.

1. Create a dummy email, let’s say `a@b.c`.  We know that an encoded character will be `email=...&uid`, so if we pad the email to be exactly equal to the block length (i.e. 16), and then append a `pad(b'admin')` block, we would know that the second encrypted block would exactly be equal to `admin`.
2. We create a new email which pads up to the third block, such that the last characters exactly before the third block are `...uid=xxxx&role=`. We encrypt this input data.
3. Now, we could replace the third block of the most recently encrypted data with the `admin` block. We then have `previous[:2*block] + admin_block`. When we decrypt this, with the email as mentioned, we get:
    
    `email=a@b.c......&uid=0521&role=admin`
    

### **Byte-at-a-time ECB decryption (Harder)**

To start with, we could still use the `find_block_length` function from the previous byte-at-a-time breaker, since even though the prefix has a random length, it is constant through the current session. We first calculate the `block_len`.

This assignment is more difficult as we do not know the length of the prefix or the suffix. As a result, we cannot assume that the prefix will evenly align with a block, i.e. that the length of the prefix is 0 modulo the block length. We cannot start breaking the ECB directly, but need to figure out what is needed to be added to ensure that we start on an “empty” block.

We could do this by generating a length of repeating characters with a length of `2 * block_len`, then adding the same character 1 more time for each round. We encrypt that repeating sequence, then check if there are two blocks with repeating output from the ECB encryption algorithm. When we detect it, we have found our `char_offset` and `block_offset`. These are essential, as the `char_offset` says how many characters we need to add to get aligned with the next block seen from the prefix. Furthermore, the `block_offset` says how many bytes we need to offset to check where the encrypted blocks are equal. 

```python
# iterate till we find two repetitions
for offset in range(0, block_len):
    repetition = algorithm(b'A' * (2 * block_len + offset))
    for i in range(block_len, len(repetition), block_len):
        if repetition[i-block_len:i] == repetition[i:i+block_len]:
            char_offset = offset
            block_offset = i - block_len
						prefix_len = block_offset - char_offset
            break
    if char_offset is not None:
        break
```

More specifically, the relation between these are such that `block_offset - char_offset = prefix_len`, which gives us the information of how many minimum blocks the `suffix` or key we are looking for is.

```python
# Encrypt an empty byte-sequence
encrypted = algorithm(b'')
if prefix_len is None:
    min_blocks = len(encrypted) // block_len
else:
		# We can deduce the amount of minimum blocks from the prefix_len
    min_blocks = (len(encrypted) - prefix_len) // block_len
```

After this, the algorithm is very similar to the corresponding Simple challenge. The main difference is that we now use a `filler` which aligns the first block. We also use the `block_offset` to check for a match in the encrypted output.

```python
# changed line
nfew_bytes = filler + b'A' * (block_len - n)
...
# also a changed line
if encrypted == output[block_offset+round:block_offset+round+block_len]:
```

With this, we get the same output as the previous assignment, i.e. we have solved the challenge.

### PKCS padding validation

This solution is quite straight-forward and speaks for itself. Go through each byte, from the index of which the last byte points to, to the last index in the byte array. If the index is negative, greater or equal to the array length, or the value of the byte at that index is not equal to the value of the last index, we raise a `ValueError` (by the specification of the assignment — I would prefer to return `False`). Also, raise an error if the length is zero. Return `True` if the range is successfully checked.

```python
def pkcs_validate(data: bytes) -> bool:
    if len(data) < 1:
        raise ValueError
    for i in range(len(data)-data[-1], len(data)):
        if i < 0 or i > len(data)-1 or data[i] != data[-1]:
            raise ValueError
    return True
```

This passes all tests according to the challenge specification.
