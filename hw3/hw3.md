# Homework 3 - Password Cracking

## Part 1: TryHackMe - Crack the Hash

![TryHackMe completion screenshot](images/crackthehashcompleted(emmanart).png)

## Part 2: Redo with John the Ripper

I used the following template command to crack each hash:

```sh
john --format=FORMAT --wordlist=WORDLIST HASHFILE > /dev/null 2>&1 && john --show --format=FORMAT HASHFILE
```

Where:
- `FORMAT` = the hash format (e.g., `Raw-MD5`)
- `WORDLIST` = the wordlist file (e.g., `/usr/share/wordlists/rockyou.txt`)
- `HASHFILE` = the file containing the hash (e.g., `hash1.txt`)

### Hash 1: MD5

Hash: `48bb6e862e54f2a795ffc4e541caed4d`

```sh
❯ echo "48bb6e862e54f2a795ffc4e541caed4d" > hash1.txt

❯ john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt > /dev/null 2>&1 && john --show --format=Raw-MD5 hash1.txt
?:easy
1 password hash cracked, 0 left
```

Password: `easy`

### Hash 2: SHA-1

Hash: `CBFDAC6008F9CAB4083784CBD1874F76618D2A97`

```sh
❯ echo "CBFDAC6008F9CAB4083784CBD1874F76618D2A97" > hash1.txt

❯ john --format=Raw-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt > /dev/null 2>&1 && john --show --format=Raw-SHA1 hash1.txt
?:password123
1 password hash cracked, 0 left
```

Password: `password123`

### Hash 3: SHA-256

Hash: `1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032`

```sh
❯ echo "1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032" > hash1.txt

❯ john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt > /dev/null 2>&1 && john --show --format=Raw-SHA256 hash1.txt
?:letmein
1 password hash cracked, 0 left
```

Password: `letmein`

### Hash 4: bcrypt

Hash: `$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom`

```sh
❯ echo '$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom' > hash1.txt

❯ john --format=bcrypt --wordlist=rockyou_4char.txt hash1.txt > /dev/null 2>&1 && john --show --format=bcrypt hash1.txt
?:bleh
1 password hash cracked, 0 left
```

Password: `bleh`

### Hash 5: SHA-256

Hash: `F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85`

```sh
❯ echo "F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85" > hash1.txt

❯ john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt > /dev/null 2>&1 && john --show --format=Raw-SHA256 hash1.txt
?:paule
1 password hash cracked, 0 left
```

Password: `paule`

### Hash 6: NTLM

Hash: `1DFECA0C002AE40B8619ECF94819CC1B`

```sh
❯ echo "1DFECA0C002AE40B8619ECF94819CC1B" > hash1.txt

❯ john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt > /dev/null 2>&1 && john --show --format=NT hash1.txt
?:n63umy8lkf4i
1 password hash cracked, 0 left
```

Password: `n63umy8lkf4i`

### Hash 7: SHA-512 crypt

Hash: `$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.`

Salt: `aReallyHardSalt`

```sh
❯ echo '$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.' > hash1.txt

❯ grep -E '^.{6}$' /usr/share/wordlists/rockyou.txt > rockyou_6char.txt && john --format=sha512crypt --wordlist=rockyou_6char.txt hash1.txt > /dev/null 2>&1 && john --show --format=sha512crypt hash1.txt
?:waka99
1 password hash cracked, 0 left
```

Password: `waka99`

### Hash 8: Salted hash (unsupported by John)

Hash: `e5d8870e5bdd26602cab8dbe07a942c8669e56d6`

Salt: `tryhackme`

Note: John the Ripper does not support this hash format.

### Hash 9: MD4 (unsolved)

Hash: `279412f945939ba78ce0758d3fd83daa`

I attempted to crack this hash using multiple formats and approaches:

```sh
❯ echo "279412f945939ba78ce0758d3fd83daa" > hash1.txt

❯ grep -E '^.{10}$' /usr/share/wordlists/rockyou.txt > rockyou_10char.txt

❯ wc -l rockyou_10char.txt
2014080 rockyou_10char.txt

❯ john --format=Raw-MD4 --wordlist=rockyou_10char.txt hash1.txt > /dev/null 2>&1 && john --show --format=Raw-MD4 hash1.txt
0 password hashes cracked, 1 left

❯ john --format=MD2 --wordlist=rockyou_10char.txt hash1.txt > /dev/null 2>&1 && john --show --format=MD2 hash1.txt
0 password hashes cracked, 1 left

❯ john --format=Raw-MD5 --wordlist=rockyou_10char.txt hash1.txt > /dev/null 2>&1 && john --show --format=Raw-MD5 hash1.txt
0 password hashes cracked, 1 left

❯ john --format=NT --wordlist=rockyou_10char.txt hash1.txt > /dev/null 2>&1 && john --show --format=NT hash1.txt
0 password hashes cracked, 1 left
```

I tried multiple hash formats (Raw-MD4, MD2, Raw-MD5, NT) with a filtered wordlist of over 2 million ten-character words from rockyou.txt, but was unable to crack this hash.

## Part 3: John Utilities and Passphrase Cracking

Note: I had to restart my computer during this part, so I lost the output data for all commands I ran in the first 8 steps (Steps 1-8). However, I have copied and pasted all my terminal activity after the restart in `commands_and_output.txt`.

### Step 1: Create sample.awk script
I created the sample.awk script using the code provided in the homework instructions.

### Step 2: Create rockyou20.txt
I ran the command `awk -f sample.awk -v n=20 /usr/share/wordlists/rockyou.txt > rockyou20.txt` to create a file with 20 random lines from the rockyou wordlist. I verified it worked by running `wc -l rockyou20.txt` which showed 20 lines.

### Step 3: Select 3 random words from rockyou20.txt
I ran the command `awk -f sample.awk -v n=3 rockyou20.txt` which produced three words: `m71864`, `flygal32`, and `903242`.

### Step 4: Create SSH key with passphrase
I created an ed25519 SSH key using the command `ssh-keygen -t ed25519 -f test_key -N "m71864 flygal32 903242"`. The key pair was successfully generated with the private key saved in `test_key` and the public key saved in `test_key.pub`.

### Step 5: Convert SSH key to John format
I ran the command `python3 /usr/share/john/ssh2john.py test_key > test_key.john` to convert the SSH key to a format that John can understand. The file `test_key.john` was successfully created.

### Step 6: Generate 2-word combinations with spaces
I created a version of rockyou20.txt with trailing spaces using `sed 's/$/ /' rockyou20.txt > rockyou20_space.txt`. Then I generated all 2-word combinations with spaces between words using `hashcat --stdout -a 1 rockyou20_space.txt rockyou20_space.txt > two_word_space.txt`. This created 400 combinations in the format "word1 word2 " with spaces between the words.

### Step 7: Generate all 3-word combinations
I combined the 2-word combinations with the third word from rockyou20.txt using `hashcat --stdout -a 1 two_word_space.txt rockyou20.txt > combinations.txt`. This created all 8000 possible 3-word combinations in the format "word1 word2 word3" with spaces between all words.

### Step 8: Attempt to crack with hashcat
I attempted to crack the key using hashcat with the command `hashcat -m 22921 -a 0 test_key.john combinations.txt` and `hashcat -m 22921 -a 0 test_key combinations.txt`. However, hashcat reported "Signature unmatched" errors and was unable to load the hash. Hashcat does not appear to support the ssh2john format directly.

### Step 9: Crack with John
I recreated the john format file using `python3 /usr/share/john/ssh2john.py test_key > test_key_clean.john` to ensure it was properly formatted. Then I successfully cracked the key using John:

```sh
❯ python3 /usr/share/john/ssh2john.py test_key > test_key_clean.john

❯ john --format=SSH --wordlist=combinations.txt test_key_clean.john > /dev/null 2>&1 && john --show --format=SSH test_key_clean.john
test_key:m71864 flygal32 903242
1 password hash cracked, 0 left
```

Password: `m71864 flygal32 903242`

---

## Part 4: Python Script for 3-Word Combinations

I wrote a Python script (`combinations.py`) that replicates the functionality of hashcat for generating all 3-word combinations. The script:

1. Reads words from `rockyou20.txt` line by line into a list
2. Uses a backtracking algorithm to generate all possible 3-word combinations (with replacement, allowing the same word to appear multiple times)
3. Joins each combination with spaces in the format "word1 word2 word3"
4. Writes all combinations to `three_word_combinations.txt`, one per line

I ran the script and verified it works correctly by comparing the output with the hashcat-generated `combinations.txt` file:

```sh
❯ python combinations.py

❯ wc -l combinations.txt three_word_combinations.txt
  8000 combinations.txt
  8000 three_word_combinations.txt
 16000 total

❯ diff combinations.txt three_word_combinations.txt
```

Both files contain exactly 8000 lines, and `diff` showed no differences, confirming the files are identical. The script successfully generates all 20 × 20 × 20 = 8000 possible 3-word combinations from the 20 words in rockyou20.txt.

