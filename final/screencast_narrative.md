# Directory Challenge - Screencast Narrative Guide

This document provides detailed explanations of what happened during the solution of each question, designed to help you narrate the screencast effectively.

---

## Question 1: Open Ports

### The Problem
We need to identify which ports the attacker found open during their initial reconnaissance scan. The question asks for ports from lowest to highest, comma-separated.

### The Approach

**Initial Analysis:**
- Started by examining the first few packets to understand the traffic pattern
- Identified the attacker's IP (10.0.2.74) and target IP (10.0.2.75)
- Observed SYN packets being sent to various ports - this is a port scan

**Understanding Port Scanning:**
- When an attacker scans ports, they send SYN packets (TCP connection initiation)
- **Open ports** respond with SYN-ACK (both SYN and ACK flags set)
- **Closed ports** respond with RST (reset)
- This is the TCP three-way handshake concept from the course

**The Solution Technique:**
1. **Filter for SYN-ACK responses:** Used `tcpdump` with BPF filter `tcp[13] == 18`
   - Byte 13 in the TCP header contains the flags
   - SYN flag = 2, ACK flag = 16, so SYN+ACK = 18
   - This is a byte-level filter we learned in HW4

2. **Extract port numbers:** Built a text processing pipeline:
   - `grep "10.0.2.75\."` - Only responses from the target
   - `awk '{print $3}'` - Extract the source IP:port field
   - `cut -d'.' -f5` - Split by dots, get the port (5th field)
   - `sort -n` - Sort numerically
   - `uniq` - Remove duplicates

**The Challenge:**
- Initially, the output included responses from external IPs (outbound connections)
- Had to add host filtering: `host 10.0.2.75 and host 10.0.2.74` to only show traffic between attacker and target

**The Result:**
Found 14 open ports: 53 (DNS), 80 (HTTP), 88 (Kerberos), 135 (MSRPC), 139 (NetBIOS), 389 (LDAP), 445 (SMB), 464 (Kerberos), 593 (RPC over HTTP), 636 (LDAP over SSL), 3268/3269 (LDAP Global Catalog), 5357 (Windows Media Player), and 5985 (WinRM).

**What to Narrate:**
- "So I started by looking at how port scanning works - basically the attacker sends SYN packets and we look at the responses"
- "Open ports respond with SYN-ACK, and I can find those using a BPF filter on the TCP flags byte - that's byte 13 in the header"
- "Then I built this text processing pipeline using grep, awk, cut, sort - all the tools we learned in HW2 - to pull out and sort the port numbers"
- "The tricky part was filtering by the specific hosts because initially I was getting responses from external IPs that weren't part of the scan"

---

## Question 2: Username That Achieved Foothold

### The Problem
The attacker found four valid usernames, but only one allowed them to achieve a foothold (successful remote access). We need to identify which username this was, in the format Domain.TLD\username.

### The Approach - Multiple Failed Attempts

**Initial Wrong Approach - SMB/NTLM:**
- Started by looking at SMB traffic (port 445) where authentication happens
- Tried to extract usernames from NTLM authentication packets
- **Problem:** NTLM encodes usernames in binary format - not directly readable
- Tried multiple regex patterns, string searches, but usernames were obfuscated

**The Breakthrough - Kerberos Traffic:**
- Switched to analyzing Kerberos traffic (port 88)
- Kerberos is the authentication protocol used in Windows Active Directory
- **Key insight:** Kerberos tickets contain usernames in **readable form** in the AS-REQ and AS-REP packets
- This is different from NTLM, which encodes everything

**The Solution Steps:**

1. **Examine Kerberos packets:**
   ```bash
   tcpdump -r traffic-1725627206938.pcap -n -A -s 0 'port 88 and tcp[tcpflags] & tcp-push != 0'
   ```
   - `-A` shows ASCII output so we can read the usernames
   - `tcp-push != 0` filters for packets with actual data (not just handshakes)
   - Found readable usernames: `larry.doe`, `john.doe`, `ranith.kays`, `joan.ray`

2. **Find all four usernames:**
   - Used `grep` with pattern matching to find all usernames
   - Pattern: `(\.doe|\.ray|\.kays|\.ranith)` to match the username patterns
   - Found all four: larry.doe, john.doe, ranith.kays, joan.ray

3. **Identify which one achieved foothold:**
   - **Timing analysis:** `larry.doe` appears first at 20:43:52, before others at 20:44:32
   - **Frequency:** `larry.doe` appears multiple times, indicating successful authentication
   - **Verification:** Decoded WinRM Authorization header (base64-encoded NTLM) and found `larry.doe` inside
   - **Timeline correlation:** larry.doe Kerberos (20:43:52) → SMB auth (20:45:17) → WinRM connection (20:45:17.627)

**The Challenges:**
- Shell escaping issues when searching for backslashes (`grep: Trailing backslash`)
- Initially found `john.doe` and thought it was correct based on frequency - but timing matters more
- Had to understand that different protocols store data differently (Kerberos readable, NTLM encoded)

**What to Narrate:**
- "At first I tried getting usernames from SMB and NTLM traffic, but that didn't work because NTLM encodes everything in binary - you can't just read the usernames directly"
- "The real breakthrough was switching to Kerberos traffic on port 88 - that's where usernames actually show up in readable form in the authentication packets"
- "I found all four usernames pretty easily, but then I had to figure out which one actually got the attacker in"
- "Looking at the timing, larry.doe showed up first at 20:43:52, and then there's this clear sequence - Kerberos auth, then SMB, then WinRM connection - so that's how I knew it was larry.doe"
- "I double-checked by decoding the WinRM Authorization header and sure enough, larry.doe was in there"

---

## Question 3: Last 30 Characters of Hash

### The Problem
The attacker captured a hash from the user in question 2. We need to find the last 30 characters of that hash.

### The Approach - Multiple Failed Attempts

**Initial Wrong Approaches:**
1. **Tried NTLM packets:** Extracted hex data from NTLM type 3 response packets in SMB traffic
   - Got multiple incorrect hashes: `6bc50093580c7ede4d6929150ad05d`, `ec611716ddf3199dfebd17161a37fc`
   - **Why wrong:** The hash isn't in NTLM packets for this challenge

2. **Tried WinRM Authorization header:** Decoded base64 and extracted hex
   - Still got incorrect hash
   - **Why wrong:** This contains authentication data, not the password hash we need

**The Correct Approach - Kerberos AS-REP:**
- The hash is actually in the **Kerberos AS-REP (Authentication Server Response)** packet
- When a user authenticates with Kerberos, the server sends back an encrypted ticket
- This encrypted ticket (in the `cipher` field) contains password-derived hash data
- This is the hash that can be cracked to recover the password

**The Solution Steps:**

1. **Use tshark to extract Kerberos cipher field:**
   ```bash
   tshark -r traffic-1725627206938.pcap -Y 'kerberos and kerberos.CNameString == "larry.doe"' -T fields -e kerberos.cipher
   ```
   - `-Y` applies a display filter (like Wireshark's filter bar)
   - Filters for Kerberos packets where the username is larry.doe
   - `-T fields -e kerberos.cipher` extracts just the cipher field

2. **Get the last packet:**
   - Multiple Kerberos packets exist for larry.doe (frames 4689, 4713, 4779, 4816, 4817)
   - Only frames 4779 and 4817 have cipher data
   - **Important:** Need the **last** packet (frame 4817) - most recent authentication
   - Used `tail -n 1` to get the last entry

3. **Extract last 30 characters:**
   ```bash
   awk '{print substr($0, length($0)-29)}'
   ```
   - `length($0)` gets the total string length
   - `length($0)-29` calculates starting position for 30 characters
   - `substr()` extracts the substring
   - This is string manipulation from HW2

**The Challenges:**
- Extracted from wrong packet initially (frame 4779 instead of 4817)
- Tried multiple wrong locations (NTLM, WinRM) before finding Kerberos
- Needed to understand that the most recent authentication packet contains the hash we need

**What to Narrate:**
- "I tried getting the hash from NTLM packets first, but that was wrong - got a few incorrect hashes that way"
- "Turns out the hash is actually in the Kerberos AS-REP response - that's the encrypted ticket the server sends back when you authenticate"
- "So I used tshark to pull out the cipher field from the Kerberos packets for larry.doe"
- "Here's the important part - I needed the last packet, frame 4817, not the first one, because that's the most recent authentication attempt"
- "Then I used awk's substr function to grab exactly the last 30 characters from that cipher field"

---

## Question 4: User's Password

### The Problem
Now that we have the hash, we need to crack it to find the user's password.

### The Approach

**Initial Attempts:**
- Tried searching for plaintext passwords in the traffic - doesn't exist (passwords are never transmitted in plaintext)
- Found some password-like strings ("Washington1", "Redmond1") but these were from certificate traffic, not authentication

**The Solution - Hash Cracking:**

1. **Extract full hash in Hashcat format:**
   - The Kerberos cipher field contains comma-separated values
   - Hashcat requires a specific format: `$krb5asrep$23$username@domain:cipher_part1$cipher_part2`
   - Used complex `awk` command to:
     - Split the cipher by comma
     - Extract the second part (the actual hash data)
     - Format with proper `$` separators as Hashcat requires

2. **Crack with Hashcat:**
   ```bash
   hashcat -a 0 -m 18200 larry_doe_hash.txt /usr/share/wordlists/rockyou.txt
   ```
   - `-a 0` = dictionary attack mode (straight wordlist attack)
   - `-m 18200` = Kerberos 5 AS-REP hash type (etype 23)
   - `rockyou.txt` = common password wordlist (14+ million passwords)

**The Challenge:**
- **Hashcat format error:** Got "Separator unmatched" error
- Hashcat is very strict about hash format
- The Kerberos cipher has comma-separated values, but Hashcat needs `$` separators
- Had to use complex `awk` to reformat the hash correctly

**The Result:**
- Password cracked in less than 1 second!
- Found at position 184,320 in the rockyou wordlist
- Password: `Password1!`
- This demonstrates why weak passwords are vulnerable - it was found quickly in a common wordlist

**What to Narrate:**
- "Obviously passwords aren't sent in plaintext, so I had to crack the hash"
- "I pulled out the full Kerberos AS-REP hash from frame 4817 and had to format it properly for Hashcat"
- "Hashcat is really picky about format - it needs dollar sign separators in specific places, so I had to use this complex awk command to reformat it"
- "I ran Hashcat with mode 18200, which is for Kerberos AS-REP hashes, and used the rockyou wordlist"
- "It cracked almost instantly - the password was `Password1!` - which just shows how vulnerable weak passwords are to dictionary attacks"

---

## Question 5: Second and Third Commands

### The Problem
We need to find what commands the attacker executed after gaining access. The question asks for the second and third commands.

### The Approach - The Encryption Challenge

**Initial Problem:**
- WinRM traffic (port 5985) is **encrypted**
- Commands are not visible in plaintext
- Tried multiple approaches:
  - `tcpdump -A` - only showed HTTP headers
  - `tshark` with various filters - still encrypted
  - `strings` on the PCAP - no readable commands

**Failed Attempt - Kerberos Decryption:**
- Tried to decrypt using Kerberos keytab with `tshark`
- Created keytab file using `ktutil` with larry.doe's password
- Attempted: `tshark -o 'kerberos.decrypt:TRUE' -o 'kerberos.file:larry_doe.keytab'`
- **Why it failed:** WinRM uses **NTLM** for encryption, not Kerberos
- The session key is derived from NTLM, not from Kerberos tickets

**The Solution - Python Decryption Script:**
- Used a provided Python script (`decrypt.py`) that:
  - Takes the password (`Password1!`) and derives the NTLM session key
  - Decrypts WinRM encrypted messages using the session key
  - Outputs decrypted XML/SOAP structures
- Command: `python3 decrypt.py -p 'Password1!' ./traffic-1725627206938.pcap > decrypted_traffic.txt`
- This took several minutes to process the entire PCAP

**Extracting Commands from Decrypted Data:**

1. **Extract base64-encoded arguments:**
   - The decrypted XML contains `<rsp:Arguments>` tags
   - These contain base64-encoded command data
   - Used `grep -oP` with Perl-compatible regex to extract the base64 strings

2. **Decode base64:**
   - Used `base64 --decode` to convert to binary
   - **Problem:** The decoded data is binary XML, not readable text

3. **Extract readable strings:**
   - Used `strings` utility to extract readable text from binary data
   - This reveals the XML structure and command data

4. **Extract commands from XML:**
   - Commands are in `<S N="V">` tags (V = value/command)
   - Used regex: `grep -oP '(?<=<S N="V">)[^<]+'`
   - This extracts the command text between the tags

**Identifying Which Commands Count:**
- Found many commands: `hostname`, `(get-location).path`, `whoami /all`, `reg save HKLM\SYSTEM C:\SYSTEM`, etc.
- The format hint helped: `*** **** ****\****** *:\******`
- This pattern matches: `reg save HKLM\SYSTEM C:\SYSTEM` and `reg save HKLM\SAM C:\SAM`
- `(get-location).path` is just a directory check, not a substantive command
- So: First = `hostname`, Second = `reg save HKLM\SYSTEM C:\SYSTEM`, Third = `reg save HKLM\SAM C:\SAM`

**What to Narrate:**
- "The WinRM traffic is encrypted, so I couldn't just read the commands - everything was scrambled"
- "I tried using tshark with Kerberos decryption first, but that didn't work because WinRM actually uses NTLM for encryption, not Kerberos"
- "So I used this Python script that takes the password, derives the NTLM session key, and decrypts all the WinRM traffic - took a few minutes to process everything"
- "Once decrypted, I got XML output with base64-encoded arguments, so I decoded those, but they were still binary XML, so I used the strings utility to pull out readable text"
- "Then I extracted the commands from the XML structure - they're in these `<S N="V">` tags - and used the format hint to figure out which ones were the second and third substantive commands"

---

## Question 6: The Flag

### The Problem
Find the flag in TryHackMe format: `THM{...}`

### The Approach

**The Challenge:**
- The flag is hidden in the encrypted WinRM traffic
- Required the full decryption pipeline from Question 5
- After decryption and extraction, the flag appears in the command execution history

**The Solution:**
- The flag was embedded in a command: `echo "THM{Ya_G0t_R0aSt3d!}" > note.txt`
- This command creates the `note.txt` file on Larry's Desktop (mentioned in the scenario)
- Used regex pattern matching to extract it:
  ```bash
  grep -oP 'THM\{[^}]+\}' arguments_strings.txt
  ```
  - `THM\{` matches literal "THM{"
  - `[^}]+` matches one or more characters that are not "}"
  - `\}` matches literal "}"
  - This is advanced regex from HW2

**What to Narrate:**
- "The flag was buried in the encrypted WinRM traffic, so I needed to use the whole decryption pipeline from Question 5"
- "After decrypting and getting the readable strings, I just searched for the TryHackMe flag format with regex"
- "The flag was actually in an echo command that created that note.txt file on Larry's Desktop that was mentioned in the scenario"
- "I used grep with Perl-compatible regex to pull out the flag pattern from the huge text file - pretty straightforward once I had the decrypted data"

---

## Overall Narrative Flow for Screencast

### Introduction
- "So this is the Directory challenge from TryHackMe - it's a hard-level digital forensics challenge"
- "I'm analyzing a PCAP file that was captured during an attack on a Windows Active Directory environment"
- "This challenge really brings together a bunch of concepts from the course - network security, authentication, cryptography, and digital forensics"

### Question 1 - Port Scanning
- "I started by looking for the port scan - basically finding SYN-ACK responses to identify open ports"
- "This uses the TCP three-way handshake stuff and BPF filtering we learned in HW4"
- "Then I built a text processing pipeline to pull out and sort all the ports"

### Question 2 - Authentication Analysis
- "Finding the username was tricky because I had to understand how different authentication protocols work"
- "I learned that Kerberos actually has readable usernames, while NTLM encodes everything - that was a key insight"
- "Timing was really important here - larry.doe showed up first and you can see it led to the WinRM connection"

### Question 3 - Hash Extraction
- "This taught me that different protocols store data in totally different places"
- "The hash was in the Kerberos AS-REP cipher field, not in NTLM packets like I thought at first"
- "And I needed the most recent authentication packet, not the first one - that was a gotcha"

### Question 4 - Password Cracking
- "Cracking the password really shows why weak passwords are such a problem"
- "Hashcat is super strict about format, so I had to carefully extract and reformat the hash"
- "The password was found almost instantly in the rockyou wordlist - `Password1!` - which just proves the point about strong passwords"

### Question 5 - Traffic Decryption
- "This was definitely the hardest part - decrypting the WinRM traffic"
- "I learned that WinRM uses NTLM for encryption, not Kerberos, so I needed a special Python script to decrypt it"
- "Once decrypted, I could see all the commands the attacker ran - registry exports and stuff"

### Question 6 - Flag Extraction
- "The flag was hidden in the encrypted traffic, so I needed the full decryption pipeline from Question 5"
- "Then it was just a matter of using regex to find the flag pattern in the decrypted text"

### Conclusion
- "This challenge really ties together network security, authentication, cryptography, and digital forensics"
- "The main lessons: you need to understand protocols, pick the right tools, and be ready to try different approaches when things don't work"
- "It shows the complete workflow from initial reconnaissance all the way through to post-exploitation"

---

## Key Talking Points for Each Question

### Question 1
- TCP three-way handshake and port scanning
- BPF filters and byte-level packet analysis
- Text processing pipelines (grep, awk, cut, sort)

### Question 2
- Authentication protocols (Kerberos vs NTLM)
- Where usernames appear in network traffic
- Timing analysis and correlation

### Question 3
- Hash functions and cryptographic primitives
- Protocol-specific data storage
- String manipulation and extraction

### Question 4
- Password security and dictionary attacks
- Hash format requirements
- Hashcat usage and hash types

### Question 5
- Encryption and decryption
- Session key derivation
- Binary data processing
- Post-exploitation techniques

### Question 6
- Digital forensics and artifact analysis
- Regex pattern matching
- Following the complete attack chain

