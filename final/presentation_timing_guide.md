# 15-Minute Presentation Timing Guide

## Suggested Time Allocation

**Total: 15 minutes**

### Introduction (1 minute)
- Challenge overview and scenario
- Main security concepts covered
- What we'll be analyzing

### Question 1: Open Ports (2 minutes)
- Quick explanation of port scanning
- BPF filter concept (`tcp[13] == 18`)
- Text processing pipeline
- Show the command and result

### Question 2: Username (2.5 minutes)
- Brief mention of failed NTLM approach
- Switch to Kerberos (port 88) - key insight
- Show usernames in readable form
- Timing analysis to identify larry.doe

### Question 3: Hash Extraction (2 minutes)
- Mention wrong approaches (NTLM, WinRM)
- Kerberos AS-REP cipher field
- Getting the last packet (frame 4817)
- String extraction with awk

### Question 4: Password Cracking (2 minutes)
- Hashcat format requirements
- Show the hashcat command
- Quick result - Password1!
- Lesson about weak passwords

### Question 5: Commands (3.5 minutes)
- WinRM encryption challenge
- Failed Kerberos decryption attempt
- Python script from GitHub gist
- Decryption process
- Base64 decoding and strings utility
- Command extraction from XML
- Show the two commands

### Question 6: Flag (1 minute)
- Quick mention of decryption pipeline
- Regex pattern matching
- Show the flag

### Conclusion (1 minute)
- Key lessons learned
- Course concepts integrated
- Overall workflow summary

---

## Condensed Talking Points (15 minutes)

### Introduction (1 min)
"This is the Directory challenge - a hard-level digital forensics challenge analyzing a PCAP file from an attack on a Windows Active Directory environment. It demonstrates network security, authentication, cryptography, and digital forensics concepts."

### Q1: Ports (2 min)
"I identified the port scan by looking for SYN-ACK responses using a BPF filter on the TCP flags byte. Built a text processing pipeline to extract and sort the 14 open ports."

### Q2: Username (2.5 min)
"Initially tried NTLM, but usernames are encoded there. Switched to Kerberos on port 88 where usernames are readable. Found four usernames, but larry.doe appeared first and led to the WinRM connection, so that's the one that achieved foothold."

### Q3: Hash (2 min)
"The hash wasn't in NTLM packets - it's in the Kerberos AS-REP cipher field. Used tshark to extract it, making sure to get the last packet (frame 4817) for the most recent authentication, then extracted the last 30 characters with awk."

### Q4: Password (2 min)
"Formatted the hash for Hashcat mode 18200 and ran it with the rockyou wordlist. Cracked almost instantly - Password1! - showing why weak passwords are vulnerable."

### Q5: Commands (3.5 min)
"WinRM traffic is encrypted. Tried Kerberos decryption but WinRM uses NTLM. Used a Python script from a GitHub gist that derives the NTLM session key. Decrypted to XML, decoded base64, used strings to extract readable text, then pulled commands from XML tags. The second and third commands were registry exports."

### Q6: Flag (1 min)
"Flag was in the decrypted traffic - used regex to find the THM format pattern."

### Conclusion (1 min)
"This challenge integrated multiple course concepts and showed the importance of protocol knowledge, tool selection, and iterative problem-solving."

---

## Tips for 15-Minute Presentation

1. **Focus on key insights, not every detail** - Skip over failed attempts quickly
2. **Show commands and results** - Visual demonstration is faster than explanation
3. **Emphasize the "aha" moments:**
   - Switching from NTLM to Kerberos (Q2)
   - Hash in Kerberos AS-REP, not NTLM (Q3)
   - WinRM uses NTLM, not Kerberos (Q5)
4. **Use the images** - They save explanation time
5. **Practice the flow** - Know which commands to show vs. just mention
6. **Keep it conversational** - The informal tone helps maintain pace

---

## What to Skip or Minimize

- Detailed explanation of every failed attempt
- Complex awk command breakdowns (just show they work)
- All the challenges encountered (maybe mention 1-2 key ones)
- Deep protocol explanations (just the key differences)

## What to Emphasize

- The protocol insights (Kerberos vs NTLM)
- The tool selection decisions
- The iterative problem-solving process
- How course concepts were applied

