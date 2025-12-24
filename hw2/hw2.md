I took these steps to complete this homework:

1. Downloaded the following ebooks:
   - The Linux Command Line
   - Adventures with the Linux Command Line
   - The Linux Development Platform

2. Completed the Linux Fundamentals Part 1 room and Linux Modules Room on TryHackMe

![Linux Fundamentals Part 1 Completion](images/linuxfundamentalscompleted(emmanart).png)
![Linux  Modules Completion](images/linux_modules_completed(emmanart).png)

3. Completed the Regular Expressions room on TryHackMe

![Regular Expressions Completion](images/placeholder.png)

4. Used grep to find the following patterns in the `/usr/share/wordlists/rockyou.txt` file:

   - All lines that contain the word "password" (case-sensitive):
     ```bash
     grep "password" /usr/share/wordlists/rockyou.txt
     ```
   The number of lines that contain "password" is 3959
   - All lines that contain "password" (case-insensitive):
     ```bash
     grep -i "password" /usr/share/wordlists/rockyou.txt
     ```
   The number of lines that match this criteria is 4690
   
   - All lines that end with exactly 3 numerical digits:
     - With an anchor:
       ```bash
       grep -E '[0-9]{3}$' /usr/share/wordlists/rockyou.txt
       ```
       The number of lines that match this criteria is 5076143
     
     - Without an anchor:
       ```bash
       grep -E '[0-9]{3}' /usr/share/wordlists/rockyou.txt
       ```
       The number of lines that match this criteria is 5774765
   
   - All lines that contain exactly 3 numerical digits, in any position (do not have to be adjacent, just 3 total):
     ```bash
     grep -E '^[^0-9]*[0-9][^0-9]*[0-9][^0-9]*[0-9][^0-9]*$' /usr/share/wordlists/rockyou.txt
     ```
     The number of lines that match this criteria is 1009564

5. Here is sed command to do the following:

   - Replace all instances of `from this.that import something` to `from that import something` in all python files in the current directory tree:
   ```bash
   find . -name "*.py" -type f -exec sed -i 's/from this\.that import/from that import/g' {} \;
   ```

   - Print lines 312-345 of a file (inclusive):
   ```bash
   sed -n '312,345p' /usr/share/wordlists/rockyou.txt
   ```

   - Replace `#PasswordAuthentication yes` with `PasswordAuthentication no` in `/etc/ssh/sshd_config`:
   ```bash
   sudo sed -i 's/^#PasswordAuthentication yes$/PasswordAuthentication no/g' /etc/ssh/sshd_config
   ```

6. Below are the results of my runs objdump, nm, and readelf on `/bin/ls` and my answers to the questions below:
   Running these commands without any flags just produces help notes for each command. Using the flags produces actual results which I put in .txt files. I chose to run the following commands:
   - `objdump -h /bin/ls` (output in objdump_out.txt)
   - `nm -D /bin/ls` (output in nm_out.txt)
   - `readelf -h /bin/ls` (output in readelf_out.txt)
   
   - What do each of these tools do?
     - **objdump**: Display information from object files
     - **nm**: List symbols from object files
     - **readelf**: Display information about ELF files
      
   - What information do they provide?
     - **objdump -h**: Section headers including names, sizes, addresses, and offsets
     - **nm -D**: Dynamic symbols with names, addresses, and types (imported/exported functions)
     - **readelf -h**: ELF header with file metadata, architecture, and entry point
      
   - How do they differ from each other?
     - **objdump**: General-purpose tool that works on multiple object file formats, can disassemble code and show various sections
     - **nm**: Specialized for quickly listing symbols only, useful for finding what functions/variables are in a binary
     - **readelf**: ELF-specific tool that provides the most detailed information about ELF file structure and cannot be used on non-ELF formats
      
   - Give examples of each tool's output?
     - See objdump_out.txt, nm_out.txt, and readelf_out.txt for the full output examples from each tool
      
7. Virtual environment activation:

   **Command to activate the virtual environment in the current directory:**
   ```bash
   source $(find . -type f -path "*/bin/activate" | head -1)
   ```
   
   When I initially ran this command without `| head -1`, I got an error. I found on Google that you would have to use `head -1` to get the first line of output of the `/bin/activate` search, in case multiple virtual environments exist in the directory tree.

   **Zsh function to activate virtual environment from anywhere:**
   ```zsh
   activate_venv() {
       source $(find . -type f -path "*/bin/activate" | head -1)
   }
   ```
   
   This function can be added to `~/.zshrc` and then sourced with `source ~/.zshrc`. After that, you can use `activate_venv` from any directory to activate a virtual environment found in the current directory tree.

8. Pipeline Analysis:

   The following pipeline is used to find users causing excessive load on a server:
   ```bash
   ps -efH --no-header | awk '{print $1}' | grep -Ev $(python3 -c 'import sys; print("|".join(sys.argv[1:]))' $(cut -f1 -d':' /etc/passwd)) | sort | uniq -c | sort -n
   ```
   Here are the answers to the following questions: 
   - What do you think the grep portion does? Why is that useful?
     
     The grep portion filters out all usernames that exist in `/etc/passwd`. The Python script extracts all valid system usernames using `cut`, joins them with `|` to create a regex pattern like `user1|user2|user3`, and `grep -Ev` excludes lines matching this pattern. This is useful because it identifies processes running under usernames that don't exist in the system's user database, which could indicate orphaned processes, unauthorized users, or security issues.
     
     When I ran this pipeline on my system, I got output showing `1 message+` and `24 emmarth+`. However, when I checked `/etc/passwd`, I found these correspond to `messagebus` and `emmarthur` - legitimate users whose names were truncated by `ps`. This reveals a limitation of the pipeline: it doesn't account for username truncation, which can produce false positives.
   - What is an alias?
     
     An alias is a shell shortcut that creates a custom command name for a longer or more complex command. Aliases are defined using the `alias` command (e.g., `alias ll='ls -la'`) and are typically stored in shell configuration files like `~/.bashrc` or `~/.zshrc`. They help reduce typing and make complex commands more memorable.
   - Can you replace the awk pipeline component with a cut? What about the reverse?
     
     **Replacing awk with cut:** Yes, but not directly. `awk '{print $1}'` prints the first field, but `awk` handles multiple spaces as a single delimiter while `cut` treats each space separately. To replicate awk's behavior, you'd need: `tr -s ' ' | cut -d' ' -f1` (where `tr -s` squeezes multiple spaces into one).
     
     When I tested the simple replacement with `cut -d' ' -f1`, I got different results: `20 emmarth+` instead of `24 emmarth+`. This demonstrates that `cut` doesn't handle variable whitespace correctly, causing it to extract the wrong field in some cases.
     
     **Replacing cut with awk:** Yes, easily. The `cut -f1 -d':'` command can be replaced with `awk -F':' '{print $1}'`. This works well because both handle delimiters properly, and `awk` is actually more flexible.
     
     When I tested this replacement, I got the same output (`24 emmarth+`), confirming that `awk` successfully replaces `cut` when dealing with consistent single-character delimiters like the colons in `/etc/passwd`.
   - Take a look at a tool called paste. How might you use it to replace the use of python in this pipeline?
     
     The Python portion joins usernames with `|` to create a regex pattern. You can use `paste -sd'|'` to do the same thing. The `-s` (serial) option merges all lines into one, and `-d'|'` sets the delimiter to `|`. 
     
     Replace: `$(python3 -c 'import sys; print("|".join(sys.argv[1:]))' $(cut -f1 -d':' /etc/passwd))`
     
     With: `"$(paste -sd'|' <(cut -f1 -d':' /etc/passwd))"`
     
     This is cleaner and doesn't require invoking Python.
     
     When I tested this replacement, I initially got `22 emmarth+` instead of `24 emmarth+`. However, when I compared the actual patterns generated by both methods, they were identical. The difference in count was probably due to system state changes - processes had stopped between my test runs, not because `paste` behaves differently from Python. This demonstrates that `paste` successfully replaces Python for this use case.

