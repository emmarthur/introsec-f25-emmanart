Kali Linux setup and GUI verification

I used the integrated PowerShell terminal inside VS Code to install and set up Kali Linux under WSL, then launched Kali as a separate integrated terminal in VS Code. From within the Kali terminal, I installed the Win‑KeX components and successfully launched the Kali GUI.

Steps performed:

1) From VS Code PowerShell (Windows side):

```powershell
wsl --install -d Kali-Linux
```

2) Opened a new integrated terminal in VS Code using the Kali Linux distro (WSL). Inside the Kali shell:

```bash
sudo apt update
sudo apt install -y kali-win-kex
kex --win -s
```

3) ## Kali Configuration and Setup

Following the configuration steps outlined in [Kali Configuration Guide](https://web.cecs.pdx.edu/~dmcgrath/courses/netsec/linux_setup.html), I successfully completed the system configuration and tool installation:

### System Configuration

1) **Repository Configuration**: Used `kali-tweaks` to configure repositories:
```bash
sudo kali-tweaks
```
- Selected "Network Repositories"
- Chose the "Cloudflare" mirror with "HTTPS" protocol
- Applied changes to update `/etc/apt/sources.list`

2) **System Updates**: Updated the system to latest packages:
```bash
sudo apt update
sudo apt upgrade -y
```

### Tool Installation

3) **Setup Script Installation**: Downloaded and executed the provided setup script:
```bash
curl -LO https://web.cecs.pdx.edu/~dmcgrath/courses/netsec/setup.sh
chmod +x setup.sh
./setup.sh
```

The setup script successfully installed a comprehensive set of useful tools and utilities. After completion, I rebooted the VM to ensure proper configuration and logged back in to verify the installation.

![Setup Script Completion](images/setup_sh%20working.png)

4) **OpenVPN Setup**: Completed the OpenVPN room on TryHackMe to establish VPN connectivity for future homework assignments and labs. This ensures secure access to lab environments and resources.

![OpenVPN TryHackMe Completion](images/openvpntryhackme%20completed.png)

5) **Security Principles**: Completed the Security Principles room on TryHackMe to reinforce fundamental cybersecurity concepts and best practices essential for network security coursework.

![Security Principles Completion](images/Security%20priniciples%20completed.png)





