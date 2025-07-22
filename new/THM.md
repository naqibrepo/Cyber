# THM
```
# Soc 1

------------------------------------------------------------------
# Pyramid Of Pain
Finding and analyzing the IoCs to make the attack more challenging for threat actor.

1. Hasding		# malware have hashes
2. IP
3. Domain Name
4. Host Artifact	# hosts events and abnormal activities
5. Network Traffic
6. Tools		
7. TTP			# MITRE ATT&K


2. Fast Flux		# having multiple IP addresses associated with a domain name, which is constantly changing and acting as proxies
3. Punycode		# a way of converting words that cannot be written in ASCII, into a Unicode ASCII encoding (used in url typo attacks),
			# the URL adıdas.de which has the Punycode of http://xn--addas-o4a.de/
3. URL Shortener	# creates a short and unique URL. bit.ly, goo.gl, ow.ly, s.id, smarturl.it, tiny.pl, tinyurl.com, x.co
5. Any.run		# a website that has the attacks and their info practically
6. fuzzy hashing	# similarity analysis (match two files with minor differences based on the fuzzy hash values), SSDeep


------------------------------------------------------------------
# Cyber Kill Chain

1. Recon
OSINT
Email harvesting	# obtaining email addresses from public, paid, or free services
theHarvester		# gathering emails, also capable of gathering names, subdomains, IPs, and URLs using multiple public data sources 
Hunter.io		# this is  an email hunting tool that will let you obtain contact information associated with the domain
OSINT Framework		# OSINT Framework provides the collection of OSINT tools based on various categories

2. Weaponization	# combines malware and exploit into a deliverable payload
3. Delivery
4. Exploitation
5. Installation
	Installing a web shell
	Installing bakedoor
	Creating or modifying Windows services, sc.exe (sc.exe lets you Create, Start, Stop, Query, or Delete any Windows Service) and Reg 
	Adding the entry to the "run keys" for the malicious payload in the Registry or the Startup Folder
	Timestomping technique to avoid detection by the forensic investigator

6. Command and control
	The protocols HTTP on port 80 and HTTPS on port 443
	DNS (DNS Tunneling)

------------------------------------------------------------------
# Unified Kill Chain

Threat modelling	# Threat modelling is about identifying risk and reducing the them within a system
			# STRIDE, DREAD and CVSS are all frameworks specifically used in threat modelling

1. In
	Reconnaissance (MITRE Tactic TA0043)
	Weaponization (MITRE Tactic TA0001)
	Social Engineering (MITRE Tactic TA0001)
	Exploitation (MITRE Tactic TA0002)
	Persistence (MITRE Tactic TA0003)
	Defence Evasion (MITRE Tactic TA0005)
	Command & Control (MITRE Tactic TA0011)
	Pivoting (MITRE Tactic TA0008)

2. Through
	Pivoting (MITRE Tactic TA0008)
	Discovery (MITRE Tactic TA0007)		# information about the system and the network
	Privilege Escalation (MITRE Tactic TA0004)
	Execution (MITRE Tactic TA0002)
	Credential Access (MITRE Tactic TA0006)
	Lateral Movement (MITRE Tactic TA0008)

3. Out
	Collection MITRE Tactic (TA0009)
	Exfiltration (MITRE Tactic TA0010)
	Impact (MITRE Tactic TA0040)		# compromise the integrity and availability 
	Objectives

------------------------------------------------------------------
# Diamond Model of Intrusion Analysis

1. adversary		# an actor or organization responsible for utilizing a capability against the victim
	Adversary Operator is the “hacker” or person
	Adversary Customer is the entity that stands to benefit from the attack. May be a separate person or group

2. victim		# is a target of the adversary
	Victim Personae are the people and organizations being targeted
	Victim Assets like systems, networks, email addresses, hosts, IP addresses, social networking accounts

3. Capability		# skill, tools, and techniques used by the adversary
	Capability Capacity is all of the vulnerabilities that the individual capability can use
	Adversary Arsenal is a set of capabilities that belong to an adversary

4. Infrastructure	#  physical or logical interconnections that the adversary uses to deliver a capability
			# or maintain control of capabilities
	Type 1 Infrastructure is controlled or owned by the adversary
	Type 2 Infrastructure is the infrastructure controlled by an intermediary
	Service Providers

Event Meta Features: Timestamp, Phase, Result, Direction, Methodology, and Resources


------------------------------------------------------------------
# MITRE

ATT&CK® (Adversarial Tactics, Techniques, and Common Knowledge) Framework
CAR (Cyber Analytics Repository) Knowledge Base
ENGAGE (sorry, not a fancy acronym)
D3FEND (Detection, Denial, and Disruption Framework Empowering Network Defense)
AEP (ATT&CK Emulation Plans)

APT is an acronym for Advanced Persistent Threat
https://www.mandiant.com/resources/insights/apt-groups

TTP:
The Tactic is the adversary's goal or objective.
The Technique is how the adversary achieves the goal or objective.
The Procedure is how the technique is executed.


ATT&CK® framework:



===============================================================================
# Phishing
```
POP3
Emails are downloaded and stored on a single device.
Sent messages are stored on the single device from which the email was sent.
Emails can only be accessed from the single device the emails were downloaded to.
If you want to keep messages on the server, make sure the setting "Keep email on server" is enabled, or all messages are deleted from the server once downloaded to the single device's app or software.

IMAP
Emails are stored on the server and can be downloaded to multiple devices.
Sent messages are stored on the server.
Messages can be synced and accessed across multiple devices.

SMTP | Port 25
SMTP | Port 465 (Secure Transport — SSL function enabled)
SMTP | Port 587 (Insecure Transport, but can be upgraded to a secure connection using STARTTLS)

IMAP | Port 993 (Secure Transport   — SSL function enabled)
POP3 | Port 995 (Secure Transport   — SSL function enabled)
IMAP | Port 143 (Insecure Transport — No SSL function enabled)
POP3 | Port 110 (Insecure Transport — No SSL function enabled)


The syntax for email messages is known as the Internet Message Format (IMF).

X-Originating-IP - The IP address of the email was sent from (this is known as an X-header)
Smtp.mailfrom/header.from - The domain the email was sent from (these headers are within Authentication-Results)
Reply-To - This is the email address a reply email will be sent to instead of the From email address

https://www.arin.net/

Content-Type is application/pdf. 
Content-Disposition specifies it's an attachment. 
Content-Transfer-Encoding tells us it's base64 encoded. 

A BEC (Business Email Compromise) is when an adversary gains control of an internal employee's account and then uses the compromised email account to convince other internal employees to perform unauthorized or fraudulent actions. 

Defanging is a way of making the URL/domain or email address unclickable to avoid accidental clicks, which may result in a serious security breach. It replaces special characters, like "@" in the email or "." in the URL, with different characters. For example, a highly suspicious domain, http://www.suspiciousdomain.com, will be changed to hxxp[://]www[.]suspiciousdomain[.]com before forwarding it to the SOC team for detection.

------------------------------------------------------------------
different tactics used to make the phishing emails look legitimate

Cancel your PayPal order:
Spoofed email address
URL shortening services
HTML to impersonate a legitimate brand

Pixel tracking		# embedded in the email and hidden in image and send out info like location to spammer

------------------------------------------------------------------

Below is a checklist of the pertinent information an analyst (you) is to collect from the email header:
Sender email address
Sender IP address
Reverse lookup of the sender IP address
Email subject line
Recipient email address (this information might be in the CC/BCC field)
Reply-to email address (if any)
Date/time
Afterward, we draw our attention to the email body and attachment(s) (if any).

Below is a checklist of the artifacts an analyst (you) needs to collect from the email body:
Any URL links (if an URL shortener service was used, then we'll need to obtain the real URL link)
The name of the attachment
The hash value of the attachment (hash type MD5 or SHA256, preferably the latter)

------------------------------------------------------------------
Tools:
PhishTool						# automated phishing analysis

Messageheader from the Google Admin Toolbox. 
Message Header Analyzer
mailheader.org

https://ipinfo.io/					# Analyze the sender IP
https://urlscan.io/					# Scan and analyze websites
URL2PNG and Wannabrowser				# Scan and analyze websites
https://talosintelligence.com/reputation		# Reputation

URL Extractor 						# obtain URL and link from the email, https://www.convertcsv.com/url-extractor.htm
You may also use CyberChef to extract URLs with the Extract URLs recipe.

Malware Sandbox:
https://www.joesecurity.org/
Hybrid Analysis: https://www.hybrid-analysis.com/
Any.Run: https://app.any.run/


------------------------------------------------------------------
defend against phishing:

Email Security (SPF, DKIM, DMARC)
SPAM Filters (flags or blocks incoming emails based on reputation)
Email Labels (alert users that an incoming email is from an outside source)
Email Address/Domain/URL Blocking (based on reputation or explicit denylist)
Attachment Blocking (based on the extension of the attachment)
Attachment Sandboxing (detonating email attachments in a sandbox environment to detect malicious activity)
Security Awareness Training (internal phishing campaigns)

https://dmarcian.com/domain-checker/		# Check the SPF, DKIM, and DMARC status of a domain

---
Sender Policy Framework (SPF): 
- Authenticate the sender of an email.
- An SPF record is a DNS TXT record containing a list of the IP addresses that are allowed to send email on behalf of your domain

An explanation for the above record:
v=spf1 ip4:127.0.0.1 include:_spf.google.com -all

v=spf1 -> This is the start of the SPF record
ip4:127.0.0.1 -> This specifies which IP (in this case version IP4 & not IP6) can send mail
include:_spf.google.com -> This specifies which domain can send mail. In this case, "Trust Google's list of authorized mail servers for my domain."
-all -> non-authorized emails will be rejected

-all		# no pass and discard
~all		# no pass


---
DKIM (DomainKeys Identified Mail): 
- authentication of an email that’s being sent.

---
DMARC, (Domain-based  Message Authentication Reporting, & Conformance): 
- uses a concept called alignment to tie the result of SPF and DKIM  to an email 
- give you feedback that will allow you to troubleshoot your SPF and DKIM configurations if needed.

v=DMARC1; p=quarantine; rua=mailto:postmaster@website.com 

An explanation of the above record:

v=DMARC1 -> Must be in all caps, and it's not optional
p=quarantine -> If a check fails, then an email will be sent to the spam folder (DMARC Policy)
rua=mailto:postmaster@website.com -> Aggregate reports will be sent to this email address

---
S/MIME (Secure/Multipurpose internet Mail Extensions) 
- protocol for sending digitally signed and encrypted messages

---
links to Wireshark smtp filters:
https://www.wireshark.org/docs/dfref/s/smtp.html
https://www.wireshark.org/docs/dfref/i/imf.html
https://www.mailersend.com/blog/smtp-codes

```
===============================================================================
# Threat Intelligence Tools
```
Who's attacking you?
What's their motivation?
What are their capabilities?
What artefacts and indicators of compromise should you look out for?

Urlscan.io			# scanning and analysing websites

https://abuse.ch/
Malware Bazaar:  A resource for sharing malware samples.
Feodo Tracker:  A resource used to track botnet command and control (C2) infrastructure linked with Emotet, Dridex and TrickBot.
SSL Blacklist:  A resource for collecting and providing a blocklist for malicious SSL certificates and JA3/JA3s fingerprints.
URL Haus:  A resource for sharing malware distribution sites.
Threat Fox:  A resource for sharing indicators of compromise (IOCs).

phishtool

Cisco Talos Intelligence:

```
===============================================================================
# Yara 
```
Yara can identify information based on both binary and textual patterns, such as hexadecimal and strings contained within a file.

Every yara command requires two arguments to be valid, these are:
1) The rule file we create
2) Name of file, directory, or process ID to use the rule for.

yara myrule.yar somedirectory

Every rule must have a name and condition.

myrule.yar:
rule examplerule {
        condition: true
}

Simply, the rule we have made checks to see if the file/directory/PID that we specify exists via condition: true. If the file does exist, we are given the output of examplerule
Keyword:
Desc			# Similar to commenting code
Weight
Meta
Strings
any file or the entire directory with the below strings will trigger the rule:
1. Hello World!
2. hello world
3. HELLO WORLD
rule helloworld_checker{
	strings:
		$hello_world = "Hello World!"
		$hello_world_lowercase = "hello world"
		$hello_world_uppercase = "HELLO WORLD"

	condition:
		any of them
}


---
Conditions:
true
any of them
<= less than or equal to
>= more than or equal to
!= not equal to
and, or, not

rule matches if there are less than or equal to ten occurrences of the "Hello World!" string:
rule helloworld_checker{
	strings:
		$hello_world = "Hello World!"

	condition:
        #hello_world <= 10
}

and, or, not:
rule helloworld_checker{
	strings:
		$hello_world = "Hello World!" 
        
        condition:
	        $hello_world and filesize < 10KB 
}



- Cuckoo Sandbox is an automated malware analysis environment. This module allows you to generate Yara rules based upon the behaviours discovered from Cuckoo Sandbox.
- Python's PE module allows you to create Yara rules from the various sections and elements of the Windows Portable Executable (PE) structure. This structure is the standard formatting of all executables and DLL files on windows.


# Yara Automation tools:
- LOKI is a free open-source IOC (Indicator of Compromise) scanner. Detection is based on 4 methods:
File Name IOC Check
Yara Rule Check
Hash Check
C2 Back Connect Check
- THOR Lite is Florian's newest multi-platform IOC AND YARA scanner.
- Fenrir is a bash script; it will run on any system capable of running bash
- YAYA will only run on Linux systems. 

used for threat int. and matching yara rules on pasted IOC
https://valhalla.nextron-systems.com/

-------------------------------------
# Using LOKI and its Yara rule set


```
===============================================================================
# Intro to endpoint security

```
The Sysinternals tools are a compilation of over 70+ Windows-based tools. Each of the tools falls into one of the following categories:

File and Disk Utilities
Networking Utilities
Process Utilities
Security Utilities
System Information
Miscellaneous

TCPView - Networking Utility tool: show you detailed listings of all TCP and UDP endpoints on your system, includes Tcpvcon, a command-line version with the 	same functionality
Process Explorer - Process Utility tool: currently active processes, and info


event viewer:
the event viewer raw data can be translated into XML using the Windows API. The events in these log files are stored in a proprietary binary format with a .evt or .evtx extension. The log files with the .evtx file extension typically reside in C:\Windows\System32\winevt\Logs

There are three main ways of accessing these event logs within a Windows system:
Event Viewer (GUI-based application)
Wevtutil.exe (command-line tool)
Get-WinEvent (PowerShell cmdlet)

Sysmon
Sysmon, a tool used to monitor and log events on Windows
gathers detailed and high-quality logs as well as event tracing that assists in identifying anomalies in your environment
commonly used with a security information and event management (SIEM) 

OSQuery
Osquery is an open-source tool created by Facebook.
security specialist can query an endpoint (or multiple endpoints) using SQL syntax

in powershell:
osqueryi
select pid,name,path from processes where name='lsass.exe';

Osquery only allows you to query events inside the machine. But with Kolide Fleet, you can query multiple endpoints from the Kolide Fleet UI instead of using Osquery locally to query an endpoint. 


Having a baseline document aids you in differentiating malicious events from benign ones.
Event correlation provides a deeper understanding of the concurrent events triggered by the malicious activity.
Taking note of each significant artefact is crucial in the investigation.
Other potentially affected assets should be inspected and remediated using the collected malicious artefacts.

```
===============================================================================
# Core Windows process
```
Tools:
Process Hacker
Process Explorer


Task manager:
Type - Each process falls into 1 of 3 categories (Apps, Background process, or Windows process).
command line tools: tasklist, Get-Process or ps (PowerShell), and wmic


System:
The PID for System is always 4
What is unusual behaviour for this process?
A parent process (aside from System Idle Process (0))
Multiple instances of System. (Should only be one instance) 
A different PID. (Remember that the PID will always be PID 4)
Not running in Session 0

System > smss.exe:
smss.exe (Session Manager Subsystem)
responsible for creating new sessions, it is the first user-mode process started by the kernel.
This process starts the kernel and user modes of the Windows subsystem 
This subsystem includes win32k.sys (kernel mode), winsrv.dll (user mode), and csrss.exe (user mode)

Smss.exe starts csrss.exe (Windows subsystem) and wininit.exe in Session 0, an isolated Windows session for the operating system, and csrss.exe and winlogon.exe for Session 1, which is the user session. The first child instance creates child instances in new sessions, done by smss.exe copying itself into the new session and self-terminating.

Any other subsystem listed in the Required value of HKLM\System\CurrentControlSet\Control\Session Manager\Subsystems is also launched.

SMSS is also responsible for creating environment variables, virtual memory paging files and starts winlogon.exe (the Windows Logon Manager)

What is unusual?
A different parent process other than System (4)
The image path is different from C:\Windows\System32
More than one running process. (children self-terminate and exit after each new session)
The running User is not the SYSTEM user
Unexpected registry entries for Subsystem


csrss.exe:
csrss.exe (Client Server Runtime Process) is the user-mode side of the Windows subsystem
This process is responsible for the Win32 console window and process thread creation and deletion. For each instance, csrsrv.dll, basesrv.dll, and winsrv.dll are loaded (along with others). 
If this process is terminated by chance, it will result in system failure. 

these processes are spawned by smss.exe, which self-terminates itself

What is unusual?
An actual parent process. (smss.exe calls this process and self-terminates)
Image file path other than C:\Windows\System32
Subtle misspellings to hide rogue processes masquerading as csrss.exe in plain sight
The user is not the SYSTEM user.

wininit.exe:
The Windows Initialization Process, wininit.exe, is responsible for launching services.exe (Service Control Manager), lsass.exe (Local Security Authority), and lsaiso.exe within Session 0.
lsaiso.exe is a process associated with Credential Guard and KeyGuard. You will only see this process if Credential Guard is enabled. 

What is unusual?
An actual parent process. (smss.exe calls this process and self-terminates)
Image file path other than C:\Windows\System32
Subtle misspellings to hide rogue processes in plain sight
Multiple running instances
Not running as SYSTEM

wininit.exe > services.exe:
The next process is the Service Control Manager (SCM) or services.exe.
Its primary responsibility is to handle system services: loading services, interacting with services and starting or ending services.
It maintains a database that can be queried using a Windows built-in utility, sc.exe
registry: HKLM\System\CurrentControlSet\Services.

This process also loads device drivers marked as auto-start into memory. 
responsible for setting the value of the, HKLM\System\Select\LastKnownGood

is the parent to several other key processes: svchost.exe, spoolsv.exe, msmpeng.exe, and dllhost.exe, to name a few. 

What is unusual?
A parent process other than wininit.exe
Image file path other than C:\Windows\System32
Subtle misspellings to hide rogue processes in plain sight
Multiple running instances
Not running as SYSTEM

wininit.exe > services.exe > svchost.exe:
The Service Host (Host Process for Windows Services), or svchost.exe, is responsible for hosting and managing Windows services. 
The services running in this process are implemented as DLLs
The DLL to implement is stored in the registry for the service under the Parameters subkey in ServiceDLL. The full path is HKLM\SYSTEM\CurrentControlSet\Services\SERVICE NAME\Parameters.
Since svchost.exe will always have multiple running processes on any Windows system, this process has been a target for malicious use.

What is unusual?
A parent process other than services.exe
Image file path other than C:\Windows\System32
Subtle misspellings to hide rogue processes in plain sight
The absence of the -k parameter

LSASS:
Local Security Authority Subsystem Service (LSASS) is a process in Microsoft Windows operating systems that is responsible for enforcing the security policy on the system.
It creates security tokens for SAM (Security Account Manager), AD (Active Directory), and NETLOGON. It uses authentication packages specified in HKLM\System\CurrentControlSet\Control\Lsa

What is unusual?
A parent process other than wininit.exe
Image file path other than C:\Windows\System32
Subtle misspellings to hide rogue processes in plain sight
Multiple running instances
Not running as SYSTEM

winlogon.exe:
The Windows Logon, winlogon.exe, is responsible for handling the Secure Attention Sequence (SAS). It is the ALT+CTRL+DELETE key combination users press to enter their username & password. 

loading the user profile

What is unusual?
An actual parent process. (smss.exe calls this process and self-terminates)
Image file path other than C:\Windows\System32
Subtle misspellings to hide rogue processes in plain sight
Not running as SYSTEM
Shell value in the registry other than explorer.exe

explorer.exe:
Winlogon process runs userinit.exe, which launches the value in HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell. Userinit.exe exits after spawning explorer.exe. Because of this, the parent process is non-existent. 

Parent Process:  Created by userinit.exe and exits

What is unusual?
An actual parent process. (userinit.exe calls this process and exits)
Image file path other than C:\Windows
Running as an unknown user
Subtle misspellings to hide rogue processes in plain sight
Outbound TCP/IP connections


```
===============================================================================
# Sysinternals
```
File and Disk Utilities
Networking Utilities
Process Utilities
Security Utilities
System Information
Miscellaneous

https://docs.microsoft.com/en-us/sysinternals/downloads/
https://live.sysinternals.com/					# run from web

from system properties (sysdm.cpl) change the path (environmental variable, System Variables)
Download-SysInternalsTools C:\Tools\Sysint

"Sysinternals Live is a service that enables you to execute Sysinternals tools directly from the Web without hunting for and manually downloading them. Simply enter a tool's Sysinternals Live path into Windows Explorer or a command prompt as live.sysinternals.com/<toolname> or \\live.sysinternals.com\tools\<toolname>."
- WebDAV client must be installed to access a remote machine running a WebDAV share and perform actions in it
get-service webclient						# status in linux
start-service webclient						# start weblient (WebDAV)
Also, Network Discovery needs to be enabled as well. This setting can be enabled in the Network and Sharing Center.

Install-WindowsFeature WebDAV-Redirector –Restart		# install windows feature
Get-WindowsFeature WebDAV-Redirector | Format-Table –Autosize	# verify it has been installed

------------------------------------------------------------------
File and Disk Utilities:
Sigcheck: 
shows file version number, timestamp information, digital signature details, certificate chains, and check a file’s status on VirusTotal

Use Case: Check for unsigned files in C:\Windows\System32.
Command: sigcheck -u -e C:\Windows\System32
-u "If VirusTotal check is enabled, show files that are unknown by VirusTotal or have non-zero detection, otherwise show only unsigned files."
-e "Scan executable images only (regardless of their extension)"

Streams:
By default, all data is stored in a file's main unnamed data stream, but by using the syntax 'file:stream', you are able to read and write to alternates. (NTFS)
Every file has at least one data stream ($DATA) and ADS allows files to contain more than one stream of data
there are identifiers written to ADS to identify that it was downloaded from the Internet.

streams C:\Users\Administrator\Desktop\SysinternalsSuite.zip -Accepteula
get-item C:\Users\Administrator\Desktop\file.txt | get-content -stream ads.txt		# read the ads.txt file which is hidden in the ADS ($DATA)

SDelete:
A deleting/sanitizing utility

------------------------------------------------------------------
Networking Utilities:

TCPView:
show you detailed listings of all TCP and UDP endpoints on your system
Tcpvcon, a command-line version with the same functionality
Resource Monitor: same functionality

------------------------------------------------------------------
Process Utilities

Autoruns:
shows you what programs are configured to run during system bootup or login, and when you start various built-in Windows applications
These programs and drivers include ones in your startup folder, Run, RunOnce, and other Registry keys
This is a good tool to search for any malicious entries created in the local machine to establish Persistence.

ProcDump:
command-line utility, monitoring an application for CPU spikes and generating crash dumps during a spike

Process Explorer (procexp):
has two sub-windows,
top: list of the currently active processes, their owning accounts
bottom: handle mode, DLL mode (dll and memory-mapped files)
has Verify Signatures or signer option in columns
is color coded

Process Monitor:
shows real-time file system, Registry and process/thread activity
The option to capture events can be toggled on and off. 

PsExec:
a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software.
launching interactive command-prompts on remote systems and remote-enabling tools like Ipconfig.

------------------------------------------------------------------
Security Utilities

Sysmon:
System Monitor (Sysmon) is a Windows system service and device driver
log system activity to the Windows event log
information about process creations, network connections, and changes to file creation time

------------------------------------------------------------------
System Information

WinObj:
uses the native Windows NT API (provided by NTDLL.DLL) to access and display information on the NT Object Manager's name space.

------------------------------------------------------------------
Miscellaneous

BgInfo:
automatically displays relevant information about a Windows computer on the desktop's background

RegJump:
This little command-line applet takes a registry path and makes Regedit open to that path. It accepts root keys in standard (e.g. HKEY_LOCAL_MACHINE) and abbreviated form (e.g. HKLM)
other ways to query the Windows Registry: (reg query) and PowerShell (Get-Item/Get-ItemProperty)

strings:
Strings just scans the file you pass it for UNICODE (or ASCII) strings 
strings .\ZoomIt.exe | findstr /i pdb			# scan for pdb text in the zoomit.exe strings


```
===============================================================================
# Windows Event Logs
```

C:\Windows\System32\winevt\Logs
https://learn.microsoft.com/en-us/windows/win32/eventlog/event-types

Event Viewer (GUI-based application)
Wevtutil.exe (command-line tool)
Get-WinEvent (PowerShell cmdlet)

------------------------------------------------------------------
Wevtutil.exe (command-line tool)

el | enum-logs          List log names.
gl | get-log            Get log configuration information.
sl | set-log            Modify configuration of a log.
ep | enum-publishers    List event publishers.
gp | get-publisher      Get publisher configuration information.
im | install-manifest   Install event publishers and logs from manifest.
um | uninstall-manifest Uninstall event publishers and logs from manifest.
qe | query-events       Query events from a log or log file.
gli | get-log-info      Get log status information.
epl | export-log        Export a log.
al | archive-log        Archive an exported log.
cl | clear-log          Clear a log.

wevtutil qe Application /c:3 /rd:true /f:text
/c:3		# maximum number of event to read
/rd:true	# read direction, (most recent event first)
/f:text		# format = text


------------------------------------------------------------------
Get-WinEvent
gets events from event logs and event tracing log files on local and remote computers.
you can combine numerous events from multiple sources into a single command and filter using XPath queries, structured XML queries, and hash table queries.

Get all logs from a computer: Get-WinEvent -ListLog *
Get event log providers and log names: Get-WinEvent -ListProvider *

Log filtering:
Get-winEvent -LogName Application | Where-Object { $_.ProviderName -Match 'WLMS' }		# not recommended
instead:
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='MsiInstaller'; ID=11707 }
-MaxEvents 3			# return maximum of 3 logs

example:
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Select-Object -Property Message | Select-String -Pattern 'SecureString'


------------------------------------------------------------------
XPath
provide a standard syntax and semantics for addressing parts of an XML document and manipulating strings, numbers, and booleans

// The following query selects all events from the channel or log file where the severity level is less than or equal to 3 and the event occurred in the last 24 hour period. 
XPath Query: *[System[(Level <= 3) and TimeCreated[timediff(@SystemTime) <= 86400000]]]

starts with '*' or 'Event'
Filter by Event ID: */System/EventID=<ID>
Filter by XML Attribute/Name: */EventData/Data[@Name="<XML Attribute/Name>"]
Filter by Event Data: */EventData/Data=<Data>

Event/* system/EventData

Get-WinEvent -LogName Application -FilterXPath '*'
Get-WinEvent -LogName Application -FilterXPath '*/System'

Note: Its best practice to explicitly use the keyword System but you can use an * instead as with the Event keyword. The query -FilterXPath '*/*' is still valid. 

Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=100'
wevtutil.exe qe Application /q:*/System[EventID=100] /f:text /c:1

Get-WinEvent -LogName Application -FilterXPath '*/System/Provider[@Name="WLMS"]'
Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=101 and */System/Provider[@Name="WLMS"]'	# combine 2 queries

Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="System"'		# We will build the query for TargetUserName. 
													# In this case, that will be System.	

Examples:
Get-WinEvent -LogName Application -FilterXPath '*/system/Provider[@Name="WLMS"] and */system/TimeCreated[@SystemTime="2020-12-15T01:09:08.940277500Z"]
Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="sam" and */system/EventID=4720'

Get-WinEvent -Path .\\Desktop\\merged.evtx -FilterXPath '*/System/EventID=4104
 and */EventData/Data[@Name="ScriptBlockText"]' | Format-List

Get-WinEvent -Path .\\Desktop\\merged.evtx -FilterXPath '*/EventData/Data[@Name="CallerProcessName"]='C:\Windows\System32\net1.exe' | Format-List

```

===============================================================================
# Sysmon
```
Events within Sysmon are stored in Applications and Services Logs/Microsoft/Windows/Sysmon/Operational

sysmon-config:
https://github.com/SwiftOnSecurity/sysmon-config
sysmon.exe -accepteula -i sysmonconfig-export.xml

 there are rulesets like the ION-Storm sysmon-config fork that takes a more proactive approach

Event ID 1: Process Creation
it is excluding the svchost.exe process from the event logs
<RuleGroup name="" groupRelation="or">
	<ProcessCreate onmatch="exclude">
	 	<CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc</CommandLine>
	</ProcessCreate>
</RuleGroup>


Event ID 3: Network Connection
<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
	 	<Image condition="image">nmap.exe</Image>
	 	<DestinationPort name="Alert,Metasploit" condition="is">4444</DestinationPort>
	</NetworkConnect>
</RuleGroup>

The above code snippet includes two ways to identify suspicious network connection activity. The first way will identify files transmitted over open ports. In this case, we are specifically looking for nmap.exe which will then be reflected within the event logs. The second method identifies open ports and specifically port 4444 which is commonly used with Metasploit. If the condition is met an event will be created and ideally trigger an alert for the SOC to further investigate.


Event ID 7: Image Loaded
look for DLLs loaded by processes
<RuleGroup name="" groupRelation="or">
	<ImageLoad onmatch="include">
	 	<ImageLoaded condition="contains">\Temp\</ImageLoaded>
	</ImageLoad>
</RuleGroup>

The above code snippet will look for any DLLs that have been loaded within the \Temp\ directory. If a DLL is loaded within this directory it can be considered an anomaly and should be further investigateded. 


Event ID 8: CreateRemoteThread
The CreateRemoteThread Event ID will monitor for processes injecting code into other processes

<RuleGroup name="" groupRelation="or">
	<CreateRemoteThread onmatch="include">
	 	<StartAddress name="Alert,Cobalt Strike" condition="end with">0B80</StartAddress>
	 	<SourceImage condition="contains">\</SourceImage>
	</CreateRemoteThread>
</RuleGroup>

The above code snippet shows two ways of monitoring for CreateRemoteThread. The first method will look at the memory address for a specific ending condition which could be an indicator of a Cobalt Strike beacon. The second method will look for injected processes that do not have a parent process. This should be considered an anomaly and require further investigation. 


Event ID 11: File Created
<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
	 	<TargetFilename name="Alert,Ransomware" condition="contains">HELP_TO_SAVE_FILES</TargetFilename>
	</FileCreate>
</RuleGroup> 

The above code snippet is an example of a ransomware event monitor


Event ID 12 / 13 / 14: Registry Event
<RuleGroup name="" groupRelation="or">
	<RegistryEvent onmatch="include">
	 	<TargetObject name="T1484" condition="contains">Windows\System\Scripts</TargetObject>
	</RegistryEvent>
</RuleGroup>

The above code snippet will look for registry objects that are in the "Windows\System\Scripts" directory as this is a common directory for adversaries to place scripts to establish persistence.


Event ID 15: FileCreateStreamHash
This event will look for any files created in an alternate data stream. 
<RuleGroup name="" groupRelation="or">
	<FileCreateStreamHash onmatch="include">
	 	<TargetFilename condition="end with">.hta</TargetFilename>
	</FileCreateStreamHash>
</RuleGroup> 

The above code snippet will look for files with the .hta extension that have been placed within an alternate data stream.

<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
		<TargetFileName condition="contains">mimikatz</TargetFileName>
	</FileCreate>
</RuleGroup>


Event ID 22: DNS Event
<RuleGroup name="" groupRelation="or">
	<DnsQuery onmatch="exclude">
	 	<QueryName condition="end with">.microsoft.com</QueryName>
	</DnsQuery>
</RuleGroup> 

The above code snippet will get exclude any DNS events with the .microsoft.com query. This will get rid of the noise that you see within the environment.


------------------------------------------------------------------
an example of using Get-WinEvent to look for network connections coming from port 4444:
Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'

------------------------------------------------------------------
Detecting Mimikatz:

<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
		<TargetFileName condition="contains">mimikatz</TargetFileName>
	</FileCreate>
</RuleGroup>

Hunting Abnormal LSASS Behavior:
If LSASS is accessed by a process other than svchost.exe it should be considered suspicious behavior 

<RuleGroup name="" groupRelation="or">
	<ProcessAccess onmatch="include">
	       <TargetImage condition="image">lsass.exe</TargetImage>
	</ProcessAccess>
</RuleGroup>


below significantly and can focus on only the anomalies:
<RuleGroup name="" groupRelation="or">
	<ProcessAccess onmatch="exclude">
		<SourceImage condition="image">svchost.exe</SourceImage>
	</ProcessAccess>
	<ProcessAccess onmatch="include">
		<TargetImage condition="image">lsass.exe</TargetImage>
	</ProcessAccess>
</RuleGroup>
 


Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'

------------------------------------------------------------------
Hunting Malware:

<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
		<DestinationPort condition="is">1034</DestinationPort>
		<DestinationPort condition="is">1604</DestinationPort>
	</NetworkConnect>
	<NetworkConnect onmatch="exclude">
		<Image condition="image">OneDrive.exe</Image>
	</NetworkConnect>
</RuleGroup>

Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=<Port>'


------------------------------------------------------------------
Hunting Persistence:
registry modification as well as startup scripts

We can hunt persistence with Sysmon by looking for File Creation events as well as Registry Modification events.

Hunting Startup Persistence:
We will first be looking at the SwiftOnSecurity detections for a file being placed in the \Startup\ or \Start Menu directories. 
<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
		<TargetFilename name="T1023" condition="contains">\Start Menu</TargetFilename>
		<TargetFilename name="T1165" condition="contains">\Startup\</TargetFilename>
	</FileCreate>
</RuleGroup>



Hunting Registry Key Persistence:
We will again be looking at another SwiftOnSecurity detection this time for a registry modification that adjusts that places a script inside CurrentVersion\Windows\Run and other registry locations.
<RuleGroup name="" groupRelation="or">
	<RegistryEvent onmatch="include">
		<TargetObject name="T1060,RunKey" condition="contains">CurrentVersion\Run</TargetObject>
		<TargetObject name="T1484" condition="contains">Group Policy\Scripts</TargetObject>
		<TargetObject name="T1060" condition="contains">CurrentVersion\Windows\Run</TargetObject>
	</RegistryEvent>
</RuleGroup>


------------------------------------------------------------------
Detecting Evasion Techniques
Alternate Data Streams are used by malware to hide its files from normal inspection by saving the file in a different stream apart from $DATA

Hunting Alternate Data Streams
The code snippet below will hunt for files in the Temp and Startup folder as well as .hta and .bat extension.
<RuleGroup name="" groupRelation="or">
	<FileCreateStreamHash onmatch="include">
		<TargetFilename condition="contains">Downloads</TargetFilename>
		<TargetFilename condition="contains">Temp\7z</TargetFilename>
		<TargetFilename condition="ends with">.hta</TargetFilename>
		<TargetFilename condition="ends with">.bat</TargetFilename>
	</FileCreateStreamHash>
</RuleGroup>


Detecting Remote Threads 
Adversaries also commonly use remote threads to evade detections in combination with other techniques. Remote threads are created using the Windows API CreateRemoteThread and can be accessed using OpenThread and ResumeThread. This is used in multiple evasion techniques including DLL Injection, Thread Hijacking, and Process Hollowing.
<RuleGroup name="" groupRelation="or">
	<CreateRemoteThread onmatch="exclude">
		<SourceImage condition="is">C:\Windows\system32\svchost.exe</SourceImage>
		<TargetImage condition="is">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</TargetImage>
	</CreateRemoteThread>
</RuleGroup>
```

===============================================================================
# Osquery
```
It converts the operating system into a relational database

Realistically all your queries will start with a SELECT statement.
The exception to the rule: Using other SQL statements, such as UPDATE and DELETE, is possible, but only if you're creating run-time tables (views) or using an extension if the extension supports them. 
Some tables require a WHERE clause, such as the file table, to return a value. If the required WHERE clause is not included in the query, then you will get an error. 

https://osquery.io/schema

meta-commands:
osqueryi			# start osquery in terminal
.help
.tables				# list tables
.tables process			# list tables that are associated with processes
.tables user			# list all the tables with the term user in them
.schema table_name		# list a table's schema (known as knowledge of columns and types)
.mode <mode> 			# Osquery comes with multiple display modes to select from like list, line, column, csv, pretty (use .help)

queries:
select column1, column2, column3 from table;
SELECT * FROM programs LIMIT 1;		# return the first installed program
SELECT name, version, install_location, install_date from programs limit 1;
SELECT count(*) from programs;		# see how many programs or entries in any table are returned
select name,install_location from programs where name LIKE '%wireshark%';

= [equal]
<>  [not equal]
>, >= [greater than, greater than, or equal to]
<, <= [less than or less than or equal to] 
BETWEEN [between a range]
LIKE [pattern wildcard searches]
% [wildcard, multiple characters]
_ [wildcard, one character]

Matching Examples:
/Users/%/Library: Monitor for changes to every user's Library folder, but not the contents within.
/Users/%/Library/: Monitor for changes to files within each Library folder, but not the contents of their subdirectories.
/Users/%/Library/%: Same, changes to files within each Library folder.
/Users/%/Library/%%: Monitor changes recursively within each Library.
/bin/%sh: Monitor the bin directory for changes ending in sh.

Joining Tables using JOIN Function:
join two tables based on a column that is shared by both tables
Query1: select uid, pid, name, path from processes;
Query2: select uid, username, description from users;
Joined Query: select p.pid, p.name, p.path, u.username from processes p JOIN users u on u.uid=p.uid LIMIT 10;
```
===============================================================================
# Wazuh
```
The rule with an id of 5710 detects attempted connections that are unsuccessful for the SSH protocol.

Field			Value		Description
agent.ip		10.10.73.118	This is the IP address of the agent that the alert was triggered on.
agent.name		ip-10-10-73-118	This is the hostname of the agent that the alert was triggered on.
rule.description	sshd: Attempt to login using a non-existent user	This field is a brief description of what the event is alerting to.
rule.mitre.technique	Brute-Force	This field explains the MITRE technique that the alert pertains to.
rule.mitre.id		T1110		This field is the MITRE ID of the alert
rule.id			5710		This field is the ID assigned to the alert by Wazuh's ruleset
location		/var/log/auth.log					This field is the location of the file that the alert was generated from on the agent. In this example, it is the authentication log on the linux agent.


alert is stored in a specific file on the Wazuh management server: /var/ossec/logs/alerts/alerts.log

windows:
For collecting windows logs we need to configure Sysmon and integrate it with wazuh.
Wazuh agent file located at: C:\Program Files (x86)\ossec-agent\ossec.conf
/var/ossec/etc/rules/local_rules.xml

Linux:
Wazuh comes with many rules that enable Wazuh to analyze log files and can be found in /var/ossec/ruleset/rules

  <!-- Apache2 Log Analysis -->
  <localfile>
    <location>/var/log/example.log</location>
    <log_format>syslog</log_format>
  </localfile>

Auditd monitors the system for certain actions and events and will write this to a log file.
edit the file using sudo nano /etc/audit/rules.d/audit.rules and appending -a exit,always -F arch=64 -F euid=0 -S execve -k audit-wazuh-c
sudo auditctl -R /etc/audit/rules.d/audit.rules		# restart
<localfile>
    <location>/var/log/audit/audit.log</location>
    <log_format>audit</log_format>
</localfile>



TOKEN=$(curl -u : -k -X GET "https://WAZUH_MANAGEMENT_SERVER_IP:55000/security/user/authenticate?raw=true")
```
# Network Security and Traffic Analysis

===============================================================================
# Traffic Analysis Essentials
```
Network Security and Network Data
authentication and authorization
Network Access Control (NAC)
Controls the devices' suitability before access to the network. Designed to verify device specifications and conditions are compliant with the predetermined profile before connecting to the network.
Security Orchestration Automation and Response (SOAR)
Technology that helps coordinate and automates tasks between various people, tools, and data within a single platform to identify anomalies, threats, and vulnerabilities. It also supports vulnerability management, incident response, and security operations.

```

===============================================================================
# Snort
```
Snort is the foremost Open Source Intrusion Prevention System (IPS) in the world. Snort IPS uses a series of rules that help define malicious network activity and uses those rules to find packets that match against them and generate alerts for users

uses: As a packet sniffer like tcpdump, as a packet logger — which is useful for network traffic debugging, or it can be used as a full-blown network intrusion prevention system.

Behaviour-based Intrusion Prevention System (Network Behaviour Analysis - NBA)
You will use Snort as an IDS. You will need to start "inline mode" to turn on IPS mode.

Snort has three main use models:
Sniffer Mode - Read IP packets and prompt them in the console application.
Packet Logger Mode - Log all IP packets (inbound and outbound) that visit the network.
NIDS (Network Intrusion Detection System)  and NIPS (Network Intrusion Prevention System) Modes - Log/drop the packets that are deemed as malicious according to the user-defined rules.

snort -V					# version
sudo snort -c /etc/snort/snort.conf -T 		# -T=testing configuration,  "-c"=identifying the configuration file

-V / --version	This parameter provides information about your instance version.
-c	Identifying the configuration file
-T	Snort's self-test parameter, you can test your setup with this parameter.
-q	Quiet mode prevents snort from displaying the default banner and initial information about your setup.

------------------------------------------------------------------
Sniffer Mode

-v	Verbose. Display the TCP/IP output in the console.
-d	Display the packet data (payload).
-e	Display the link-layer (TCP/IP/UDP/ICMP) headers. 
-X	Display the full packet details in HEX.
-i	This parameter helps to define a specific network interface to listen/sniff. Once you have multiple interfaces, you can choose a specific interface to sniff. 

sudo snort -v -i eth0		# verbose mode (-v), use the interface (-i)

------------------------------------------------------------------
Packet Logger Mode

-l	
Logger mode, target log and alert output directory. Default output folder is /var/log/snort

The default action is to dump as tcpdump format in /var/log/snort

-K ASCII	Log packets in ASCII format.
-n	Specify the number of packets that will process/read. Snort will stop after reading the specified number of packets.
-r	Reading option, read the dumped logs in Snort. (sudo snort -r snort.log.1638459842)/(sudo tcpdump -r snort.log.1638459842 -ntc 10)
"-r" parameter also allows users to filter the binary log files. You can filter the processed log to see specific packets with the "-r" parameter and Berkeley Packet Filters (BPF). 

filter:
sudo snort -r logname.log -X
sudo snort -r logname.log icmp
sudo snort -r logname.log tcp
sudo snort -r logname.log 'udp and port 53'
sudo snort -r logname.log 'tcp port 80'

snort -dvr logname.log -n 10

------------------------------------------------------------------
IDS/IPS
NIDS mode parameters are explained in the table below;
Parameter	Description
-c		Defining the configuration file.
-T		Testing the configuration file.
-N		Disable logging.
-D		Background mode.
-A		Alert modes;
	full: Full alert mode, providing all possible information about the alert. This one also is the default mode; once you use -A and don't specify any 	mode, snort uses this mode. there is no console output in this mode
	fast:  Fast mode shows the alert message, timestamp, source and destination IP, along with port numbers. there is no console output in this mode

	console: Provides fast style alerts on the console screen.

	cmg: CMG style, basic header details with payload in hex and text format.

	none: Disabling alerting. creates a log file in binary dump format

alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)

------------------------------------------------------------------
investigate PCAPs

-r / --pcap-single=	Read a single pcap
--pcap-list=""	Read pcaps provided in command (space separated).
--pcap-show	Show pcap name on console during processing.

sudo snort -c /etc/snort/snort.conf -q -r icmp-test.pcap -A console -n 10
sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console -n 10
sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console --pcap-show   # show the name and distinguish each pcap
sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap

------------------------------------------------------------------
Snort Rule Structure

Action		Protocol	Source IP	Source Port	Direction	Destination IP	Destination Port	Option
alert		TCP		ANY		ANY		<> (Bidir)	ANY		ANY			msg: message	
drop		ICMP		192.168.1.56			-> (s to d)			21			Reference: 
reject		UDP		192.168.1.0/24							!21			sid: Rule id
log				[192.168.1.0/24, 10.1.1.0/24]					1:1024 (range)		rev: Revision information
				!192.168.1.0/24 any 						:1024 (equal and less than 1024)
												1025: (equal and greater than 1025)
												[21,23]

alert icmp any any <> any any (msg: "ICMP Packet found";reference:CVE-XXXX;sid:1000001;rev1;)

You will use Snort as an IDS. You will need to start "inline mode" to turn on IPS mode.
"alert"  for IDS mode and "reject" for IPS mode
Rules cannot be processed without a header. Rule options are "optional" parts
once you create a rule, it is a local rule and should be in your "local.rules" file. This file is located under "/etc/snort/rules/local.rules".

action:
	alert: Generate an alert and log the packet.
	log: Log the packet.
	drop: Block and log the packet.
	reject: Block the packet, log it and terminate the packet session. 

Protocol:
	Snort2 supports only four protocols filters in the rules (IP, TCP, UDP and ICMP)

There are three main rule options in Snort:
General Rule Options - Fundamental rule options for Snort. 
	Snort rule IDs (SID) 
		<100: Reserved rules
		100-999,999: Rules came with the build.
		>=1,000,000: Rules created by user.
	Reference
		 additional information or reference to explain the purpose of the rule
	Rev
		Snort rules can be modified and updated for performance and efficiency issues. Rev option help analysts to have the revision information of
 	each rule. Rev option is only an indicator of how many times the rule had revisions. no auto-backup feature on the rule history, Analysts should 
	keep the rule history
Payload Rule Options - Rule options that help to investigate the payload data. These options are helpful to detect specific payload patterns.
	Content
		Payload data. It matches specific payload data by ASCII, HEX or both.
		Following rules will create an alert for each HTTP packet containing the keyword "GET". This rule option is case sensitive!
		ASCII mode - alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; sid: 100001; rev:1;)
		HEX mode - alert tcp any any <> any 80  (msg: "GET Request Found"; content:"|47 45 54|"; sid: 100001; rev:1;)
	Nocase
		isabling case sensitivity.
		alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; nocase; sid: 100001; rev:1;)
	Fast_pattern
		Prioritise content search to speed up the payload search operation. This option always works case insensitive and can be used once per rule. Note that this option is required when using multiple "content" options. 
		The following rule has two content options, and the fast_pattern option tells to snort to use the first content option (in this case, "GET") for the initial packet match.
		alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; fast_pattern; content:"www";  sid:100001; rev:1;)

Non-Payload Rule Options - Rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.
	ID	
		Filtering the IP id field.
		alert tcp any any <> any any (msg: "ID TEST"; id:123456; sid: 100001; rev:1;)
	
	Flags
		Filtering the TCP flags. F - FIN, S - SYN, R - RST, P - PSH, A - ACK, U - URG
		alert tcp any any <> any any (msg: "FLAG TEST"; flags:S;  sid: 100001; rev:1;)

	Dsize
		Filtering the packet payload size.

		dsize:min<>max;
		dsize:>100
		dsize:<100
		alert ip any any <> any any (msg: "SEQ TEST"; dsize:100<>300;  sid: 100001; rev:1;)

	Sameip
		Filtering the source and destination IP addresses for duplication.
		alert ip any any <> any any (msg: "SAME-IP TEST";  sameip; sid: 100001; rev:1;)

------------------------------------------------------------------
config info

Main Components of Snort

Packet Decoder - Packet collector component of Snort. It collects and prepares the packets for pre-processing. 
Pre-processors - A component that arranges and modifies the packets for the detection engine.
Detection Engine - The primary component that process, dissect and analyse the packets by applying the rules. 
Logging and Alerting - Log and alert generation component.
Outputs and Plugins - Output integration modules (i.e. alerts to syslog/mysql) and additional plugin (rule management detection plugins) support is done with this component. 

Step #1: Set the network variables.
This section manages the scope of the detection and rule paths.

TAG NAME	INFO											EXAMPLE
HOME_NET	That is where we are protecting.							'any' OR '192.168.1.1/24'
EXTERNAL_NET 	This field is the external network, so we need to keep it as 'any' or '!$HOME_NET'.	'any' OR '!$HOME_NET'
RULE_PATH	Hardcoded rule path.									/etc/snort/rules
SO_RULE_PATH	These rules come with registered and subscriber rules.					$RULE_PATH/so_rules
PREPROC_RULE_PATH	These rules come with registered and subscriber rules.				$RULE_PATH/plugin_rules


Step #2: Configure the decoder.
In this section, you manage the IPS mode of snort. The single-node installation model IPS model works best with "afpacket" mode. You can enable this mode and run Snort in IPS.

TAG NAME	INFO	EXAMPLE
#config daq:	IPS mode selection.	afpacket
#config daq_mode:	Activating the inline mode	inline
#config logdir:	Hardcoded default log path.	/var/logs/snort
Data Acquisition Modules (DAQ) are specific libraries used for packet I/O, bringing flexibility to process packets. It is possible to select DAQ type and mode for different purposes.

There are six DAQ modules available in Snort;

Pcap: Default mode, known as Sniffer mode.
Afpacket: Inline mode, known as IPS mode.
Ipq: Inline mode on Linux by using Netfilter. It replaces the snort_inline patch.  
Nfq: Inline mode on Linux.
Ipfw: Inline on OpenBSD and FreeBSD by using divert sockets, with the pf and ipfw firewalls.
Dump: Testing mode of inline and normalisation.
The most popular modes are the default (pcap) and inline/IPS (Afpacket).

6: Configure output plugins

Step #7: Customise your ruleset
# site specific rules	Hardcoded local and user-generated rules path.	include $RULE_PATH/local.rules
#include $RULE_PATH/	Hardcoded default/downloaded rules path.	include $RULE_PATH/rulename

```
===============================================================================
# Snort Challenge - The Basics
```
sudo strings snort.log.1688564350 | grep 220	# find strings for success FTP response (220) that includes the name of the service
Each failed FTP login attempt prompts a default message with the pattern; "530 User"
230 User		# successful FTP login attempt 

alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)
alert tcp any any <> any any (msg: "PNG test"; content:"|89 50 4E 47 0D 0A 1A 0>
alert tcp any any <> any any (msg: "gif"; content:"|47 49 46 38 39 61|"; depth:6>

```
===============================================================================
# NetworkMiner
```
Network Forensics Analysis Tool
Developed and still maintained by Netresec.
NetworkMiner is to investigate the overall flow/condition of the limited amount of traffic, not for a long in-depth live traffic investigation.

------------------------------------------------------------------
Introduction to Network Forensics

Who (Source IP and port)
What (Data/payload)
Where (Destination IP and port)
When (Time and data)
Why (How/What happened)

Sources of Network Forensics Evidence
Capturing proper network traffic requires knowledge and tools. Usually, there is a single chance of gathering the live traffic as evidence. There are multiple evidence resources to gather network forensics data.
TAPS
InLine Devices
SPAN Ports
Hubs
Switches
Routers
DHCP Servers
Name Servers
Authentication Servers
Firewalls
Web Proxies
Central Log Servers
Logs (IDS/IPS, Application, OS, Device)



------------------------------------------------------------------
Hosts:
The "hosts" menu shows the identified hosts in the pcap file. This section provides information on;
IP address
MAC address
OS type
Open ports
Sent/Received packets
Incoming/Outgoing sessions
Host details

Sessions:
The session menu shows detected sessions in the pcap file. This section provides information on;
Frame number
Client and server address
Source and destination port
Protocol
Start time

This menu accepts four types of inputs;
"ExactPhrase"
"AllWords"
"AnyWord"
"RegExe"

Credentials:
The credentials menu shows extracted credentials and password hashes from investigated pcaps. You can use Hashcat (GitHub) and John the Ripper (GitHub) to decrypt extracted credentials. NetworkMiner can extract credentials including; Kerberos hashes, NTLM hashes, RDP cookies, HTTP cookies, HTTP requests, IMAP, FTP, SMTP, MS SQL

files: shows extracted files and detail
Images: shows extracted images and detail
Messages: 
shows extracted emails, chats and messages
you will discover additional details like attachments and attributes on the selected message
You can use the built-in viewer to investigate overall information and the "open file" option to explore attachments.

Mac Address Processing
Frame Processing (up to 1.6)
Cleartext Processing (up to 1.6)
```
===============================================================================
# Wireshark: The Basics
```
You can use the "right-click menu" or "View --> Coloring Rules" menu to create permanent colouring rules. The "Colourise Packet List" menu activates/deactivates the colouring rules.
Temporary: "right-click menu" or "View --> Conversation Filter"
File --> Merge: combine two pcap files into one single file
file details/properties: "Statistics --> Capture File Properties" or by clicking the "pcap icon located on the left bottom" of the window.

Packet Dissection:  Wireshark uses OSI layers to break down packets

------------------------------------------------------------------
Packet Navigation:

use the "Go" menu and toolbar to view specific packets.
use the "Edit --> Find Packet" menu to make a search inside the packets for a particular event of interest (Display filter, Hex, String and Regex)
use the "Edit" or the "right-click" menu to mark/unmark packets. Marked packets will be shown in black regardless of the original color representing the connection type.marked packets will be lost after closing the capture file. 

Edit --> Packet Comment: comments can stay within the capture file until the operator removes them
Export Packets: export specified packets that we need
Export Objects (Files): DICOM, HTTP, IMF, SMB and TFTP
use the "View --> Time Display Format" menu to change the time display format.
Expert Info:  use the "lower left bottom section" in the status bar or "Analyse --> Expert Information"
Severity Colour	Info
Chat	Blue	Information on usual workflow.
Note	Cyan	Notable events like application error codes.
Warn	Yellow	Warnings like unusual error codes or problem statements.
Error	Red	Problems like malformed packets.

------------------------------------------------------------------
﻿﻿Packet Filtering
capture filters (at capture time) and display filters (for the captured packet)

Apply as Filter: click on the field you want to filter and use the "right-click menu" or "Analyse --> Apply as Filter" (filter only a single entity of the packet)
Conversation filter:  filter multiple entity of the packet, "right-click menu" or "Analyse --> Conversation Filter
Colourise Conversation: similar to the "Conversation Filter" with one difference. It highlights the linked packets without applying a display filter. View --> Colourise Conversation --> Reset Colourisation"

Prepare as Filter: Similar to "Apply as Filter", however it only adds the filter to the filter box and we can change and/or apply it
Apply as Column: select the value, "right-click menu" or "Analyse -->  Apply as Column"
Follow Stream: packets originating from the server are highlighted with blue, and those originating from the client are highlighted with red.
```
===============================================================================
# Wireshark: Packet Operations
```
eq (==)			# ip.src == 10.10.10.100
ne (!=)			# ip.src != 10.10.10.100
gt (>)			# ip.ttl > 250
lt (<)			# ip.ttl < 10
ge (>=)			# ip.ttl >= 0xFA
le (<=)			# ip.ttl <= 0xA

and (&&)		# (ip.src == 10.10.10.100) AND (ip.src == 10.10.10.111)
or (||)			# (ip.src == 10.10.10.100) OR (ip.src == 10.10.10.111)
not (!)			# use !(value) instead of !=value, exp: !(ip.src == 10.10.10.111)
contains		# like find, case sensitive, focusing on a specific field, exp: http.server contains "Apache"
matches			# Search a pattern of a regular expression (regex), exp: http.host matches "\.(php|html)"
in			# tcp.port in {80 443 8080}, udp.port in {50 .. 70} for list
upper			# Convert a string value to uppercase. exp: upper(http.server) contains "APACHE" (Convert all HTTP packets' "server" fields to uppercase and list packets that contain the "APACHE" keyword.)
lower			# Convert a string value to lowercase.
string			# Convert a non-string value to a string. exp: string(frame.number) matches "[13579]$" (Convert all "frame number" fields to string values, and list frames end with odd values.)
------------------------------------------------------------------

eth.src, eth.dst 	# mac address
ip, ip.addr, ip.dst, ip.src
tcp.port, tcp.srcport, tct.dstport
http, http.response.code, http.request.method
dns, dns.flags.response, dns.qry.type == 1 (A records)

```
===============================================================================
# Wireshark: Traffic Analysis
```
------------------------------------------------------------------
nmap scan

TCP FLAGS:
FIN=1, SYN=2, RST=4, ACK=16, SYN+ACK=18, RST+ACK=20

tcp.flags eq 2                                # SYN only
tcp.flags.syn eq 1                            # SYN flag is set

tcp.flags eq 18                               # SYN + ACK
tcp.flags.syn eq 1 && tcp.flags.ack eq 1      # SYN and ACK flags are set

---
example: 
# TCP Connect Scan (nmap -sT)
tcp.flags.syn eq 1 && tcp.flags.ack eq 0 && tcp.window_size gt 1024   # Detect TCP Connect scan (3-way handshake)

# TCP SYN Scan (nmap -sS)
tcp.flags.syn eq 1 && tcp.flags.ack eq 0 && tcp.window_size le 1024   # Detect SYN scan (half-open scan)

# UDP Scan (nmap -sU)
icmp.type eq 3 && icmp.code eq 3                                      # Detect UDP scan (ICMP port unreachable response)

------------------------------------------------------------------
ARP Poisoning - Flooding

eth.src, eth.dst				   # mac address
arp                                                # Global search for ARP packets
arp.opcode eq 1                                    # ARP requests
arp.opcode eq 2                                    # ARP replies
arp.dst.hw_mac eq 00:00:00:00:00:00                # Empty destination MAC → common in spoofing
arp.duplicate-address-detected                     # Wireshark detected duplicate IP addresses
arp.duplicate-address-frame                        # Alternate field for same detection
((arp) && (arp.opcode eq 1)) && (arp.src.hw_mac eq 00:0c:29:e2:18:b4)   # Scan/hunt by known MAC

---
Suspicious:
2 MACs responding to 1 IP (IP conflict/spoofing)
Same MAC claiming multiple IPs (flooding/spoofing)
Repeated ARP requests from one MAC (scanning/flood)

# IP-MAC Match (Legit)
00:0c:29:e2:18:b4 = 192.168.1.25
50:78:b3:f3:cd:f4 = 192.168.1.1  (Gateway)
00:0c:29:98:c7:a8 = 192.168.1.12 (Victim)

# ARP Spoofing
MAC: 00:0c:29:e2:18:b4 claims 192.168.1.25 (OK)
MAC: 00:0c:29:e2:18:b4 ALSO claims 192.168.1.1 (gateway!) → Spoofing

# ARP Flooding
00:0c:29:e2:18:b4 sends many ARP requests with varying IPs: 192.168.1.xxx

# MITM Confirmed
All HTTP traffic to 192.168.1.12 is redirected to MAC b4 → MITM in action

------------------------------------------------------------------
Host and User Identification (DHCP, NBNS, Kerberos)

---
# DHCP Analysis (IP assignment, hostname, domain info)
dhcp || bootp                                        # Global DHCP traffic filter

# DHCP Types:
dhcp.option.dhcp == 3                                # DHCP Request (hostname info)
dhcp.option.dhcp == 5                                # DHCP ACK (accepted request)
dhcp.option.dhcp == 6                                # DHCP NAK (rejected request)

# Useful DHCP Options:
dhcp.option.hostname contains "DESKTOP"              # Option 12: Client hostname
dhcp.option.domain_name contains "corp"              # Option 15: Domain name
# Others (view manually):
# Option 50 - Requested IP, Option 51 - Lease time, Option 61 - MAC, Option 56 - Rejection msg

---
# NBNS (NetBIOS Name Service)
nbns                                                  	# Global search for NBNS/NetBIOS traffic
nbns.name contains "WORKSTATION"                      	# Look for queried or announced hostnames
nbns.flags.opcode == 5					# NetBIOS registration requests

---
# Kerberos (Windows authentication protocol)
kerberos                                              # Global filter

# User Detection:
kerberos.CNameString contains "admin"                 		# CNameString shows username
kerberos.CNameString && !(kerberos.CNameString contains "$")   	# Exclude hostnames (end with "$")

# Kerberos Fields:
kerberos.pvno == 5                                    # Protocol version
kerberos.realm contains ".org"                        # Domain/realm info
kerberos.SNameString == "krbtgt"                      # Service name (ticket-granting ticket)
# "addresses" field (client IP) appears in request packets (view manually)

---
Suspicious Indicators:
- DHCP requests from unknown MACs or changing hostnames
- NBNS responses with unusual TTL/IP/hostnames
- Kerberos usernames with odd formats or too many requests

Example (DHCP):
dhcp.option.hostname contains "testpc" && dhcp.option.dhcp == 3   # Host requesting IP using hostname

Example (Kerberos - filter usernames only):
kerberos.CNameString && !(kerberos.CNameString contains "$")

------------------------------------------------------------------
Tunneling Traffic (ICMP & DNS)

# ICMP Tunneling (C2, Exfil, Bypass), also called port forwarding
icmp                                              # Global filter
icmp && data.len > 64                             # ICMP packet carrying extra data (suspicious)

# Indicators:
- High volume of ICMP traffic
- ICMP packets with payload size > 64 bytes
- ICMP packets with unusual content/patterns
- Post-malware or exploit activity

# Example:
icmp && data.len > 100                            # Possible ICMP tunneling or exfiltration

---
# DNS Tunneling (C2 over DNS queries)
dns                                               # Global filter
dns contains "dnscat"                             # Known tunneling tool
dns.qry.name.len > 15 && !mdns                    # Long/encoded domain names (suspicious)

# Indicators:
- DNS queries to long/obscure subdomains
- Repeated queries to same unusual domain
- Encoded subdomains like: abcd1234.malicious.com
- High volume of DNS traffic after exploit

# Example:
dns.qry.name contains "command"                   # Look for encoded commands
dns.qry.name.len > 30                             # Unusually long DNS request (likely encoded)

# Tip:
Use !mdns to ignore local device noise:
dns && !mdns

------------------------------------------------------------------
Cleartext Protocol Analysis: FTP
---
# x1x - Info responses
211 (System status), 212 (Directory status), 213 (File status) 
 			
# x2x - Connection status
220 (Service ready), 227 (Entering passive mode), 228 (Long passive mode), 229 (Extended passive mode) 
		 
# x3x - Authentication:
230 (User login successful), 231 (User logout), 331 (Username OK, need password) 	
430 (Invalid username or password), 530 (Login failed – bad credentials)
		
# 200  → Command OK

ftp.response.code == 211    			    # (System status)

---
# FTP Commands:
ftp.request.command == "USER"                       # Username sent
ftp.request.command == "PASS"                       # Password sent
ftp.request.command == "LIST"                       # List directory contents
ftp.request.command == "CWD"                        # Change working directory

---
# Brute-force / Spray Detection:
ftp.response.code == 530                            # Failed login attempts
ftp.response.arg contains "user"                    # Repeated failures on user
ftp.request.arg == "password"                       # Weak/static password usage

---
# Security Risks:
- Credentials sent in cleartext
- Easy to sniff usernames/passwords
- Look for login loops, repeated 530s, and suspicious commands

------------------------------------------------------------------
Cleartext Protocol Analysis: HTTP

# HTTP Protocols
http                                                # HTTP traffic
http2                                               # HTTP/2 traffic (binary, multiplexed)

---
# HTTP Methods
http.request                                         # All HTTP requests
http.request.method == "GET"                         # GET requests

---
# HTTP Response Codes (short summary):
200 (OK), 301 (Moved Permanently), 302 (Found),  
400 (Bad Request), 401 (Unauthorized), 403 (Forbidden),  
404 (Not Found), 405 (Method Not Allowed),  
408 (Request Timeout), 500 (Internal Server Error), 503 (Service Unavailable)

# Example filters:
http.response.code == 200                           # Successful response

---
# HTTP Parameters (requests)
http.request.uri contains "admin"                   # Resource URI
http.request.full_uri contains "admin"              # Full URI (host + path)
http.user_agent contains "nmap"                     # Suspicious user-agent (scanner)

---
# HTTP Parameters (responses)
http.server contains "apache"                      # Server type
http.host contains "domain"                        # Requested host
http.connection == "Keep-Alive"                    # Connection header
data-text-lines contains "password"                # Cleartext response body match

---
# User-Agent Analysis
http.user_agent                                      			# Global search
http.user_agent contains "sqlmap"/"Nmap"/"Nikto"/"Wfuzz"                # Known scanner

---
# Look for:
- Inconsistent user-agents from the same host
- Custom or misspelled user-agents (e.g., "Mozlila")
- Tools: Nmap, Nikto, sqlmap, Wfuzz
- Payloads or suspicious characters (like `$`, `==`)

---
# Log4j Exploit Detection
http.request.method == "POST"                       		# Log4j attack starts with POST
frame contains "jndi" || frame contains "Exploit"   		# Common payload indicators
http.user_agent contains "$" || http.user_agent contains "=="  	# Exploit pattern in user-agent

------------------------------------------------------------------
Decrypting HTTPS Traffic (TLS/SSL)

# To view actual content, you need a session key log file (SSLKEYLOGFILE)

---
# Common Filters:
http.request                                          # All HTTP requests (visible after decryption)
tls                                                   # Global TLS traffic
tls.handshake.type == 1                               # Client Hello
tls.handshake.type == 2                               # Server Hello
ssdp                                                  # Ignore local SSDP (service discovery)

# Filter Examples:
(http.request or tls.handshake.type == 1) and !(ssdp)              # Client Hello (initial TLS handshake)

---
# What You Need for Decryption:
- Use Chrome or Firefox
- Set environment variable before browsing:
  export SSLKEYLOGFILE=/path/to/sslkeylog.txt         # Linux/macOS
  set SSLKEYLOGFILE=C:\path\to\sslkeylog.txt          # Windows
- Wireshark will use this file to decrypt sessions

# How to load key log file in Wireshark:
- Right-click → Protocol Preferences → TLS → (Add Key Log File)
- OR go to: Edit → Preferences → Protocols → TLS → (Add Key Log File)

------------------------------------------------------------------
Cleartext Credential Hunting

# View known cleartext creds:
Tools → Credentials                         # Works in Wireshark v3.1+

# Supported for cleartext protocols like:
FTP, HTTP, IMAP, POP3, SMTP

# Filters for manual checks:
ftp.request.command == "USER"
ftp.request.command == "PASS"
http.request.method == "POST" && data-text-lines contains "password"
```

===============================================================================
# TShark: The Basics
```
capinfos				# A tool that provides details of a specified capture file

------------------------------------------------------------------
# TShark is Wireshark's CLI tool for traffic capture and analysis
# Requires sudo to list interfaces or capture live traffic

---
# Common Parameters:
tshark -h              # Show help menu
tshark -v              # Show version info
tshark -D              # List all available interfaces
tshark -i <iface>      # Start capture on specific interface (e.g., -i 1, -i eth0)
tshark                 # Capture on default interface (same as -i 1)

---
$ tshark -i 2		# Choose interface by number (-D lists interfaces by number) or name
Capturing on 'Loopback: lo'

------------------------------------------------------------------
TShark CLI: Parameters II (Reading, Writing, Verbosity)

---
# Key Parameters:

-r <file>     # Read packets from capture file
-c <num>      # Stop after N packets
-w <file>     # Write captured/filtered packets to file
-V            # Verbose output (detailed info like Wireshark's Packet Details Pane)
-q            # Quiet mode (suppress output)
-x            # Show packet bytes (hex + ASCII)

tshark -r demo.pcapng		# Read from file
tshark -r demo.pcapng -c 2	# Read first 2 packets
tshark -r demo.pcapng -c 1 -w write-demo.pcap		# Write to file
tshark -r write-demo.pcap -x				# show packet bytes (hex + ASCII)
tshark -r demo.pcapng -c 1 -V				# Verbose packet view (detailed breakdown), Use after filtering or small packet sets for easier analysis

------------------------------------------------------------------
TShark: Capture Condition Parameters

# Use -a (autostop) or -b (ring buffer) to control how long or how much TShark captures

---
# Autostop Conditions (stop after condition met):
-a duration:X       # Stop after X seconds
-a filesize:X       # Stop when file size reaches X KB
-a files:X          # Stop after X numbers of files created
Example:
$ tshark -w test.pcap -a duration:2 -a filesize:5 -a files:5

---
# Ring Buffer (looped capture, replaces old files):
-b duration:X       # Every X sec, create new file
-b filesize:X       # New file every X KB
-b files:X          # Rotate X files, overwrite oldest

Example:
$ tshark -w test.pcap -b filesize:10 -b files:3

---
# Notes:
- Works only in live capture mode (not with -r)
- You can mix -a and -b
- At least one -a is required to stop an infinite loop

------------------------------------------------------------------
TShark: Packet Filtering (Capture vs Display)

1. Capture Filters (-f) - set *before* capture (live filter)
2. Display Filters (-Y) - set *after* capture (used for analysis)

$ tshark -i eth0 -f "tcp port 80"		# only capture http traffic
$ tshark -r file.pcap -Y "http"			# filter http packets inside the file

------------------------------------------------------------------
TShark: Capture Filters (Live Traffic Filtering)

# Capture filters use BPF (Berkeley Packet Filter) syntax.
# Filters are applied before capturing, not editable during capture.

---
# Filter Syntax Structure:
<direction> <type> <value>
Examples:
- host 10.10.10.10
- src port 80
- dst net 192.168.1.0/24
- tcp, udp, icmp, etc.

---
# Common Filter Types:
host         → Match an IP or hostname
net          → Match a network range
port         → Match a single port
portrange    → Match a range of ports

# Directions:
src          → Source only
dst          → Destination only
(no direction = both)

# Protocols:
tcp, udp, icmp, arp, ether, ip, ip6
or protocol numbers (e.g., ip proto 1 for ICMP)

---
# Examples:
$ tshark -f "host 10.10.10.10"
$ tshark -f "src port 22"
$ tshark -f "udp"
$ tshark -f "ip proto 1"
$ tshark -f "ether host F8:DB:C5:A2:5D:81"

------------------------------------------------------------------
TShark: Display Filters (Post-Capture Filtering)

# Display filters are used to view only specific packets in a capture file
# Syntax is the same as Wireshark’s display filters
# Can be used with -Y option

Note: Use single quotes in filters to avoid shell issues.

---
# Display Filter Examples:

## IP Filters
tshark -r demo.pcapng -Y 'ip.addr == 10.10.10.10'         # Any match (src/dst)
tshark -r demo.pcapng -Y 'ip.addr == 10.10.10.0/24'       # Network range
tshark -r demo.pcapng -Y 'ip.dst == 10.10.10.10'          # Destination IP
```

===============================================================================
# TShark: CLI Wireshark Features
```
------------------------------------------------------------------
TShark: CLI Wireshark Features – Statistics

TShark supports several Wireshark-like features using the `-z` (statistics) parameter.

Notes:
- Applies to all packets unless filtered with `-Y`
- Use `-q` to suppress packet output and show stats only
- Use `--color` for colorized output

---
# Color Output
tshark -r file.pcap --color         # Highlighted output (like Wireshark)

---
# Protocol Hierarchy
tshark -r file.pcap -z io,phs -q    	# Summary of protocols used
tshark -r file.pcap -z io,phs,udp -q  	# Focus only on UDP traffic

---
# Packet Length Tree
tshark -r file.pcap -z plen,tree -q  	# Shows distribution by packet size

---
# Endpoints
tshark -r file.pcap -z endpoints,ip -q   # List of IPv4 addresses, packets, and byte counts
# Filters: eth, ip, ipv6, tcp, udp, wlan

---
# Conversations
tshark -r file.pcap -z conv,ip -q     	# Show IP-to-IP conversation stats
# Also works with eth, tcp, udp, etc.

---
# Expert Info
tshark -r file.pcap -z expert -q      	# Show warnings like retransmissions, errors, etc.

------------------------------------------------------------------
TShark: Protocol-Specific Stats (Post-Capture)

# Protocol Type Stats
tshark -r demo.pcapng -z ptype,tree -q                # Show TCP/UDP count, % share

# All IPv4 Hosts
tshark -r demo.pcapng -z ip_hosts,tree -q             # List all IPv4 addresses seen

# Source & Destination IPs
tshark -r demo.pcapng -z ip_srcdst,tree -q            # List all src and dst IPs
tshark -r demo.pcapng -z ipv6_srcdst,tree -q          # For IPv6

# Destinations & Ports
tshark -r demo.pcapng -z dests,tree -q                # List destination IPs and ports used

# DNS Stats
tshark -r demo.pcapng -z dns,tree -q                  # Show DNS query types, responses

# HTTP Stats
tshark -r demo.pcapng -z http,tree -q                 # HTTP status codes (200, etc.)
tshark -r demo.pcapng -z http_req,tree -q             # HTTP requests only
tshark -r demo.pcapng -z http_seq,tree -q             # Request/response matching
tshark -r demo.pcapng -z http_srv,tree -q             # HTTP load distribution
tshark -r demo.pcapng -z http2,tree -q                # HTTP/2 stats

------------------------------------------------------------------
TShark: Streams, File Extraction & Credentials

# Analyze traffic streams, extract objects, or find cleartext creds
# Use -z or --export-objects with proper params

---

# Follow Streams (TCP, UDP, HTTP, etc.)
# Format: -z follow,<proto>,ascii,<stream_id> -q

## TCP Stream #1
tshark -r demo.pcapng -z follow,tcp,ascii,1 -q

## UDP Stream #0
tshark -r demo.pcapng -z follow,udp,ascii,0 -q

## HTTP Stream #0
tshark -r demo.pcapng -z follow,http,ascii,0 -q

---

# Export Objects (Extract Files)
# Format: --export-objects <proto>,<folder> -q

## Extract HTTP Files
tshark -r demo.pcapng --export-objects http,./out -q

---
# Find Cleartext Credentials (FTP, HTTP, etc.)
# Format: -z credentials -q

## Scan for Credentials
tshark -r credentials.pcap -z credentials -q

------------------------------------------------------------------
TShark: Advanced Filtering & Field Extraction

# For deep analysis, use `contains`, `matches`, and field extraction
# Use `-Y` for filters and `-T fields` to format output

---
# Filter: contains
# Search for exact (case-sensitive) strings in fields

## Example: Find "Apache" in HTTP server field
tshark -r demo.pcapng -Y 'http.server contains "Apache"'

## Display with src/dst IP and server name
tshark -r demo.pcapng -Y 'http.server contains "Apache"' -T fields -e ip.src -e ip.dst -e http.server -E header=y

---
# Filter: matches
# Use regex (case-insensitive) to match patterns

## Example: Match GET or POST HTTP requests
tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"'

## Display IPs and request method
tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"' \
  -T fields -e ip.src -e ip.dst -e http.request.method -E header=y

---
# Extract Fields
# Extract specific values from packets using `-T fields`

## Syntax:
-T fields -e <field1> -e <field2> ... -E header=y

## Example: Extract src & dst IPs (first 5 packets)
tshark -r demo.pcapng -T fields -e ip.src -e ip.dst -E header=y -c 5

------------------------------------------------------------------
TShark: Common Use Cases

---
# Extract Hostnames (from DHCP)

tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname		# Basic extraction
tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname | awk NF | sort -r | uniq -c | sort -r	# Cleaned and organized output (count duplicates)

---
# Extract DNS Queries
tshark -r dns-queries.pcap -T fields -e dns.qry.name | awk NF | sort -r | uniq -c | sort -r

---
# Extract User-Agent Strings
tshark -r user-agents.pcap -T fields -e http.user_agent | awk NF | sort -r | uniq -c | sort -r
```

===============================================================================
# DFIR: An Introduction
```
Artifacts are pieces of evidence that point to an activity performed on a system. 
- Collecting Artifacts
- Evidence Preservation (integrity), copy for analysis
- Chain of custody
- Order of volatility
- Timeline creation

Eradication
Definition: Eradication is the process of removing the root cause of the security incident and eliminating any malicious code or artifacts that may be present in the system.
activities: Deleting malicious files and code, Disabling compromised accounts.

Remediation
Definition: Remediation is the broader process that encompasses eradication, focusing on fixing the root cause of the incident and preventing future occurrences.
activities: Implementing long-term security measures, Revising and updating security policies and procedures, security audits and assessments, training

Recovery
Definition: Recovery involves restoring and validating system functionality to return operations to normal after an incident.
activities: restore, verify, monitor the system and let the stakeholders know about that 

```
===============================================================================
# Windows Forensics 1
```
Windows Registry: configs, also includes data about the recently used files, programs used, or devices connected to the system.

Keys and Values
Registry Hive: is a group of Keys, subkeys, and values stored in a single file on the disk.

Structure of the Registry, five root keys:
HKEY_CURRENT_USER: The current user's folders, screen colors, and Control Panel settings |configuration|
HKEY_USERS: all the actively loaded user profiles on the computer (HKCU is a subkey of HKU)
HKEY_LOCAL_MACHINE: Contains configuration information particular to the computer (for any user).

HKEY_CLASSES_ROOT: Is a subkey of HKEY_LOCAL_MACHINE\Software. The information that is stored here makes sure that the correct program opens when you open a file by using Windows Explorer. This key is sometimes abbreviated as HKCR. Starting with Windows 2000, this information is stored under both the HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER keys. The HKEY_LOCAL_MACHINE\Software\Classes key contains default settings that can apply to all users on the local computer. The HKEY_CURRENT_USER\Software\Classes key has settings that override the default settings and apply only to the interactive user.
The HKEY_CLASSES_ROOT key provides a view of the registry that merges the information from these two sources. HKEY_CLASSES_ROOT also provides this merged view for programs that are designed for earlier versions of Windows. To change the settings for the interactive user, changes must be made under HKEY_CURRENT_USER\Software\Classes instead of under HKEY_CLASSES_ROOT.
To change the default settings, changes must be made under HKEY_LOCAL_MACHINE\Software\Classes .If you write keys to a key under HKEY_CLASSES_ROOT, the system stores the information under HKEY_LOCAL_MACHINE\Software\Classes.
If you write values to a key under HKEY_CLASSES_ROOT, and the key already exists under HKEY_CURRENT_USER\Software\Classes, the system will store the information there instead of under HKEY_LOCAL_MACHINE\Software\Classes.

HKEY_CURRENT_CONFIG: Contains information about the hardware profile that is used by the local computer at system startup.

------------------------------------------------------------------
Accessing registry hives offline:
 
hives are located in the C:\Windows\System32\Config directory and are:
DEFAULT (mounted on HKEY_USERS\DEFAULT)
SAM (mounted on HKEY_LOCAL_MACHINE\SAM)
SECURITY (mounted on HKEY_LOCAL_MACHINE\Security)
SOFTWARE (mounted on HKEY_LOCAL_MACHINE\Software)
SYSTEM (mounted on HKEY_LOCAL_MACHINE\System)

two other hives containing user information can be found in the User profile directory C:\Users\<username>\:
NTUSER.DAT (mounted on HKEY_CURRENT_USER when a user logs in)
USRCLASS.DAT (mounted on HKEY_CURRENT_USER\Software\CLASSES) (C:\Users\<username>\AppData\Local\Microsoft\Windows)

Amcache Hive: save information on programs that were recently run on the system, C:\Windows\AppCompat\Programs\Amcache.hve 
Transaction Logs and Backups: 
Transaction logs: changelog of the registry hive, has same name as the registry hive, stored as a .LOG file in the same directory as the hive itself.
Backups: backups of the registry hives located in the C:\Windows\System32\Config directory. These hives are copied to the C:\Windows\System32\Config\RegBack directory every ten days.

------------------------------------------------------------------
Data Acquisition: copy/image the data, so then we can do forensic analysis on it
Data Acquisition tools:
KAPE: live data acquisition and analysis tool which can be used to acquire registry data
Autopsy: acquire data from both live systems or from a disk image
FTK Imager:  extract files from a disk image or a live system by mounting the disk image or drive in FTK Imager

Exploring Windows Registry:
Registry Viewer:  It only loads one hive at a time, and it can't take the transaction logs into account.
Zimmerman's Registry Explorer::  It can load multiple hives simultaneously and add data from transaction logs into the hive to make a more 'cleaner' hive with more up-to-date data. Has bookmarks.
RegRipper: takes a registry hive as input and outputs a report that extracts data from some of the forensically important keys and values in that hive.  does not take the transaction logs into account

------------------------------------------------------------------
Registry Explorer:

System Information and System Accounts:
OS Version: SOFTWARE\Microsoft\Windows NT\CurrentVersion
Current control set: The hives containing the machine’s configuration data used for controlling system startup are called Control Sets. 
Commonly, ControlSet001 will point to the Control Set that the machine booted with, and ControlSet002 will be the last known good configuration.
SYSTEM\ControlSet001
SYSTEM\ControlSet002

Windows creates a volatile Control Set when the machine is live, called the CurrentControlSet (HKLM\SYSTEM\CurrentControlSet). For getting the most accurate system information, this is the hive that we will refer to. (SYSTEM\Select\Current)
last known good configuration (SYSTEM\Select\LastKnownGood)

Computer Name: SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName 
Time Zone Information: SYSTEM\CurrentControlSet\Control\TimeZoneInformation
Network Interfaces and Past Networks: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces

The past networks a given machine was connected to can be found in the following locations:
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed
SYSTEM\[CurrentControlSet]\Services\Tcpip\Parameters\Interfaces		# DHCP IP Address 

Autostart Programs (Autoruns):
The following registry keys include information about programs or commands that run when a user logs on. 
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\Run

Services: SYSTEM\CurrentControlSet\Services (if the start key is set to 0x02, this means that this service will start at boot)
SAM hive and user information:: SAM\Domains\Account\Users (contains user account information, login information, and group information)

----------------------------
Usage or knowledge of files/folders:

Recent Files: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf		# Recent .pdf files

Office Recent Files: 
NTUSER.DAT\Software\Microsoft\Office\15.0\Word
NTUSER.DAT\Software\Microsoft\Office\VERSION(a number)\UserMRU\LiveID_####\FileMRU	# Office 365

ShellBags: or can use shellbag
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags

Open/Save and LastVisited Dialog MRUs:
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
									
Windows Explorer Address/Search Bars: 
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery

-----------------------------
Evidence of Execution

NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU		# executed Commands

UserAssist: Windows keeps track of applications launched by the user using Windows Explorer for statistical purposes in the User Assist registry keys. These keys contain information about the programs launched, the time of their launch, and the number of times they were executed. programs that were run using the command line can't be found in the User Assist keys. 
NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count
ShimCache: ShimCache is a mechanism used to keep track of application compatibility with the OS and tracks all applications launched on the machine. also called (AppCompatCache). (SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache)
or use, AppCompatCache Parser: AppCompatCacheParser.exe --csv <path to save output> -f <path to SYSTEM hive for data parsing> -c <control set to parse>

AmCache: stores additional data related to program executions. execution path, installation, execution and deletion times, and SHA1 ,  C:\Windows\appcompat\Programs\Amcache.hve, Amcache.hve\Root\File\{Volume GUID}\

Appcompat and AppCompatFlags in registry also have good info

PowerShell Logs:
|| On a Windows Server, this history file  is located at %APPDATA%\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
|| logs are recorded for every PowerShell process executed on a system. These logs are located within the Event Viewer under Application and Services Logs -> Microsoft -> Windows -> PowerShell -> Operational or also under Application and Service Logs -> Windows PowerShell

BAM/DAM: Background Activity Monitor or BAM keeps a tab on the activity of background applications. Similar Desktop Activity Moderator or DAM is a part of Microsoft Windows that optimizes the power consumption of the device. Both of these are a part of the Modern Standby system in Microsoft Windows.  last run programs, their full paths, and last execution time.
SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}
SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}

--------------------------------
External Devices/USB device forensics

Device identification: track of USB keys plugged, vendor id, product id, and version, store the time
SYSTEM\CurrentControlSet\Enum\USBSTOR
SYSTEM\CurrentControlSet\Enum\USB

First/Last Times: first time the device was connected, the last time it was connected and the last time the device was removed
SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####

USB device Volume Name: SOFTWARE\Microsoft\Windows Portable Devices\Devices
```
===============================================================================
# Windows Forensics 2
```
FAT: FAT8, FAT12, FAT16, FAT32, exFAT
File Allocation Table creates a table that indexes the location of bits that are allocated to different files.
NTFS file system, it was not suitable for digital media devices as they did not need the added security features

Data structures:
bits that make up a file are stored in clusters. All the filenames on a file system, their starting clusters, and their lengths are stored in directories. And the location of each cluster on the disk is stored in the File Allocation Table

Clusters: storage unit
Directory: information about file identification, like file name, starting cluster, and filename length.
File Allocation Table: a linked list of all the clusters, contains the status of the cluster and the pointer to the next cluster in the chain

--------------------------------
NTFS:
Journaling: keeps a log of changes to the metadata in the volume ($LOGFILE in the volume's root directory)
Access Controls: owner of a file/directory and permissions
Volume Shadow Copy: Backup/Restore changes
Alternate Data Streams: Allows files to have multiple streams of data stored in a single file. Internet Explorer and other browsers use Alternate Data Streams to identify files downloaded from the internet (using the ADS Zone Identifier).

Master File Table (MFT): structured database that tracks the objects stored in a volume, similar to File Allocation Table, following are some of the critical files in the MFT:
$MFT: stores information about the clusters where all other objects present on the volume are located. The Volume Boot Record (VBR) points to the cluster where it is located.
$LOGFILE
$UsnJrnl: It stands for the Update Sequence Number (USN) Journal. It is present in the $Extend record. It contains information about all the files that were changed in the file system and the reason for the change. It is also called the change journal.


MFT Explorer: used to explore MFT files
MFTECmd.exe		# MFTECmd parses data from the different files created by the NTFS file system like $MFT, $Boot, etc.
MFTECmd.exe -f <path-to-$MFT-file> --csv <path-to-save-results-in-csv>

then use the EZviewer tool to view the output of MFTECmd, or to view CSV files

--------------------------------
Deleted files and Data recovery:

Recovering files using Autopsy

--------------------------------
Evidence of Execution

Windows Prefetch files: 
When a program is run in Windows, it stores its information in prefetch (C:\Windows\Prefetch) for future use (.pf files)
contain the last run times of the application, the number of times the application was run, and any files and device handles used by the file
use Prefetch Parser (PECmd.exe) from Eric Zimmerman's tools for parsing Prefetch
PECmd.exe -f <path-to-Prefetch-files> --csv <path-to-save-csv>		#  run Prefetch Parser on a file and save the results in a CSV
PECmd.exe -d <path-to-Prefetch-directory> --csv <path-to-save-csv>


Windows 10 Timeline:
Windows 10 stores recently used applications and files in an SQLite database called the Windows 10 Timeline. 
C:\Users\<username>\AppData\Local\ConnectedDevicesPlatform\{randomfolder}\ActivitiesCache.db
WxTCmd.exe -f <path-to-timeline-file> --csv <path-to-save-csv>

Windows Jump Lists:
Windows introduced jump lists to help users go directly to their recently used files from the taskbar. We can view jumplists by right-clicking an application's icon in the taskbar, and it will show us the recently opened files in that application. This data is stored in the following directory:
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations

include information about the applications executed, first time of execution, and last time of execution of the application against an AppID
use Eric Zimmerman's JLECmd.exe to parse Jump Lists
JLECmd.exe -f <path-to-Jumplist-file> --csv <path-to-save-csv>		# file
JLECmd.exe -d <path-to-Jumplist-file> --csv <path-to-save-csv>		# dir

--------------------------------
File/folder knowledge

Jump Lists

Shortcut Files:
Windows creates a shortcut file for each file opened either locally or remotely. first and last opened times of the file and the path of the opened file
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\
C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\
LECmd.exe -f <path-to-shortcut-files> --csv <path-to-save-csv>

IE/Edge history:
IE/Edge browsing history is that it includes files opened in the system as well, whether those files were opened using the browser or not.
C:\Users\<username>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat

use Autopsy to analyze Web cache data and select Logical Files as a data source.

--------------------------------
External Devices/USB device forensics

Shortcut files

Setupapi dev logs for USB devices
 serial number and the first/last times when the device was connected. 
C:\Windows\inf\setupapi.dev.log

```
===============================================================================
# Linux Forensics
```
cat /etc/os-release
cat /etc/passwd| column -t -s :		# -t (create a table), -s : (delimiter)
/etc/group
/etc/sudoers

Login information:
/var/log/wtmp  		# historical data of logins and boot
/var/log/btmp		# saves information about failed logins

can't be read using cat, less or vim; instead, they are binary files, which have to be read using last.
Last by default, returns the info of /var/log/wtmp. If we want to read another file, we would use -f.
sudo last -f /var/log/wtmp

Authentication logs:
/var/log/auth.log

------------------------------------------------------------------
# System Configuration

Hostname
/etc/timezone		# time zone, also gives an indicator of the general location of the device 
/etc/hosts
/etc/resolv.conf

Network Configuration:
/etc/network/interfaces
ip address show 

Active network connections:
netstat -natp

------------------------------------------------------------------
# Persistence mechanisms
cat /etc/crontab
ls /etc/init.d/		# Services
.Bashrc			# cat ~/.bashrc
When a bash shell is spawned, it runs the commands stored in the .bashrc file.
System-wide settings are stored in /etc/bash.bashrc and /etc/profile files

------------------------------------------------------------------
# Evidence of Execution

cat /var/log/auth.log* | grep -i COMMAND	# Sudo execution history
cat ~/.bash_history 				# Bash history of the logged in user
cat ~/.viminfo					# Vim text editor stores logs for opened files in Vim in the file named .viminfo

------------------------------------------------------------------
# Log files

Syslog
contains messages that are recorded by the host about system activity
cat /var/log/syslog* | head
We can see an asterisk(*) after the syslog. This is to include rotated logs as well. 

Auth logs
information about users and authentication-related logs.
```

===============================================================================
# Autopsy
```
Create/open the case for the data source you will investigate
Select the data source you wish to analyze
Configure the ingest modules to extract specific artefacts from the data source
Review the artefacts extracted by the ingest modules
Create the report

Autopsy case files have a ".aut" file extension.
Autopsy adds metadata about files to the local database, not the actual file contents. 

You can add data sources by using the "Add Data Source" button. Supported Disk Image Formats:
Raw Single (For example: *.img, *.dd, *.raw, *.bin)
Raw Split (For example: *.001, *.002, *.aa, *.ab, etc)
EnCase (For example: *.e01, *.e02, etc)
Virtual Machines (For example: *.vmdk, *.vhd)

Ingest Modules are Autopsy plug-ins. Each Ingest Module is designed to analyze and retrieve specific data from the drive. By default, the Ingest Modules are configured to run on All Files, Directories, and Unallocated Space. 
The results of any Ingest Module you select to run against a data source will populate the Results node in the Tree view, which is the left pane of the Autopsy user interface.

Don't confuse the Results node (from the Tree Viewer) with the Result Viewer (which is the right panel)

```
===============================================================================
# Redline
```
- perform memory analysis and scan for IOCs on an endpoint.

Here is what you can do using Redline:
Collect registry data (Windows hosts only)
Collect running processes
Collect memory images (before Windows 10)
Collect Browser History
Look for suspicious strings

handle is a connection from a process to an object or resource like files, registry keys, resources, etc.
Memory Sections will let you investigate unsigned memory sections used by some processes. Many processes usually use legitimate dynamic link libraries (DLLs), which will be signed. This is particularly interesting because if you see any unsigned DLLs then it will be worth taking a closer look. 

Some of the other important sections you need to pay attention to are:
File System
Registry
Windows Services
Tasks (Threat actors like to create scheduled tasks for persistence)
Event Logs (this another great place to look for the suspicious Windows PowerShell events as well as the Logon/Logoff, user creation events, and others)
ARP and Route Entries (not included in this analysis session)
Browser URL History (not included in this analysis session)
File Download History

If you know when the host compromise or suspicious activity occurred, you can use TimeWrinkles to filter out the timeline to only the events that took place around that time. 
TimeCrunches helps to reduce the excessive amount of data that is not relevant in the table view. A TimeCrunch will hide the same types of events that occurred within the same minute you specified.

You can use OpenIOC Editor and IOC Editor to create indicators of compromise and then match them with the data we analyze

```
===============================================================================
# KAPE
```
 1) collect files and 2) process the collected files as per the provided options.


Target Options:
Windows Prefetch is a forensic artifact for evidence of execution so that we can create a Target for it. Similarly, we can also create Targets for the registry hives. In short, Targets copy files from one place to another.

We can see different .tkape extension files. This is how a Target is defined for KAPE. A TKAPE file contains information about the artifact that we want to collect, such as the path, category, and file masks to collect.

Notice that we have the C:\Windows.old path listed here as well. This path contains files retained after Windows has updated to a new version. For forensic analysis, we can also find interesting historical artifacts from this directory.

Compound Targets include !BasicCollection, !SANS_triage and KAPEtriage

!Disabled
This directory contains Targets that you want to keep in the KAPE instance, but you don't want them to appear in the active Targets list.

!Local
If you have created some Targets that you don't want to sync with the KAPE Github repository, you can place them in this directory. These can be Targets that are specific to your environment. Similarly, anything not present in the Github repository when we update KAPE will be moved to the !Local directory.

------------------------------------------------------------------
Module Options
Modules, in KAPE's lexicon, run specific tools against the provided set of files. 

 MKAPE file tells KAPE about the executable that has to be run, the command line parameters of the executable file, the output export format, and the filename to export to.

The bin directory contains executables that we want to run on the system but are not natively present on most systems.


------------------------------------------------------------------
gkape

Here, the Flush checkbox will delete all the contents of the Target destination, so we have to be careful when using that. We have disabled the Flush checkbox so that it does not delete data already present in the directories. Add %d will append date info to the directory name where the collected data is saved. Similarly, Add %m will append machine info to the Target destination directory. 

------------------------------------------------------------------
KAPE CLI

PowerShell:
kape.exe --tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\target 
Running the above command will collect triage data defined in the KapeTriage Target and save it to the provided destination. However, it will not process it or perform any other activity on the data.

If we were using a Module source, we would have used a >--msource flag in a similar manner to the --tsource flag. But in this case, let's use the Target destination as the Module source. By doing this, we will not need to add it explicitly, and we can move on to adding the Module destination using the --mdest flag:
kape.exe --tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\Target --mdest C:\Users\thm-4n6\Desktop\module
kape.exe --tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\Target --mdest C:\Users\thm-4n6\Desktop\module --module !EZParser


Batch Mode:
we can provide a list of commands for KAPE to run in a file named _kape.cli. Then we keep this file in the directory containing the KAPE binary. When kape.exe is executed as an administrator, it checks if there is _kape.cli file present in the directory. If so, it executes the commands mentioned in the cli file.
--tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\Target --mdest C:\Users\thm-4n6\Desktop\module --module !EZParser

```
===============================================================================
# Volatility
```
vol windows --help

------------------------------------------------------------------
Memory Extraction:

extract a memory from a bare-metal machine.
FTK Imager
Redline
DumpIt.exe
win32dd.exe / win64dd.exe
Memoryze
FastDump

For virtual machines, gathering a memory file can easily be done by collecting the virtual memory file from the host machine’s drive. This file can change depending on the hypervisor used; listed below are a few of the hypervisor virtual memory files you may encounter.
VMWare - .vmem
Hyper-V - .bin
Parallels - .mem
VirtualBox - .sav file *this is only a partial memory file

------------------------------------------------------------------
plugin:

Volatility will automatically identify the host and build of the memory file.
with Volatility3, you need to specify the operating system prior to specifying the plugin to be used, for example, windows.info vs linux.info. 

Windows.cmdline		Lists process command line arguments
windows.drivermodule	Determines if any loaded drivers were hidden by a rootkit
Windows.filescan	Scans for file objects present in a particular Windows memory image
Windows.getsids		Print the SIDs owning each process
Windows.handles		Lists process open handles
Windows.info		Show OS & kernel details of the memory sample being analyzed
Windows.netscan		Scans for network objects present in a particular Windows memory image
Widnows.netstat		Traverses network tracking structures present in a particular Windows memory image.
Windows.mftscan		Scans for Alternate Data Stream
Windows.pslist		Lists the processes present in a particular Windows memory image
Windows.pstree		List processes in a tree based on their parent process ID


------------------------------------------------------------------
Identifying Image Info and Profiles:

imageinfo plugin will take the provided memory dump and assign it a list of the best possible OS profiles. OS profiles have since been deprecated with Volatility3, so we will only need to worry about identifying the profile if using Volatility2; this makes life much easier for analyzing memory dumps.
Note: imageinfo is not always correct and can have varied results depending on the provided dump; use with caution and test multiple profiles from the provided list.
windows.info linux.info mac.info. This plugin will provide information about the host from the memory dump.

python3 vol.py -f <file> windows.info

------------------------------------------------------------------
Listing Processes and Connections

1. python3 vol.py -f <file> windows.pslist
equivalent to the process list in task manager. all current processes and terminated processes with their exit times.

2. psscan
Some malware, typically rootkits, will, in an attempt to hide their processes, unlink itself from the list. This technique of listing processes will locate processes by finding data structures that match _EPROCESS.

3. pstree
list all processes based on their parent process ID

4. netstat; will attempt to identify all memory structures with a network connection.
It is better to use bulk_extractor to extract a PCAP file from the memory file. 

5. dlllist. This plugin will list all DLLs associated with processes at the time of extraction.

6. windows.netscan

7. windows.filescan; see files info and path that are stored in the memory dump

8. windows.mftscan.MFTScan:
have more detailed information like when the file was accessed or modified. timestamps correspond to the Created, Modified, Updated, and Accessed TimeStamps; we can take notes of those.


------------------------------------------------------------------
Volatility Hunting and Detection Capabilities

1. malfind; 
This plugin will attempt to identify injected processes and their PIDs along with the offset address and a Hex, Ascii, and Disassembly view of the infected area. The plugin works by scanning the heap and identifying processes that have the executable bit set RWE or RX and/or no memory-mapped file on disk (file-less malware).

2. python3 vol.py -f <file> windows.yarascan
compare the memory file against YARA rules.

------------------------------------------------------------------
Advance

These plugins is best used once you have further investigated and found potential indicators to use as input for searching and filtering.

1. 
The first evasion technique we will be hunting is hooking; there are five methods of hooking employed by adversaries, outlined below:

SSDT Hooks
IRP Hooks
IAT Hooks
EAT Hooks
Inline Hooks

# python3 vol.py -f <file> windows.ssdt

How SSDT Hooking Works:
SSDT Basics: The SSDT is a table in the Windows kernel that maps system call numbers to the corresponding kernel-mode service routines.
Hooking: An attacker modifies a specific entry in the SSDT to point to their own malicious function.
Redirection: When the hooked system call is invoked, it is redirected to the attacker's code, enabling malicious behavior like hiding processes or files.

The ssdt plugin will search for hooking and output its results. There can be hundreds of table entries that ssdt will dump; you will then have to analyze the output further or compare against a baseline. A suggestion is to use this plugin after investigating the initial compromise and working off it as part of your lead investigation.

2. 
Adversaries will also use malicious driver files as part of their evasion. Volatility offers two plugins to list drivers.

The modules plugin will dump a list of loaded kernel modules; this can be useful in identifying active malware. However, if a malicious file is idly waiting or hidden, this plugin may miss it.
The driverscan plugin will scan for drivers present on the system at the time of extraction. This plugin can help to identify driver files in the kernel that the modules plugin might have missed or were hidden.

------------------------------------------------------------------
python3 vol.py -f ./Investigation-1.vmem -o ./dump windows.memmap.Memmap --pid 1640 --dump


-o dump: Defines the output directory where dumped files or data will be saved. Here, it is named dump.
windows.memmap.Memmap: The Memmap plugin maps the memory regions of a specified process. It shows which parts of memory are allocated to a process and allows dumping those regions.
--dump: Tells Volatility to extract the memory contents of the process and save them to the output directory (dump).
```
===============================================================================
# Critical
```
We can divide the tasks in a Memory forensic task into two main phases: Memory Acquisition and Memory Analysis.

Imaging Tools:
Windows		FTK imager, WinPmem
Linux		LIME
macOS		osxpmem



```

===============================================================================
# Velociraptor
```
Velociraptor is unique because the Velociraptor executable can act as a server or a client and it can run on Windows, Linux, and MacOS.  Velociraptor is also compatible with cloud file systems, such as Amazon EFS and Google Filestore. 

we can use WSL (Windows Subsystem for Linux) to simulate an environment that running Velociraptor as a server in Linux (Ubuntu) and as a client running Windows without needing for virtual machine.

If you wish to interact and deploy Velociraptor locally in your lab, then Instant Velociraptor is for you. Instant Velociraptor is a fully functional Velociraptor system that is deployed only to your local machine.

On server: ./velociraptor-v0.5.8-linux-amd64 --config server.config.yaml frontend -v
On client (CMD), (cd C:\Program Files\Velociraptor): velociraptor-v0.5.8-windows-amd64.exe --config velociraptor.config.yaml client -v

------------------------------------------------------------------
VQL Drilldown
In this view, there is additional information about the client, such as Memory and CPU usage over 24 hours timespan, the Active Directory domain if the client is a domain-joined machine and the active local accounts for the client. 

Collected
Here the analyst will see the results from the commands executed previously from Shell. Other actions, such as interacting with the VFS (Virtual File System), will appear here in Collected. VFS will be discussed later in upcoming tasks.

------------------------------------------------------------------
Creating a new collection

Select Artifacts
Configure Parameters
Specify Resources
Review
Launch

--------
example:
Select Artifacts:
Windows.KapeFiles.Targets 			# are community-created targets and modules

Configure Parameters: select ubuntu
we configure the parameters to include Ubuntu artifacts on WSL

------------------------------------------------------------------
VFS (Virtual File System)
allow inspection of the client’s filesystem

file - uses operating system APIs to access files
ntfs - uses raw NTFS parsing to access low level files
registry - uses operating system APIs to access the Windows registry
artifacts - previously run collections. 

------------------------------------------------------------------
VQL (Velociraptor Query Language)
```
===============================================================================
# TheHive
```
TheHive allows analysts from one organisation to work together on the same case simultaneously. 

permissions:
Note that (1) Organisations, configuration, profiles and tags are global objects. The related permissions are effective only on the “admin” organisation. (2) Actions, analysis and template are available only if the Cortex connector is enabled.
```
===============================================================================
# Intro to Malware Analysis
```
Most of the time, you will have an executable file (also called a binary or a PE file. PE stands for Portable Executable), a malicious document file, or a Network Packet Capture (Pcap)
When malware is analyzed without being executed, it is called Static Analysis.
Dynamic Analysis; Malware faces a dilemma. It has to execute to fulfil its purpose, and no matter how much obfuscation is added to the code, it becomes an easy target for detection once it runs.


Remnux (Reverse Engineering Malware Linux) is a Linux distribution purpose-built for malware analysis.
 
------------------------------------------------------------------
The PE file Header
"pecheck" command is used to check the PE header.
"pe-tree" is a GUI tool for PE header check 

imports:
import function which use windows API or other libraries like RegQueryValue to Query a Windows Registry value. any PE file export functions are exposed to other binaries that can use that function instead of implementing it themselves. Exports are generally associated with Dynamically-Linked libraries (DLL files), and it is not typical for a non-DLL PE file to have a lot of exports. 

sections:
most commonly seen sections in a PE file:
.text: This Section generally contains the CPU instructions executed when the PE file is run. This section is marked as executable.
.data: This Section contains the global variables and other global data used by the PE file.
.rsrc: This Section contains resources that are used by the PE file, for example, images, icons, etc.

------------------------------------------------------------------
Basic Dynamic Analysis

Cuckoo's Sandbox
CAPE Sandbox
Online Sandboxes: Online Cuckoo Sandbox, Any.run ,Intezer, Hybrid Analysis


------------------------------------------------------------------
Anti-analysis techniques

Packing and Obfuscation:
A packer obfuscates, compresses, or encrypts the contents of malware. packed malware will not show important information when running a string search against it

Sandbox evasion:
Long sleep calls:  not to perform any activity for a long time after execution
Footprinting user activity: like if there are any files in the MS Office history or internet browsing history.
User activity detection: wait for user inactivity before performing malicious activity.
Detecting VMs
```
===============================================================================
# Investigating with ELK 101
```
Elastic stack: Elastic stack is the collection of different open source components linked together to help users take the data from any source and in any format and perform a search, analyze and visualize the data in real-time.

Beats is a set of different data shipping agents used to collect data from multiple agents. Like Winlogbeat is used to collect windows event logs, Packetbeat collects network traffic flows.
Logstash collects data from beats, ports or files, etc., parses/normalizes it into field value pairs, and stores them into elasticsearch.
Elasticsearch acts as a database used to search and analyze the data.
Kibana is responsible for displaying and visualizing the data stored in elasticsearch. The data stored in elasticseach can easily be shaped into different visualizations, time charts, infographics, etc., using Kibana.
------------------------------------------------------------------
KQL (Kibana Query Language) 

1. Free text search allows users to search for the logs based on the text-only, the search returns all the logs that contain this term regardless of the place or the field. (The case is matter and wildcard is "*")

2. Logical Operators (AND | OR | NOT)
3. Field-based search: Source_ip : 238.163.231.224    AND     UserName : Suleman
```

===============================================================================
# Incident handling with Splunk
```
index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort - Requests
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data

1. We can display only the logs that contain the username and passwd values in the form_data field by adding form_data=*username*passwd* in the above search.
Search Query: index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" form_data=*username*passwd* | table _time uri src_ip dest_ip form_data

2. Now, let's use Regex.  rex field=form_data "passwd=(?<creds>\w+)" To extract the passwd values only. This will pick the form_data field and extract all the values found with the field. creds.
Search Query:index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)"  | table src_ip creds

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" |table _time src_ip uri http_user_agent creds

Robtex:
Robtex is a Threat Intel site that provides information about IP addresses, domain names, etc.

https://otx.alienvault.com			# whois site
```
===============================================================================
# Atomic Red
```
Test the techniques on Mite attach framework.

Get-Help Invoke-Atomictest.
Invoke-AtomicTest T1566.001 -ShowDetails				# details, different available tests, commands they run, dependencies...
Invoke-AtomicTest T1566.001 -TestNumbers 1 -CheckPrereq			# check if the system met the prereqs
Invoke-AtomicTest T1566.001 -TestNumbers 1				# run the test #1
AtomicTest T1566.001 -TestNumbers 1 -cleanup				# cleanup the artifacts from test #1 
-TestNames								# execute using the complete Atomic Test Name
-TestGuids								# execute using the unique test identifier

```
===============================================================================
# zeek
```
zeekctl				# open the zeekcontrol interactive cli
zeekctl status
zeekctl start 
zeekctl stop 


zeek -C -r sample.pcap 
-r	 Reading option, read/process a pcap file.
-C	 Ignoring checksum errors.
-v	 Version information.


-------------------------------------------
Zeek Logs

Zeek-cut	Cut specific columns from zeek logs. like using "cut" command
cat <file>.log | zeek-cut <field title>


-------------------------------------------
Zeek Signatures

Zeek signatures are composed of three logical paths; signature id, conditions and action. The signature breakdown is shown in the table below;

Signature id		Unique signature name.
Conditions		Header: Filtering the packet headers for specific source and destination addresses, protocol and port numbers.
			Content: Filtering the packet payload for specific value/pattern.
Action			Default action: Create the "signatures.log" file in case of a signature match.
			Additional action: Trigger a Zeek script.


Condition Field	Available Filters:
Header	
src-ip: Source IP.
dst-ip: Destination IP.
src-port: Source port.
dst-port: Destination port.
ip-proto: Target protocol. Supported protocols; TCP, UDP, ICMP, ICMP6, IP, IP6

Content
payload: Packet payload.
http-request: Decoded HTTP requests.
http-request-header: Client-side HTTP headers.
http-request-body: Client-side HTTP request bodys.
http-reply-header: Server-side HTTP headers.
http-reply-body: Server-side HTTP request bodys.
ftp: Command line input of FTP sessions.

Context	
same-ip: Filtering the source and destination addresses for duplication.
Action	event: Signature match message.
Comparison
Operators	==, !=, <, <=, >, >=

NOTE!	 Filters accept string, numeric and regex values.
zeek -C -r sample.pcap -s sample.sig

Zeek signatures use the ".sig" extension.
-C: Ignore checksum errors.
 -r: Read pcap file.
-s: Use signature file. 


example:
signature ftp-username {
    ip-proto == tcp
    ftp /.*USER.*/
    event "FTP Username Input Found!"
}

signature ftp-brute {
    ip-proto == tcp
     payload /.*530.*Login.*incorrect.*/
    event "FTP Brute-force Attempt!"
}


-------------------------------------------
Zeek Scripts | Fundamentals

zeek -C -r smallFlows.pcap dhcp-hostname.zeek 

example:
event dhcp_message (c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
{
print options$host_name;
}

-------------------------------------------
Zeek Scripts | Packages

zkg install package_path
zkg list, zkg remove, zkg refresh, zkg upgrade

```

===============================================================================
# Brim
```


-------------------------------------------
syntax

10.0.0.1                             					# Basic Search: find logs containing this exact IP
192 and NTP                          					# Logical Operators: logs containing both "192" and "NTP"
term1 and/or/not term2              					# Logical Operators: use AND, OR, or NOT between terms
id.orig_h == 192.168.121.40         					# Field Filter: filter logs where source IP equals this
_path == "conn"                     					# Log Type Filter: show only connection (conn) logs
count() by _path                    					# Count by Field: count number of entries per log type
count() by _path | sort -r          					# Sort Results: count and show most frequent log types
cut field1, field2                  					# Cut Fields: display only the specified fields
_path == "conn" | cut id.orig_h, id.resp_p, id.resp_h     		# Field Cut Example: show source IP, destination port and IP
... | uniq                         				 	# Unique Values: remove duplicates from results
... | uniq -c                       					# Unique with Count: show count of each unique row
_path == "conn" | cut id.orig_h, id.resp_h | sort | uniq           	# Communicated Hosts: unique source-destination pairs
... | uniq -c | sort -r                                     		# Frequent Hosts: most common communications
_path == "conn" | cut id.resp_p, service | sort | uniq -c | sort -r   	# Most Active Ports: top destination ports/services
_path == "conn" | cut id.orig_h, id.resp_h, id.resp_p, service | sort id.resp_p | uniq -c | sort -r   	# Port Details: common host-port-service usage
_path == "conn" | cut id.orig_h, id.resp_p, id.resp_h, duration | sort -r duration   			# Long Connections: detect sessions with long duration
_path == "conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes   # Transferred Data: calculate and show total bytes per connection
_path == "dns" | count() by query | sort -r     # DNS Queries: show most frequent domain queries
_path == "http" | count() by uri | sort -r      # HTTP Requests: show most accessed web URIs
_path == "dhcp" | cut host_name, domain         # DHCP Hostnames: list hostname and domain info
_path == "conn" | put classnet := network_of(id.resp_h) | cut classnet | count() by classnet | sort -r   # Suspicious IP Classes: group response IPs by network class
filename != null                    		# File Transfers: find logs where a file was transferred
_path == "dce_rpc" or _path == "smb_mapping" or _path == "smb_files"     	# SMB Activity: detect file sharing and lateral movement
event_type == "alert" or _path == "notice" or _path == "signatures"     	# Alerts & Notices: find known threat or detection logs
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort value.uri	# sort with value of uri

-------------------------------------------


```