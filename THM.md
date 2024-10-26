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

Using a Yara rule is simple. Every yara command requires two arguments to be valid, these are:
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


Conditions
We have already used the (true) and (any of them)
<= less than or equal to
>= more than or equal to
!= not equal to

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



Cuckoo Sandbox is an automated malware analysis environment. This module allows you to generate Yara rules based upon the behaviours discovered from Cuckoo Sandbox.




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
use the "Edit" or the "right-click" menu to mark/unmark packets. Marked packets will be shown in black regardless of the original colour representing the connection type.marked packets will be lost after closing the capture file. 

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
# 
```

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

UserAssist: Windows keeps track of applications launched by the user using Windows Explorer for statistical purposes in the User Assist registry keys. These keys contain information about the programs launched, the time of their launch, and the number of times they were executed. programs that were run using the command line can't be found in the User Assist keys. 
NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count
ShimCache: ShimCache is a mechanism used to keep track of application compatibility with the OS and tracks all applications launched on the machine. also called (AppCompatCache). (SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache)
or use, AppCompatCache Parser: AppCompatCacheParser.exe --csv <path to save output> -f <path to SYSTEM hive for data parsing> -c <control set to parse>

AmCache: stores additional data related to program executions. execution path, installation, execution and deletion times, and SHA1 ,  C:\Windows\appcompat\Programs\Amcache.hve, Amcache.hve\Root\File\{Volume GUID}\

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
