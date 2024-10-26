===============================================================================
# Windows basics

```
------------------------------------------------------------------
Permisions:

Folders:
Full control			# Allow everything + changing the permission
Modify				# Allow all below
Read & Execute			# Read and execute files and folders in the folder
List folder contents		# List and execute file and folders, cat read files
Read				# Read files and folders
Write				# Add files and folders

Files
Full control
Modify
Read & Execute
Read
Write				# Write to the file

------------------------------------------------------------------
info:

location of all the executables is C:\Windows\System32, except for Explorer.exe (which is C:\Windows)



```
===============================================================================
# Tools
```
MSConfig			# startup issues, Boot, Services, Tools
VSS				# Volume Shadow Copy


```
===============================================================================
# commands
```
winver.exe			# windows version info
launch
hostname			# computer name
whoami				# name of the logged-in user
ipconfig
ipconfig /?			# help manual
cls				# clear
net help user			# see the help information for "net user" command
control /name Microsoft.WindowsUpdate				# open windows update
C:\WINDOWS\System32\cmd.exe /C echo someting > file.txt  	# echo something to file.txt via command line

net user			# list all the users
net user /Domain		# list all AD users

|| Displays IP configuration information			| ipconfig /all ipconfig /?
|| Displays system information					| systeminfo
|| Displays network statistics					| netstat -ano
|| Displays MAC address						| getmac /v
|| Displays Windows version					| ver
|| Displays Windows version and build				| winver
|| Lists running processes					| tasklist
|| Terminates processes
/IM stands for "Image Name"
The /F flag forces termination of the process
taskkill /IM notepad.exe /F 
taskkill /PID process_id /F
taskkill /IM chrome* /F
taskkill /PID PID1 / PID PID2 /F

|| Scans and repairs system files				| sfc /scannow
|| Checks disk for errors					| chkdsk C: /f

16 diskpart
|| Manages disks and partitions
| diskpart then list disk

17 format
|| Formats a disk
| format C: /fs:ntfs

18 хсору
|| Copies files and directories
| copy C: \source D:\dest /E

19 robocopy
|| Advanced file copy utility
| robocopy C:\source D: \dest /E


|| Creates a new directory
| md NewFolder

|| Removes a directory
| rd OldFolder

24 del
|| Deletes files
| del C:\file.txt

25 сору
|| Copies files
| copy C: \file.txt D: \
26
move
|| Moves files
| move C:\file.txt D:\
27
|| ren
| Renames files or directories
ren oldname.cxt newname.txt

28 type
|| Displays contents of a text file
| type C:\file.txt

29 find
|| Searches for a text string in files
| find "error" C:\log.txt

30 findstr
|| Searches for strings in files
| ipconfig /all | findstr DNS

|| Sort the content of a file alphabetically
| sort < names.txt

32 comp
|| Compares contents of two files
| comp filel.txt file2.txt


33 fc
|| Compares files and displays differences
| fe filel.txt file2.txt


|| Displays directory structure graphically
| tree C:\

35 attrib
|| Changes file attributes
| attrib +r C:\file.txt

36 cipher
|| Displays or alters file encryption (efs)
| cipher /e C: \SecretFolder

37 compact
|| Displays or alters file compression
compact /c C: \folder		# compress 
compact /u C: \folder		# uncompress

38 powercig
|| Manages power settings
| powercig /energy

39
shutdown
|| Shuts down or restarts computer
| shutdown /r /t 0

40 gpupdate
|| Updates Group Policy settings
| gpupdate /force

41 gpresult
|| Displays Group Policy results
| gpresult /r


44 net start
|| Starts a network service
| net start "Print Spooler"

45 net stop
|| Stops a network service
| net stop "Print Spooler"

46 netsh
|| Network configuration tool
| netsh wlan show profiles


47

|| Manages Windows services with sc
sc query
sc query state= all
state= all: Shows all services (both running and stopped).
state= active: Shows only services that are currently running.
state= inactive: Shows only services that are currently stopped.

48 reg
|| Manages registry
| reg query HKLM\Software

49 runas
|| Runs a program as a different user
| runas /user:Admin cmd

50 schtasks
|| Schedules commands and programs
schtasks /create /tn "MyTask" /tr notepad.exe /sc daily

schtasks: The command-line tool for scheduling tasks in Windows.
/create: Specifies that a new scheduled task should be created.
/tn "MyTask": Assigns the name "MyTask" to the scheduled task.
/tr notepad.exe: Sets the action to run the notepad.exe application.
/sc daily: Sets the schedule to run the task daily.
schtasks /create /tn "MyTask" /tr notepad.exe /sc daily /st 09:00
/st specify the time

|| wmic (Windows Management Instrumentation Command-line)
It is a powerful Windows utility that can be used for both legitimate system administration tasks and potentially abused by attackers.

This retrieves basic OS information:
wmic os get name, version, buildnumber

This lists installed software:
wmic product get name, version

This executes a malicious Power Shell script on a remote system:
wmic /node: "victim_ip" process call create "powershell. exe -enc base64_encoded_payload"

Malware persistence:
wmic startup create
name="malware", command="C: \malw
are. exe"
This adds malware to the startup folder.
Evasion technique:
wmic process where
name="antivirus.exe" delete
Attackers may try to terminate security software.


52 assoc
53 ftype
@ Send
Windows Management Instrumentation
Command-line,
It is a powerful Windows utility that can be used for both legitimate system administration tasks and potentially abused by attackers.
Displays or modifies file extension associations
Displays or modifies file types
54 driverquery
Displays installed device drivers
55 msinfo32
Displays system information
56 mmc
Opens Microsoft Management Console
57 eventvwr
Opens Event Viewer
58 services.msc Opens Services management console
in/harunseker/

51. wmic

This retrieves basic OS information.
wmic os get name, version, buildnumber

Software inventory:
wmic product get name, version
This lists installed software.

Remote code execution:
wmic /node: "victim_ip" process call create "powershell. exe
-enc base64_encoded_payload"
This executes a malicious Power Shell script on a remote system.

Malware persistence:
wmic startup create
name="malware", command="C: \malw
are. exe"
This adds malware to the startup folder.

Evasion technique:
wmic process where
name="antivirus.exe" delete
Attackers may try to terminate security software.

52. assoc .txt
ftype txtfile
driverquery
msinfo32
mmc
eventvwr
services.msc


59 devmgmt .msc
Opens Device Manager
devmgmt .msc

60 diskmgmt.msc
61 taskmgr
Opens Disk Management
Opens Task Manager
diskmgmt.msc
taskmgr




62
perfmon
Opens Performance Monitor
perfmon

63 resmon
Opens Resource Monitor
resmon

64 msconfig
Opens System Configuration
msconfig

65 control
Opens Control Panel
control

66 mstsc
Opens Remote Desktop Connection
mstsc
67
cleanmgr
Opens Disk Cleanup
cleanmgr
68
defrag C:
Defragments a drive
defrag C:
69
fsutil
fsinfo drives
File system utility
fsutil fsinfo drives

70 path
Displays or sets PATH environment variable
path

71 set
Displays, sets, or removes environment variables
set

72 echo
Displays messages or turns command echoing on/off
echo Hello World

73 cls
Clears the screen
cls

74 query
Displays information about processes that are running on a Remote Desktop
Session Host (RD Session Host) server.
query process *
To show all processes

```
