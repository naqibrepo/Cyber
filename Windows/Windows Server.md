# Windows Server


==========================================================================
# Basics
```
|| disable/enable administrator user 				| net user administrator /active:yes ... (or no)
|| Check the current execution policy				| Get-ExecutionPolicy
|| Set the execution policy (to allow running scripts)		| Set-ExecutionPolicy RemoteSigned

|| service commands:
net stop sshd
net start sshd 
Restart/Stop/Start-Service -Name sshd
Get-Service
Get-Service | Where-Object { $_.Status -eq 'Running' }
Get-Service | Where-Object {$_.DisplayName -like "*WireGuard*"}

|| Restart the Server						| Restart-Computer
|| See installed roles and features				| Get-WindowsFeature | Where-Object { $_.Installed -eq $true }

netstat -aon
netstat -aon | findstr LISTENING
netstat -an | findstr LISTENING


tasklist | findstr 4940						| PID


netstat -aon | findstr LISTENING | ForEach-Object { 
    $fields = $_ -split "\s+"; 
    $procId = $fields[-1]; 
    $port = $fields[1]; 
    $app = (tasklist /fi "PID eq $procId" | Select-String -Pattern $procId); 
    Write-Output "Port: $port is being used by Process: $app" 
}


netstat -aon | findstr LISTENING | ForEach-Object { 
    $fields = $_ -split "\s+"; 
    $procId = $fields[-1]; 
    $app = (tasklist /fi "PID eq $procId" | Select-String -Pattern $procId); 
    $appName = $app -split "\s+" | Select-Object -First 1;
    Write-Output "$appName $procId"
}





```

==========================================================================
# Installation
```
| install/add features				| Add-WindowsCapability
| Install a package from PowerShell Gallery	| Install-Package -Name "PackageName"
| current path setting				| CMD: path, PowerShell: $env:path


```

==========================================================================
# Policies
```
|| Deny Log on Locally				| Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment
| Deny users from logging in a computer trough local interface (not local users),  we can add local users (Local account) to deny list as well

|| Deny log on through Remote Desktop Services 	| Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment
| Deny users from logging in a computer remotely, we can add local users (Local account or |BUILTIN\Users|) to deny list as well 

|| Accounts: Administrator account status	| Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
| Enable/Disable Administrator account

|| Local Users and Groups			| Computer Configuration > Preferences > Control Panel Settings > Local Users and Groups 
|  Update, add, remove, and replace local users and group through GPO


|| Password Policy and Lockout Policy 		| Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies

|| Audit Policy					| Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Audit Policy
| Audit and log management

|| Configure Automatic Updates			| Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates


|| 



```


==========================================================================
# Firewall
```
|| Allow ping from the network			| netsh advfirewall firewall add rule name="Allow ICMPv4 from Local Network" protocol=icmpv4:8,any dir=in action=allow remoteip=192.168.1.0/24
|| Delete the added firewall rule		| netsh advfirewall firewall delete rule name="Allow ICMPv4 from Local Network"

|| Confirm the SSH Firewall rule is configured 
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}

||

```



==========================================================================
# Network
```
| get network info				| Get-NetIPAddress





```


==========================================================================
# Petential Vuln
```
| Dynamic DNS updates				| it causes the dns to be updated dynamiclty by untrusted sources
| 

```

==========================================================================
# User, Group, Computers

```
Import-Module ActiveDirectory


Get-LocalGroupMember -Group "Administrators"

net:
|| add user to docker-user group			|  net localgroup docker-users <user> /add	

Local: 
|| list local users					| Get-LocalUser
|| see the Administrators group				| net localgroup Administrators		
|| create new local user				| New-LocalUser -Name "NewUser" -Password (ConvertTo-SecureString "Password" -AsPlainText -Force)	
|| Change local user's pass				| net user Administrator <NewPassword>|
|| Change local user's pass				| Set-LocalUser -Name "ExistingUser" -Password (ConvertTo-SecureString "NewPassword" -AsPlainText -Force) 



AD:
User:
|| Creating a New User					| New-ADUser -Name "John Doe" -GivenName "John" -Surname "Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@yourdomain.com" -Path "OU=Users,DC=yourdomain,DC=com" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true

|| Modifying an Existing User				| Set-ADUser -Identity "jdoe" -Surname "Smith"
|| Remove-ADUser -Identity "jdoe"			| Remove-ADUser -Identity "jdoe"
|| Enabling or Disabling a User Account			| (Disable or) Enable-ADAccount -Identity "jdoe"


|| Change the User Password				| net user "Username" "NewPassword" /domain
|| Reset Password 					| Set-ADAccountPassword -Identity "Username" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword" -Force)
|| Change the User Password				| Set-ADAccountPassword -Identity "username" -NewPassword (ConvertTo-SecureString "NewPassword" -AsPlainText -Force)
|Require Password Change at Next Logon			| Set-ADUser -Identity "jdoe" -ChangePasswordAtLogon $true

Group:
|| Creating a New Group					| New-ADGroup -Name "SSHUsers" -GroupScope Global -Path "OU=Groups,DC=yourdomain,DC=com"
|| Adding Users to a Group				| Add-ADGroupMember -Identity "SSHUsers" -Members "jdoe"
|| Removing Users from a Group				| Remove-ADGroupMember -Identity "SSHUsers" -Members "jdoe" -Confirm:$false

Computer:
|| Creating a New Computer Account			| New-ADComputer -Name "NewComputer" -Path "OU=Computers,DC=yourdomain,DC=com"
|| Remove-ADComputer -Identity "NewComputer"		| Remove-ADComputer -Identity "NewComputer"


Searching for Users and Groups: 
|| find a user by their username	| Get-ADUser -Identity "jdoe"
|| list all members of a specific group	| Get-ADGroupMember -Identity "SSHUsers"

Permissions Management:
|| set permissions for a user on a specific object:
$acl = Get-Acl "AD:OU=Users,DC=yourdomain,DC=com"
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("jdoe", "GenericRead", "Allow")
$acl.AddAccessRule($rule)
Set-Acl "AD:OU=Users,DC=yourdomain,DC=com" $acl

Get the current permissions for the OU (in this case, OU=Users).
Create a new permission rule that allows user jdoe to read information in this OU.
Add that permission rule to the current list of permissions.
Set the modified permissions back on the OU so that jdoe has the new access rights.

```

==========================================================================
# Domain Info Enum
```
CMD:
net user
net user /domain 				# list all domain users 
net user zoe.marshall /domain 			# list the info about single user
net group /domain 				# all groups 
net group “group name” /domain 			# single group
net accounts /domain 				# password policy

PowerShell:
|| Getting Domain Information				| Get-ADDomain
|| Getting Domain Controllers				| Get-ADDomainController -Filter *
Get-ADUser -Identity <username> -Server <DC Domain name> -Properties * 			# everything in properties of the user
Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table	# The -Filter parameter is used to specify a condition for retrieving users.
Get-ADGroup -Identity Administrators -Server za.tryhackme.com
Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com


```

==========================================================================
# SSH
```
|| see if the ssh feature is available and its state (installed or not)		| Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'	
|| Install ssh server								| Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
|| Install ssh client								| Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
|| Start the sshd service							| Start-Service sshd
|| Change service startup type							| Set-Service -Name sshd -StartupType 'Automatic'
|| Confirm the Firewall rule is configured					|
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}

|| Uninstall the OpenSSH Server							| Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0


# Config:
|| The system-wide configuration file at 					| programdata\ssh\ssh_config
|| A user's configuration file at						| %userprofile%\.ssh\config
|| A different configuration file might be specified by launching 		| sshd.exe -f file.config
|| set the default shell to be powershell.exe					| New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
|| Allow/deny users/groups 							| AllowGroups, AllowUsers, DenyGroups, DenyUsers - examples:
DenyUsers contoso\admin@192.168.2.23				# contoso is the domain short name of contoso.local
DenyUsers john?contoso*						# user - domain, (user or group)?domain*, to avoid conflict with Linux syntax 
AllowUsers user@192.168.2.23					# user - host, by default denies all others
DenyUsers contoso\*						# deny all in contoso.local 
DenyUsers *							# deny all, not only domain
AllowGroups contoso\sshusers contoso\serveroperators		# allow users of these two groups
AllowGroups sshusers						# members of this group, not a domain group

```

==========================================================================
# Docker
```
Docker doesn't start automatically after windows rebooted
enable Intel VT before installing docker on VMware
prepare windows for docker by installing runtime or run the below command while docker is running in administrative privilege:
& $Env:ProgramFiles\Docker\Docker\DockerCli.exe -SwitchDaemon .

restart rules for containers					# only when first building the container (ex. --restart=no)
no: Do not restart the container if it stops.
on-failure: Restart the container only if it exits with a non-zero exit code.
always: Always restart the container regardless of the exit status.
unless-stopped: Restart the container unless it was explicitly stopped

```

==========================================================================# Remove CA
```
1. Uninstall Web Enrollment Feature
Remove-WindowsFeature -Name ADCS-Web-Enrollment

2. Uninstall the CA Role
Remove-WindowsFeature -Name AD-Certificate

3. (Optional) Remove CA Database and Files
Remove-Item -Path "C:\Windows\System32\CertLog\*" -Recurse -Force

4. (Optional) Clean Up Active Directory
Get-ADObject -Filter {name -like "*<CA_Name>*"} | Remove-ADObject -Confirm:$false

5. Restart the Server
Restart-Computer

```


