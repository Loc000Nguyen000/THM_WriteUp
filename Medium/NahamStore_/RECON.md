## Domain and SubDomain:
+ The domain we will enumerate subdomains : 
```bash
<IP> nahamstore.thm(.com) 
```

+   When we discover the subdomain, we will need to add an entry into your /etc/hosts (Linux) file pointing to your deployed machine box.
+  Using a combination of subdomain enumeration, brute force, content discovery and fuzzing find all the subdomains.
+ Find all subdomains with tool enumeration Gobuster or fuzzing FFUF: 

```bash
$ gobuster dns -d nahamstore.thm -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t64 --wildcard
===============================================================
Found: www.nahamstore.thm

Found: shop.nahamstore.thm

Found: marketing.nahamstore.thm

Found: stock.nahamstore.thm

Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

```
+ All the current subdomains: 

```bash
+ www.nahamstore.thm
+ shop.nahamstore.thm
+ marketing.nahamstore.thm
+ stock.nahamstore.thm
```

+ We continue using OSINT(Open-source intelligence) tools to scan more the subdomain. We can use some popular website OSINT as https://crt.sh, https://subdomainfinder.c99.nl, ...
+ We chose some one to scan domain:

![](<Images/Pasted image 20250107172145.png>)

![](<Images/Pasted image 20250107172207.png>)

--> We find another subdomain: http://nahamstore-2020.nahamstore.com

+ When we find the way to RCE initial server http://nahamstore.thm, we will find another subdomain:

![](<Images/Pasted image 20250116171121.png>)

--> The last 2 subdomain: `http://nahamstore-2020-dev.nahamstore.thm & http://internal-api.nahamstore.thm .

### Scan Ports:
+ Using Nmap to scan all ports of target:
```bash
$ nmap -sV -vv -A -p- -T4 <IP>
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 84:6e:52:ca:db:9e:df:0a:ae:b5:70:3d:07:d6:91:78 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDk0dfNL0GNTinnjUpwRlY3LsS7cLO2jAp3QRvFXOB+s+bPPk+m4duQ95Z6qagERl/ovdPsSJTdiPXy2Qpf++KJw0UHOR6/dhjaZI4ba2DvFWfvFzfh9Jrx7rvzrOj0i0kUUwot9WmxhuoDfvTT3S6LmuFw7SAXVTADLnQIJ4k8URm5wQjpj86u7IdCEsIc126krLk2Nb7A3qoWaID72Xl0ttvsEHq8LPfdEhPQQyefozVtOJ50I1Tc3cNVsz/wLnlLTaVui2oOXd/P9/4hIDiIeOI0bSgvrTToyjjTKH8CDet8cmzQDqpII6JCvmYhpqcT5nR+pf0QmytlUJqXaC6T
|   256 1a:1d:db:ca:99:8a:64:b1:8b:10:df:a9:39:d5:5c:d3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC/YPu9Zsy/Gmgz+aLeoHKA1L5FO8MqiyEaalrkDetgQr/XoRMvsIeNkArvIPMDUL2otZ3F57VBMKfgydtBcOIA=
|   256 f6:36:16:b7:66:8e:7b:35:09:07:cb:90:c9:84:63:38 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPAicOmkn8r1FCga8kLxn9QC7NdeGg0bttFiaaj11qec
80/tcp   open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     session: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: NahamStore - Home
8000/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


### Enumerate Directories:

+ Scan all directories with Gobuster:
Port 80(HTTP):
```bash
$ gobuster dir -u http://nahamstore.thm -w /usr/share/wordlists/dirb/common.txt -xtxt -t64
===============================================================
/basket               (Status: 200) [Size: 2465]
/css                  (Status: 301) [Size: 178] [--> http://127.0.0.1/css/]
/js                   (Status: 301) [Size: 178] [--> http://127.0.0.1/js/]
/logout               (Status: 302) [Size: 0] [--> /]
/login                (Status: 200) [Size: 3099]
/register             (Status: 200) [Size: 3138]
/returns              (Status: 200) [Size: 3628]
/robots.txt           (Status: 200) [Size: 13]
/robots.txt           (Status: 200) [Size: 13]
/search               (Status: 200) [Size: 3351]
/staff                (Status: 200) [Size: 2287]
/uploads              (Status: 301) [Size: 178] [--> http://127.0.0.1/uploads/]
Progress: 9228 / 9230 (99.98%)
===============================================================
Finished
===============================================================
```

Port 8000:
```bash
$ gobuster dir -u http://nahamstore.thm:8000/ -w /usr/share/wordlists/dirb/common.txt -xtxt,php -t64
===============================================================
[+] Url:                     http://nahamstore.thm:8000/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 302) [Size: 0] [--> /admin/login]
/robots.txt           (Status: 200) [Size: 30]
/robots.txt           (Status: 200) [Size: 30]
Progress: 13842 / 13845 (99.98%)
===============================================================
Finished
===============================================================
```

+ Enumerate the subdomain `http://nahamstore-2020-dev.nahamstore.thm/`:
```bash
$ gobuster dir -u http://nahamstore-2020-dev.nahamstore.thm/ -w /usr/share/wordlists/dirb/common.txt -t64
===============================================================
/api                  (Status: 302) [Size: 0] [--> /api/]
Progress: 4614 / 4615 (99.98%)
===============================================================
```

```bash
$ gobuster dir -u http://nahamstore-2020-dev.nahamstore.thm/api/ -w /usr/share/wordlists/dirb/common.txt -t64
===============================================================
/customers            (Status: 302) [Size: 0] [--> /api/customers/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
```

+ Access `http://nahamstore-2020-dev.nahamstore.thm/api/customers/?customer_id=2` :
```bash
{"id":2,"name":"Jimmy Jones","email":"jd.jones1997@yahoo.com","tel":"501-392-5473","ssn":"521-61-6392"}
```

------------------------------------------------------------------
