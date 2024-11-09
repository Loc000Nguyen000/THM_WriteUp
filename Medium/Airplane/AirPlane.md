# -----AIR PLANE ROOM----- #
## Difficult: Medium

   ![alt text](image.png)

### Note: Are you ready to fly?

### https://tryhackme.com/r/room/airplane

--------------------------------------------
## RECON: ##

+ Scan the target machine with Nmap and Gobuster:

```bash
nmap -sV -vv -A -p- -T4 <IP>

```

```bash
Gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/commom.txt -xtxt,php,html -t64

```
