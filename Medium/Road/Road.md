## Difficult: Medium 
### Note: Inspired by a real-world pentesting engagement
-------------------------------------------------------
### Link: https://tryhackme.com/r/room/road


## Reconnaissance:

+ Scan the machine with Nmap and Gobuster:

```bash
nmap -sV -vv -A -p- -T4 <IP>

```

```bash
gobuster dir -u <IP> -w /usr/share/wordlists/dirb/common.txt -xtxt -t64

```





