## Difficult: Medium ##
### Note: This is a classic boot2root CTF-style room. Make sure to get all the flags.
### Link: https://tryhackme.com/r/room/thelondonbridge
-------------------------------------------------------

Recon:

+ Scan the machine with Nmap and Gobuster:

```bash
nmap -sV -vv -A -p- <IP>

```


```bash
gobuster dir -u <IP> -w /usr/share/wordlists/dirb/common.txt -xtxt -t64

```




