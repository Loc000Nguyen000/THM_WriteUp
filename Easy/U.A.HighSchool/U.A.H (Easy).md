# Difficult: Easy #
## Note: Welcome to the web application of U.A., the Superhero Academy.
### Link: https://tryhackme.com/r/room/yueiua

---------------------------------------------------------------------------

## Recon:
+ Scan the machine with Nmap and Gobuster:

```bash
nmap -sV -vv -A -p- <IP>

```


```bash
gobuster dir -u http://<IP> -w /usr/share/wordlist/dirb/common.txt -xtxt -t64

```