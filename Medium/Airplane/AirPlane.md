# -----AIR PLANE ROOM----- #
## Difficult: Medium

   ![alt text](image.png)

### Note: Are you ready to fly?

### https://tryhackme.com/r/room/airplane

--------------------------------------------
## RECON: ##

+ Scan the target machine with Nmap:

```bash
nmap -sV -vv -A -p- -T4 <IP>

```

+ After scan port of IP target we've known the website port 8000 run with domain airplane.thm so we need add domain into /etc/hosts to run the website.




