# Difficult: Easy #
## Note: Welcome to the web application of U.A., the Superhero Academy.
### Link: https://tryhackme.com/r/room/yueiua

---------------------------------------------------------------------------

## Recon:
+ Scan the machine with Nmap and Gobuster:

```bash
nmap -sV -vv -A -p- <IP>
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 58:2f:ec:23:ba:a9:fe:81:8a:8e:2d:d8:91:21:d2:76 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4WNbSymq7vKwxstoKDOXzTzNHnE4ut9BJPBlIb44tFvtMpfpXDF7Bq7MT9q4CWASVfZTw763S0OrtvpBFPpN/4eOvlircakFfkR3hZk7dHOXe8+cHXDth90XnMa2rq5CfxwinqP/Mo67XcpagbpU9O5lCatTMPWBUcEhIOXY8aUSMkmN6wRYSxdI40a4IYsjRqkqsdA6yaDQBSx+ryFRXwS9+kpUskAv452JKi1u2H5UGVX862GC1xAYHapKY24Yl6l5rTToGqTkobHVCv6t9dyaxkGtc/Skoi2mkWE/GM0SuqtbJ9A1qhSrfQRNpcIJ6UaVhDdUeO3qPX2uXPyLrY+i+1EgYEsRsxD5ym0bT1LPby8ONPduBEmZfnNoN5IBR05rQSSHhj349oNzDC4MRn2ygzOyx0n0c7wqffaAuohbu0cpeAcl5Nwb/Xw42RABDFQx08CttjNmtPMK/PqFt+H4nubyp7P8Pwctwi3wLf2GbU1lNgT0Ewf2GnfxY5Bs=
|   256 9d:f2:63:fd:7c:f3:24:62:47:8a:fb:08:b2:29:e2:b4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC+IqWgEnT5Asc+8VrYsQACkIjP+2CKuoor+erbKjpKwM8+X+1TPuwG56O6LxOLXeS2/pFjv9PBFI1oqHKa4GNw=
|   256 62:d8:f8:c9:60:0f:70:1f:6e:11:ab:a0:33:79:b5:5d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHQa5m2TxGI3a9ZwhAd0zWsAYwCsYANdo6fgpS8XiJKL
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: U.A. High School
|_http-server-header: Apache/2.4.41 (Ubuntu)
OS fingerprint not ideal because: maxTimingRatio (1.694000e+00) is greater than 1.4
```


```bash
gobuster dir -u http://<IP> -w /usr/share/wordlist/dirb/common.txt -xtxt -t64
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.hta.txt             (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.htpasswd.txt        (Status: 403) [Size: 278]
/.htaccess.txt        (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://<IP>>/assets/]
/index.html           (Status: 200) [Size: 1988]
/server-status        (Status: 403) [Size: 278]
Progress: 9228 / 9230 (99.98%)
===============================================================
Finished
===============================================================
```

--> Try access /assets/ we've seen nothing so we will continue to scanning  /assets/

```bash
gobuster dir -u http://<IP>/assets/ -w /usr/share/wordlist/dirb/common.txt -xtxt,php,html -t64
/images               (Status: 301) [Size: 322] [--> http://<IP>/assets/images/]
/index.php            (Status: 200) [Size: 0]
```

--> Try to access /images we've recived the message "Forbidden" because we don't have the permission to access into the page.
 
 + In this case, we've accessed /index.php so we can think that we try to query directly above the url.
 + We try some common parameters like ?page or ?cmd:  

![alt text](image-1.png)

--> We've done successfully so we've known that is the vulnerability Upload Fille.
Form that we can upload webshell into the server and RCE.

+ Now upload file shell and RCE the target:

![alt text](image-2.png)

![alt text](image-3.png)




