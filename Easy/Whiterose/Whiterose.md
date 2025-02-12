![alt text](image.png)
### Link: https://tryhackme.com/room/whiterose
--------------------------------------------------------------------
### Recon:
```bash
$nmap -sV -vv -A -T4 -p- <IP>
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCddbej9ZSf75uuDvLDeym5AYM+loP/3W862HTWjmksh0UuiuIz8UNTrf3ZpgtBej4y3E3EKvOmYFvJHZpFRV/hQBq1oZB3+XXVzb5RovazcnMgvFxI4y5nCQM8qTW09YvBOpzTyYmsKjVRJOfLR+F87g90vNdZ/u8uVl7IH0B6NmhGlCjPMVLRmhz7PuZih38t0WRWPruEY5qGliW0M3ngZXL6MmL1Jo146HtM8GASdt6yV9U3GLa3/OMFVjYgysqUQPrMwvUrQ8tIDnRAH1rsKBxDFotvcfW6mJ1OvojQf8PEw7iI/PNJZWGzkg+bm4/k+6PRjO2v/0V98DlU+gnn
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNMBr/zXjVQItMqdVH12/sZ3rIt2XFsPWRCy4bXCE7InUVg8Q9SVFkOW2LAi1UStP4A4W8yA8hW+1wJaEFP9ffs=
|   256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIdJAkvDVqEAbac77yxYfkM0AU8puWxCyqCBJ9Pd9zCi
80/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
```






