# Avenger Writeup

![alt text](image.png)

## Summary
- Think outside the box, unleash your inner prankster, and find unconventional solutions to outwit your opponents.
- Just a final reminder that `AV` is enabled, and everything should be patched!

## Table of Contents
- [Overview](#overview)
- [Recon & Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Privilege Escalation](#privilege-escalation)


## Recon & Enumeration

+ Scan open ports with `Nmap`:
```
nmap -sS -A -vv -T4 -p- avenger.tryhackme
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: Index of /
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 3.5K  2022-06-15 16:07  applications.html
| 177   2022-06-15 16:07  bitnami.css
| -     2023-04-06 09:24  dashboard/
| 30K   2015-07-16 15:32  favicon.ico
| -     2023-06-27 09:26  gift/
| -     2023-06-27 09:04  img/
| 751   2022-06-15 16:07  img/module_table_bottom.png
| 337   2022-06-15 16:07  img/module_table_top.png
| -     2023-06-28 14:39  xampp/
|_
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      syn-ack ttl 125 Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Index of /
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 3.5K  2022-06-15 16:07  applications.html
| 177   2022-06-15 16:07  bitnami.css
| -     2023-04-06 09:24  dashboard/
| 30K   2015-07-16 15:32  favicon.ico
| -     2023-06-27 09:26  gift/
| -     2023-06-27 09:04  img/
| 751   2022-06-15 16:07  img/module_table_bottom.png
| 337   2022-06-15 16:07  img/module_table_top.png
| -     2023-06-28 14:39  xampp/
|_
445/tcp   open  microsoft-ds? syn-ack ttl 125
3306/tcp  open  mysql         syn-ack ttl 125 MariaDB 5.5.5-10.4.28
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.4.28-MariaDB
|   Thread ID: 216
|   Capabilities flags: 63486
|   Some Capabilities: Speaks41ProtocolNew, Speaks41ProtocolOld, SupportsTransactions, LongColumnFlag, InteractiveClient, DontAllowDatabaseTableColumn, Support41Auth, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, FoundRows, SupportsLoadDataLocal, IgnoreSigpipes, ODBCClient, SupportsCompression, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: O_r?#.]l'wIDXl9rX?sF
|_  Auth Plugin Name: mysql_native_password
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
|_ssl-date: 2025-08-23T09:25:39+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=gift
| Issuer: commonName=gift
| rdp-ntlm-info: 
|   Target_Name: GIFT
|   NetBIOS_Domain_Name: GIFT
|   NetBIOS_Computer_Name: GIFT
|   DNS_Domain_Name: gift
|   DNS_Computer_Name: gift
|   Product_Version: 10.0.17763
|_  System_Time: 2025-08-23T09:25:29+00:00
5985/tcp  open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp  open  tcpwrapped    syn-ack ttl 125
47001/tcp open  http          syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49681/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
```

+ Access /gift --> we redirect to blog Wordpress. Enumerate wordpress with `Wpscan`