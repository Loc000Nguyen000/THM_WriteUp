# Umbrella #
### Note: Breach Umbrella Corp's time-tracking server by exploiting misconfigurations around containerisation.

![alt text](image-2.png)

### https://tryhackme.com/r/room/umbrella ###

---------------------------------------------------------

### RECON: ###

+ Scan the machine with Nmap:

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f0:14:2f:d6:f6:76:8c:58:9a:8e:84:6a:b1:fb:b9:9f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDafqZxGEa6kz/5SjDuHy4Hs02Ns+hQgiygUqck+jWWnO7A8+mzFovIR0z76dugf8sTv9P6hq++1nNkPvvdovIkCQ00Ci9VrNyRePh9ZjXUf6ohbRLa9bJ45zHSY3Icf56IeuIy3TVn6d05ed5EtaTjAYA8KyCvwm2nDZQ7DH081jnL1g1uJ4aeeA/IlNXYLV610u7lkQem8VwXQWEs7F8JH6RMX8/8oGe7oBnpvKUeACtB9NXN/5tGsiMXqx7+JB8nfpMRIyLiXA7HjV9S7mmtmBduJ5EyfvX5hdwSCEYF1E7/YowqF5KbTpmZeDI9vJharuKqB97iu1h87u1qc37zT7emxD0QxCOAT3mKGXB26u159ZjAvjJ2EUhSjfbgjTx0s0w2bysXJNrpw5oS1AMm/XD6dSCRfg0kS2LzwDFJvv3dCy56bdOdW+Xe/tkBgvNio11OiP8E2qvdZ+cSgnXi+d8m2TkFUJEfavQPES7iXuZ3gMEaVPdbILVz3zRGh58=
|   256 8a:52:f1:d6:ea:6d:18:b2:6f:26:ca:89:87:c9:49:6d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBASqbHaEEuWmI5CrkNyO/jnEdfqh2rz9z2bGFBDGoHjs5kyxBKyXoDSq/WBp7fdyvo1tzZdZfJ06LAk5br00eTg=
|   256 4b:0d:62:2a:79:5c:a0:7b:c4:f4:6c:76:3c:22:7f:f9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDDy2RWM3VB9ZBVO+OjouqVM+inQcilcbI0eM3GAjnoC
3306/tcp open  mysql   syn-ack ttl 62 MySQL 5.7.40
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_5.7.40_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-12-22T10:04:49
| Not valid after:  2032-12-19T10:04:49
| MD5:   c512:bd8c:75b6:afa8:fde3:bc14:0f3e:7764
| SHA-1: 8f11:0b77:1387:0438:fc69:658a:eb43:1671:715c:d421
|
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40
|   Thread ID: 7
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, SupportsTransactions, IgnoreSigpipes, SwitchToSSLAfterHandshake, FoundRows, ODBCClient, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, SupportsCompression, InteractiveClient, DontAllowDatabaseTableColumn, LongColumnFlag, LongPassword, SupportsLoadDataLocal, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: La\x08\x1D;0J\x11B,&\x04\x161D\x0DoKz4
|_  Auth Plugin Name: mysql_native_password
5000/tcp open  http    syn-ack ttl 62 Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8080/tcp open  http    syn-ack ttl 62 Node.js (Express middleware)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Login
```


