+ Access the feature **"Stock Check"**, we can see the parameter **"server"** resolves the url "stock.nahamstore.thm". 
	
	--> We are able to test the vuln SSRF in there but first we failed to test SSRF with **"blacklist-based"** input filters (special IP like 127.0.0.1 or localhost,etc).
	 
+ So idea we continue testing SSRF with **"whitelist-based"** input filters, we try to combine characters by using `@` and `#` 
+ We can use the cheat sheet bypass url of Portswigger: `https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet`
+ We input the Allowed hostname and Attacker hostname:

![](<Images/Pasted image 20250205160657.png>)

+ Using the BurpSuite to fuzz the Payload to find the right Payload. After fuzzing, we found the right payload: `stock.nahamstore.thm%20%26%40nahamstore.thm%23%20%40nahamstore.thm`

![](<Images/Pasted image 20250205160746.png>)

+ When we RCE the server, we've found the last subdomain which we can't access. This is `http://internal-api.nahamstore.thm` so we will use the SSRF vuln to view an API that shouldn't be available.

![](<Images/Pasted image 20250205161552.png>)

+ Access successfully, we can view `order`:

![](<Images/Pasted image 20250205161851.png>)
------------------------------------------------------------------
