## Reflect XSS:
+ In the page http://shop.nahamstore.thm, we will check each features.
+ The feature **"Search For Products"** --> there exist the vulnerability XSS by manipulate parameter "q"  we can inject the payload to popup message.
+ Using BurpSuite to look into the source code and we find out the JavaScript variable: "search" and we can escape to get the XSS to work.

![](<Images/Pasted image 20250101164326.png>)

+ We can break out of a JavaScript string with payload: `';alert(document.domain)//`


![](<Images/Pasted image 20250101164633.png>)

+ Look at the source code:

![](<Images/Pasted image 20250110162002.png>)

------------------------------------------------------------------

+ The next when we view the product, we will go to the page "Product".
+ In the first time, we find the vulnerability appear in parameter "id" and we can inject the payload to pop up the XSS:

![](<Images/Pasted image 20250101221631.png>)

+ The second time, we can use param "name" to see what happen with this page:

![](<Images/Pasted image 20250101222358.png>)

+ We saw the title is change, check source code and we know that HTML tag `<title></title>` 

![](<Images/Pasted image 20250101222558.png>)

+ So now we can inject the payload into parameter "name" but we need to trick to escape the HTML tag. We have the payload:
`</title>Merch<script>alert(document.domain)</script>`

![](<Images/Pasted image 20250101222931.png>)

+ And we can see what happen in the source code:

![](<Images/Pasted image 20250101223012.png>)

------------------------------------------------------------------

+ In the page product, we have the field "**Discount Code**". When we use BurpSuite cap the action, we can see the potential parameter "discount".

![](<Images/Pasted image 20250113181807.png>)

+ When we add to basket successfully, we see the message "Item Added To Basket". Check the Request in BurpSuite:

![](<Images/Pasted image 20250113184648.png>)

--> We can manipulate param "discount" to inject the payload that can introduce an XSS vulnerability.

+ We will craft the payload and combine the param "discount" into the request GET.
+ After try many payloads, we found out the right payload. We can use payload in `https://portswigger.net/web-security/cross-site-scripting/cheat-sheet 
+ We can use the some of danger attributes can trigger JavaScript:

![](<Images/Pasted image 20250117214528.png>)

+ Check the source code:

![](<Images/Pasted image 20250113185723.png>)

+ We can see the `value=""` which we will input the payload into so we can use double quote and  `>`  to escape and combine with payload.
+ Now we had the available payload: `"><a onfocus=alert(document.domain) autofocus tabindex=1>` 

![](<Images/Pasted image 20250113190403.png>)

+ Check the source code again:

![](<Images/Pasted image 20250113190910.png>)

------------------------------------------------------------------

+ When we access the page which does not exist, we receive the error message and are direct "Page Not Found"
![](<Images/Pasted image 20250110175335.png>)

+ Check the source code:

![](<Images/Pasted image 20250110175455.png>)

--> We've found the page `/profile` is reflected in error message so we can inject payload to create reflect XSS.

+ Using the payload `<h1>` XSS:  `<h1 onclick="alert(1)" style=display:block>test</h1>`

![](<Images/Pasted image 20250110180051.png>)

+ Check source code again:

![](<Images/Pasted image 20250110180225.png>)

------------------------------------------------------------------

+ In the page **/return**, we have the form to "Return Your Items" and we can manipulate "Return Information" to inject payload from that create XSS.
+ Look at the source code:
![](<Images/Pasted image 20250102154945.png>)
+ We have  `<textarea></textarea>` to create a blank field to write return_info. We can use trick to escape HTML tag: `</textarea><script>alert(document.domain)</script>`
![](<Images/Pasted image 20250102155506.png>)

![](<Images/Pasted image 20250102155633.png>)

------------------------------------------------------------------

+ In the page http://marketing.nahamstore.thm, we will enumerate the page first with Gobuster to find the hidden directories:

```bash
zicco@z-a:~$ gobuster dir -u http://marketing.nahamstore.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t64
===============================================================
/6e6055bd53afb9b6e4394d76e35838c9 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
/cfa5301358b9fcbe7aa45b1ceea088c6 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
/f05221fb72cfbc1b85256abe00683bc4 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
/cdd9dc973c4bf6bc852564ca006418a0 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
/64356135653039353435383166306330 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
/c097c40d3f9a53ff5c7ddfc2f7f1c05c (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
/64356135653039353435613034323230 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
.........
```

--> Try to access the directories, we have the error message and parameter "error" that is reflect the message "Campaign Not Found":

![](<Images/Pasted image 20250101213831.png>)

+ We're able to manipulate the parameter "error" to inject the payload XSS:

![](<Images/Pasted image 20250101214437.png>)
------------------------------------------------------------------
+ Access page http://nahamstore.thm:8000/admin/8d1952ba2b3c6dcd76236f090ab8642c. In the feature "Edit", we can generate reflect XSS in field "Campaign Name"

![](<Images/Pasted image 20250110180600.png>)

+ Update successfully, we can pop up the XSS

![](<Images/Pasted image 20250110180734.png>)

------------------------------------------------------------------

## Stored XSS:

+ When we checkout the product successfully, we created the "Order". Check the "Order" in **/account**.

![](<Images/Pasted image 20250113191549.png>)

+ We can see "Order Details" that contain the information which were stored. We focus "User Agent" which is the potential target to exploit. We've known "User Agent" is the HTTP Header and we can inject payload into "User-Agent" in HTTP Request to create a Stored XSS.
+ We add new item in /basket and checkout. Using BurpSuite to capture the request:

![](<Images/Pasted image 20250113192353.png>)
--> It stored the new Order and when we access the Oder we created, it will pop up the XSS.

![](<Images/Pasted image 20250113192543.png>)

+ Check the source code:

![](<Images/Pasted image 20250113192624.png>)
------------------------------------------------------------------