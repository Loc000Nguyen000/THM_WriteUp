+ Using BurpSuite when we load the main page http://nahamstore.thm we will see the URL file path that load the image of product:

![](<Images/Pasted image 20250106193101.png>)

+ Access /product/picture/?file=....

![](<Images/Pasted image 20250106193255.png>)

+ We will try access /lfi/flag.txt which information was provided the first time but not success.

![](<Images/Pasted image 20250106193757.png>)

+ Now we can combine the vuln Path Traversal to exploit LFI. The first, we will use payload: 
 `../../../../../lfi/flag.txt` 
---> Still not success.

+ We add more dot and slash for payload: `....//....//....//....//....//lfi/flag.txt`

![](<Images/Pasted image 20250106194149.png>)

+ Check again in BurpSuite:

![](<Images/Pasted image 20250106194239.png>)

--> Working!!!