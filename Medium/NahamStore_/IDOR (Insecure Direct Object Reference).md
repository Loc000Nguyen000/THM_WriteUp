+ When we checkout the products in /basket and choose the **"Shipping Address"**. Using BurpSuite:

![](<Images/Pasted image 20250115112843.png>)

--> We've found the param "==address_id==" and we can change the value of "address_id" with value we want.
+ We change by value = 3 and  now we can see the information "Shipping Address" of another users:

![](<Images/Pasted image 20250115113333.png>)

+ Impact: We can access to the sensitive files which we are not permitted to access.
------------------------------------------------------------------

+ When we created the Order successfully, access /account/orders/{number_order} and we can see the information of Order we created. 
+ We have the feature **"PDF Receipt"** to print the receipt of order we created

![](<Images/Pasted image 20250115114408.png>)

+ Idea: we are able to change the parameter of "Order" to access the sensitive Order of another users.
+ Using BurpSuite to cap the request "PDF Receipt":

![](<Images/Pasted image 20250115114634.png>)

+ We try to change the param **"id"** = 3 and we have the error message:

![](<Images/Pasted image 20250115114803.png>)

+ We try to add more param "user_id":

![](<Images/Pasted image 20250115114912.png>)

--> We still have the error message.

+ We try to encode the **"user_id"**. After try many times, we've found that we will encode `3&user_id=3` by URL encode:

![](<Images/Pasted image 20250115115925.png>)

--> We found the sensitive file "Order" of another users.
![](<Images/Pasted image 20250115120018.png>)

------------------------------------------------------------------
