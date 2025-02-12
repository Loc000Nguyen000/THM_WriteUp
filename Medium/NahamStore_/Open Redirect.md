+ When we are able to RCE the server, we can access the source code website in `Website.php`.
+ We find the potential function to introduce the vulnerability "Open Redirect".
+ The first, the function:
```bash
private static function redirectTo($resp){
        if( isset($_GET["redirect_url"])  ){
            $resp = $_GET["redirect_url"];
        }
        return $resp;
    }
```

+ The param **"redirect_url"** is not sanitized and filtered by any function. 
    --> All features use parameter **"redirect_url"**  to redirect will cause the vuln "Open Redirect".

![](<Images/Pasted image 20250116174301.png>)
--> When we login the website we can manipulate the param "redirect_url" to direct to other page.

------------------------------------------------------------------

+ The second function:
```bash
 public static function home(){
        if( isset($_GET["r"]) ){
            \View::redirect($_GET["r"]);
        }
    }
```

--> We can see the parameter **"r"** is not sanitized and filtered so we can manipulate the param **"r"** to redirect to another website. Especially, this param run in home() page so we can redirect from home page to other page.

![](<Images/Pasted image 20250116175345.png>)
------------------------------------------------------------------

