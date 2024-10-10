Difficult: Medium
---------------------------------
Note: Identify the critical security flaw in the most powerful and trusted network monitoring software on the market, that allows an user authenticated execute remote code execution.
---------------------------------
+ Scan ports and enumurate the directories:
 Nmap <IP>
 --Port 22/ssh
 --Port 80
 --Port 443
 --Port 389
 --Port 5667
+ Enumurate the directories:
 --/index.html
 --/index.php
 --/nagios
 --/javascript
+ Go to the port 80 http
+ We have got the note: "Welcome to elements.
					Ag - Hg - Ta - Sb - Po - Pd - Hg - Pt - Lr"

-> We research and know that is the elements in the periodic table.
+ Comnbine the periodic table, we have the atomic numbers:
Argon (Ag) - 47
Mercury (Hg) - 80
Tantalum (Ta) - 73
Antimony (Sb) - 51
Polonium (Po) - 84
Palladium (Pd) - 46
Mercury (Hg) - 80
Platinum (Pt) - 78
Lawrencium (Lr) - 103

+ We have the Decimal ASCII: 47-80-73-51-84-46-80-78-103
+ Decode: DEC /N -> /PI3T.PNg
+ We have the hidden file that is the format file .png but that is diffrent as usual.
+ Download it and start to analyze it.

Steganography:
+ We will use the tool name is "GIMP" to see the file.
+ Use "exiftool" to enumurate the information:
 --We have the name of the Artist "Piet Mondrian"
+ Research and we got the page name npiet, related to the piet programing language
+ Use the page or tool npiet to stegano the file .PNg
-Link: "https://www.bertnase.de/npiet/"
+ Use the Gimp to export file to .png or ppm. After that we will stegano the file in the npiet.
+ We have got the credential: nagiosadmin%n3p3UQ&9BjLp4$7uhWdY

Exploit:
+ Research the vulnearable related Nagios XI 5.5.6
+ We have the Exploit in the Metasploit - CVE-2019-15949
+ exploit/linux/http/nagios_xi_plugins_check_plugin_authenticated_rce.

END!!!