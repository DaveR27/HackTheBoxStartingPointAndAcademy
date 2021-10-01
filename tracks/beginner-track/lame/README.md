# Lame
 ```bash
export IP=10.10.10.3
 ```

## Enumeraiton

```bash
nmap -sC -sV -oA lame_nmap -Pn $IP
```

```bash
gobuster dir -u http://$IP/ -w /usr/share/dirb/wordlists/common.txt -x "php, html, txt, pdf, xml, json, js" > gobuster.txt
```

try ftp login, there is nothing there leaving samba as the only target

look up the samba version and find an exploit for root on metasploit

get flags
root -> ebdab11fd3feb90e784862ce8b9533f6
usr -> 7ffa03685b97c665b579dc5cbc5a1b6f
