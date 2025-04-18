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
- [WindscribeService 명명된 파이프 권한 확대](https://www.exploit-db.com/exploits/48021)

### WindscribeService Named Pipe Permissions 체크
```accesschk.exe -accepteula -w \pipe\WindscribeService -v```




