# FTP(21)

### FTP 포트에 대한 서비스 스캔
```nmap -sV -p21 -sC -A 192.168.1.1```

### 서비스 연결 확인
```nc -nv 192.168.1.1 21```<br/>
```telnet 192.168.1.1 21```

### FTP server에서 사용 가능한 모든 파일 다운로드
```wget -m --no-passive ftp://anonymous:anonymous@<IP>```

### FTP가 TLS/SSL 통신할 경우 openssl 사용
```openssl s_client -connect 192.168.1.1:21 -starttls ftp```

# DNS(53)

### 특정 nameserver로 NS 쿼리
```dig ns <domain> @<nameserver>```

### 특정 nameserver DNS Version 쿼리
```dig CH TXT version.bind <nameserver>```

### 특정 nameserver러 ANY 쿼리(공개된 항목 보기)
```dig any <domain> @<nameserver>```

### 특정 nameserver로 AXFR 쿼리
```dig axfr <domain> @<nameserver>```

### 서브 도메인 Brute Forcing
```$ for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.domain.com @<nameserver> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done```<br/>
```$ dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt domain.com```

# SMB(139, 445)

### SMB 포트에 대한 서비스 스캔
```nmap 192.168.1.1 -sV -sC -p139,445```

### SMB Null Session 연결
```smbclient -N -L //<IP>```

### 특정 SMB share 연결
```smbclient //<IP>/<share>```

### 느낌표(`!<cmd>`)를 사용하여 로컬 시스템 명령 실행
```smb: \> !cat prep-prod.txt```

### RPC 클라이언트 연결
```rpcclient -U "" <IP>```

#### 공유 정보 추출
```rpcclient $> netshareenumall```<br/>
```rpcclient $> netsharegetinfo <netname>```<br/>
```rpcclient $> enumdomusers```<br/>
```rpcclient $> queryuser <user_rid>```<br/>
```rpcclient $> querygroup <group_rid>```<br/>
```$ for i in $(seq 500 1100);do rpcclient -N -U "" <IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done```

### Null session을 이용한 SMB shares 열거(Tool)
```smbmap -H <IP>```<br/>
```crackmapexec smb <IP> --shares -u '' -p ''```<br/>
```enum4linux-ng.py <IP> -A```

# NFS(111, 2049)

### NFS 포트에 대한 서비스 스캔
```nmap 192.168.1.1 -p111,2049 -sV -sC```<br/>
```nmap --script nfs* 192.168.1.1 -sV -p111,2049```

### NFS shares 보기
```showmount -e <IP>```

### NFS share를 ./target-NFS에 마운트/언마운트
```mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock```<br/>
```umount ./target-NFS```

# SSH(22)

### SSH 서버 구성 및 알호화 알고리즘 정보
```git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit```<br/>
```ssh-audit.py 192.168.1.1```

### private key를 이용한 SSH 로그인
```ssh -i private.key <user>@<FQDN/IP>```

### SSH 클라이언트 인증방법 지정
```ssh -v 계정@192.168.1.1 -o PreferredAuthentications=password```

# WMI(135)

### Impacket-wmiexec를 이용한 WMI 연결 및 명령 실행
```wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"```

# IMAP, POP3(143, 993, 110, 995)

### IMAP, POP3 포트에 대한 서비스 스캔
```nmap 192.168.1.1 -sV -p110,143,993,995 -sC```

### curl을 이용한 IMAPS service 로그인
```curl -k 'imaps://<FQDN/IP>' --user <user>:<password>```

### openssl을 이용한 IMAPS service 연결
```openssl s_client -connect <FQDN/IP>:imaps```

### openssl을 이용한 POP3S service 연결
```openssl s_client -connect <FQDN/IP>:pop3s```

# R-Services(512, 513, 514)

### R-Services 포트에 대한 서비스 스캔
```nmap -sV -p 512,513,514 192.168.1.1```

### Rlogin 명령으로 로그인
```rlogin 192.168.1.1 -l <user>```

### Rusers 명령으로 인증된 사용자 정보 확인
```rusers -al 192.168.1.1```

# MSSQL(1433)

### MSSQL 포트에 대한 서비스 스캔(hostname, database instance name, software version, named pipes)
```nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 192.168.1.1```

### Windows 인증을 이용한 MSSQL 로그인
```impacket-mssqlclient <user>@<FQDN/IP> -windows-auth```

# MySQL(3306)

### MySQL 포트에 대한 서비스 스캔
```nmap 192.168.1.1 -sV -sC -p3306 --script mysql*```

### MySQL 계정으로 로그인(-p 다음 공백 없음)
```mysql -u <user> -p<password> -h 192.168.1.1```

# Oracle(1521)

### SID Bruteforcing을 위한 서비스 스캔
```nmap -p1521 -sV 192.168.1.1 --open --script oracle-sid-brute```

### Oracle-Tools-setup.sh
```
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```

### odat을 사용하여 모든 정보 수집을 위한 스캔
```./odat.py all -s <FQDN/IP>```

### SQLplus를 이용한 로그인
```sqlplus <user>/<pass>@<FQDN/IP>/<db>```

### Oracle RDBMS File Upload
```./odat.py utlfile -s <FQDN/IP> -d <db> -U <user> -P <pass> --sysdba --putFile C:\\insert\\path file.txt ./file.txt```<br/>
예) ```./odat.py utlfile -s 192.168.1.1 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt```

# SMTP(25)

### SMTP 포트에 대한 서비스 스캔
```nmap 192.168.1.1 -sC -sV -p25```

### SMTP 포트에 대한 Open Relay 스캔
```nmap 192.168.1.1 -p25 --script smtp-open-relay -v```

### Telnet - HELO/EHLO
```telnet 192.168.1.1 25```<br/>
```HELO mail1.domain.com```<br/>
```EHLO mail1```

### Telnet - VRFY로 사용자 열거
```telnet 192.168.1.1 25```<br/>
```VRFY <user>```<br/>
smtp-user-enum 툴 사용) ```smtp-user-enum -w 20 -M VRFY -U ./wordlist.txt -t 192.168.1.1``` 

# SNMP(161, 162)

#### snmpwalk를 이용한 OID 쿼리
```snmpwalk -v2c -c <community string> <FQDN/IP>```

### SNMP service community string Bruteforcing
```onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt <FQDN/IP>```

### braa를 이용한 OID Bruteforcing
```braa <community string>@<FQDN/IP>:.1.*```

# WinRM(5985, 5986)

### WinRM 포트에 대한 서비스 스캔
```nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n```

### evil-winrm을 이용하여 원격 연결
```evil-winrm -i 192.168.1.1 -u <user> -p <password>```

# IPMI(623)

### IPMI 포트에 대한 서비스 스캔
```nmap -sU --script ipmi-version -p 623 192.168.1.1```

### IPMI version 체크(MSF)
```msf6 auxiliary(scanner/ipmi/ipmi_version)```

### IPMI hashes 덤프(MSF)
```msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)```

# Rsync(873)

### Rsync 포트에 대한 서비스 스캔
```nmap -sV -p 873 192.168.1.1```<br/>
```nc -nv 192.168.1.1 873```

### 공유 디렉토리 접근
```rsync -av --list-only rsync://192.168.1.1/<share>```

### 공유된 디렉토리 모든 파일에 대한 동기화
```rsync -av rsync://192.168.1.1/<share>```
<br/><br/>
# RDP(3389)

### RDP 포트에 대한 서비스 스캔
```nmap -sV -sC 192.168.1.1 -p3389 --script rdp*```

### RDP 보안 체크
```sudo cpan```<br/>
```git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check```<br/>
```./rdp-sec-check.pl 192.168.1.1```

### RDP 연결
```xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP>```<br/>
```rdesktop -u <user> -p <password> <FQDN/IP>```
