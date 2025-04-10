# NMAP

### Nmap address scanning
#### Scan 단일 IP
```nmap 192.168.1.1```

#### Scan 멀티 IP
```nmap 192.168.1.1 192.168.1.2```

#### Scan IP 범위
```nmap 192.168.1.1-254```

#### Scan IP 대역
```nmap 192.168.1.0/24```

### Nmap 스캐닝 기술
#### TCP SYN port scan (root 권한일 경우 기본)
```nmap -sS 192.168.1.1```

#### TCP connect port scan (root 권한이 아닐 경우 기본)
```nmap -sT 192.168.1.1```

#### UDP port scan (-sS 보다 느림)
```nmap -sU 192.168.1.1```

#### TCP ACK port scan
```nmap -sA 192.168.1.1```

### Nmap Host Discovery
#### port scanning 제외. Host discovery only.
```nmap -sn 192.168.1.1```<br/>
예) ```nmap 10.129.1.0/24 -sn | grep for | cut -d" " -f5```

#### host discovery 제외. Port scan only.
```nmap -Pn 192.168.1.1```

#### DNS resolution 제외
```nmap -n 192.168.1.1```

### Nmap port scan
#### Port scan from service name
```nmap 192.168.1.1 -p http, https```

#### 특정 port scan
```nmap 192.168.1.1 -p 80,9001,22```

#### All ports
```nmap 192.168.1.1 -p-```

#### Fast scan (상위 100개 port)
```nmap -F 192.168.1.1```

#### Scan top ports
```nmap 192.168.1.1 -top-ports 200```

### Nmap OS, 서비스 detection
#### 공격적인 scanning (Opsec에 비추). Enables OS detection, version detection, script scanning, and traceroute.
```nmap -A 192.168.1.1```

#### 서비스 Version detection scanning
```nmap -sV 192.168.1.1```

#### 서비스 Version detection 강도(0-9) 설정
```nmap -sV -version-intensity 7 192.168.1.1```

#### OS detecion
```nmap -O 192.168.1.1```

#### OS detection 집중 스캔
```nmap -O -osscan-guess 192.168.1.1```

### Nmap 타이밍
#### 가장 느린(0) 스캔, IDS 우회
```nmap 192.168.1.1 -T 0```

#### 기본값은 -T 3

#### 가장 빠른(5) 스캔; 빠른 네트워크 환경에서 사용
```nmap 192.168.1.1 -T 5```

#### 최소 number 이상 packet 전송
```nmap 192.168.1.1 --min-rate 1000```

### NSE Scripts
#### single script. Example banner
```nmap 192.168.1.1 --script=banner```

#### NSE script with arguments
```nmap 192.168.1.1 --script=banner --script-args <arguments>```

### Firewall 우회 및 Spoofing
#### IP packet fragment 스캔(including ping scans)
```nmap -f 192.168.1.1```

#### mtu size(8, 16, 32, 64) 지정
```nmap 192.168.1.1 --mtu 32```

#### IP sfoop scans
```nmap 192.168.1.1 -D 192.168.1.11, 192.168.1.12, 192.168.1.13, 192.168.1.14```

#### IP sfoop 랜덤(개수) 지정
```nmap 192.168.1.1 -D RND:5```

#### 소스 IP 수동 설정
```nmap 192.168.1.1 -S 192.168.1.200 -e tun0```

#### DNS, ARP ping, ICMP scan 모두 비활성
```nmap 192.168.1.1 -p 445 -n --disable-arp-ping -Pn```

#### DNS 프록싱(신뢰할 수 있는 DNS 서버를 지정 또는 소스포트를 53으로 설정)
```nmap 192.168.1.1 --dns-server <ns>```<br/>
```nmap 192.168.1.1 --source-port 53```

#### 필터 우회하여 연결 시도
예) ```ncat -nv --source-port 53 192.168.1.1 50000```

#### 최대한 탐지 우회 스캔
예1) ```nmap 192.168.1.1 -p- -sS -Pn -n --disable-arp-ping --source-port 53 -D RND:5 --min-rate 5000```<br/>
예2) ```nmap 192.168.1.1 -p 22,80,50000 -sS -sV -Pn -n --disable-arp-ping --source-port 53 -D RND:5```

### Output
#### 일반 output file
```nmap 192.168.1.1 -oN scan.txt```
- .nmap파일 확장자를 포함한 일반 출력(-oN)
- .gnmap파일 확장자를 포함한 Grep 가능한 출력(-oG)
- .xml파일 확장자를 포함한 XML 출력(-oX)
- 모든 형식 출력(-oA)


# Rustscan

### 기본 스캔
```rustscan -a 192.168.1.11```

### 멀티 IP 스캔
```rustscan -a 192.168.1.11,192.168.1.12```

### 대역 스캔
```rustscan -a 192.168.1.0/30```

### 스캔 시간 제한
```rustscan -a 192.168.1.11 --ulimit 3000```

### 멀티 포트 스캔
```rustscan -a 192.168.1.11 -p 53,80,121,65535```

### 포트 범위 스캔
```rustscan -a www.host.com --range 1-1000```
