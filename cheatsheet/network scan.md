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
#### TCP SYN port scan (Default)
```nmap -sS 192.168.1.1```

#### TCP connect port scan (Default without root privilege)
```nmap -sT 192.168.1.1```

#### UDP port scan
```nmap -sU 192.168.1.1```

#### TCP ACK port scan
```nmap -sA 192.168.1.1```

### Nmap Host Discovery
#### port scanning 제외. Host discovery only.
```nmap -sn 192.168.1.1```

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

#### Fast scan 100 ports
```nmap -F 192.168.1.1```

#### Scan top ports
```nmap 192.168.1.1 -top-ports 200```

### Nmap OS, service detection
#### 공격적인 scanning(Opsec에 비추). Enables OS detection, version detection, script scanning, and traceroute.
```nmap -A 192.168.1.1```

#### Version detection scanning
```nmap -sV 192.168.1.1```

#### Version detection 강도(0-9) 설정
```nmap -sV -version-intensity 7 192.168.1.1```

#### OS detecion
```nmap -O 192.168.1.1```

#### OS detection에 집중 스캔
```nmap -O -osscan-guess 192.168.1.1```

### Nmap 타이밍
#### 가장 느린(0) 스캔, IDS 우회
```nmap 192.168.1.1 -T0```

#### 가장 빠른(5) 스캔; 빠른 네트워크 환경에서 사용
```nmap 192.168.1.1 -T5```

#### 초당 <number> 이상 packet 전송
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

### Output
#### 일반 output file
```nmap 192.168.1.1 -oN scan.txt```


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
