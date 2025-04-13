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

