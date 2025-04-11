# WHOIS

### 도메인 정보 수집
```whois domain.com```
<br/><br/>
# DNS

## DNS Bruteforce 도구
| 도구                                                      | 설명                                                                   |
| ------------------------------------------------------- | -------------------------------------------------------------------- |
| [dnsenum](https://github.com/fwaeytens/dnsenum)         | 하위 도메인을 발견하기 위한 사전 공격과 무차별 대입 공격을 지원하는 포괄적인 DNS 열거 도구입니다.            |
| [fierce](https://github.com/mschwager/fierce)           | 와일드카드 감지와 사용하기 쉬운 인터페이스를 갖춘 재귀적 하위 도메인 검색을 위한 사용자 친화적인 도구입니다.        |
| [dnsrecon](https://github.com/darkoperator/dnsrecon)    | 여러 DNS 정찰 기술을 결합하고 사용자 정의 가능한 출력 형식을 제공하는 다재다능한 도구입니다.               |
| [amass](https://github.com/owasp-amass/amass)           | 하위 도메인 발견에 초점을 맞춘 활발하게 유지 관리되는 도구로, 다른 도구와 광범위한 데이터 소스와의 통합으로 유명합니다. |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | 다양한 기술을 사용해 하위 도메인을 찾는 간단하면서도 효과적인 도구로, 빠르고 가벼운 검색에 적합합니다.           |
| [puredns](https://github.com/d3mondev/puredns)          | 강력하고 유연한 DNS 무차별 대입 공격 도구로, 결과를 효과적으로 해결하고 필터링할 수 있습니다.              |

### dnsenum 도구 명령
```dnsenum --enum domain.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r```

### DNS 서버에 domain.com 도메인 전체 zone transfer(axfr)을 요청
```dig axfr @<DNS> domain.com```

## Virtual Host 검색 도구
| 도구                                                   | 설명                                                        | 특징                                                |
| ---------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------- |
| [gobuster](https://github.com/OJ/gobuster)           | 디렉토리/파일 무차별 대입 공격에 자주 사용되는 다목적 도구이지만, 가상 호스트 검색에도 효과적입니다. | 빠르고 다양한 HTTP 메소드를 지원하며, 사용자 정의 단어 목록을 사용할 수 있습니다. |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | Gobuster와 유사하지만 Rust 기반으로 구현되었으며, 속도와 유연성으로 유명합니다.        | 재귀, 와일드카드 검색 및 다양한 필터를 지원합니다.                     |
| [ffuf](https://github.com/ffuf/ffuf)                 | `Host`헤더 를 퍼징하여 가상 호스트를 검색하는 데 사용할 수 있는 또 다른 빠른 웹 퍼저입니다.  | 사용자 정의 가능한 단어 목록 입력 및 필터링 옵션.                     |

### gobuster 도구 명령
```gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain```

사용 예)
```
sudo vi /etc/hosts
...
<IP주소>  domain.com
:wq

gobuster vhost -u http://domain.com:44045 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

## Certificate Transparency 도구
| 도구                                  | 주요 특징                                                         | 사용 사례                                      | 장점                          | 단점                       |
| ----------------------------------- | ------------------------------------------------------------- | ------------------------------------------ | --------------------------- | ------------------------ |
| [crt.sh](https://crt.sh/)           | 사용자 친화적인 웹 인터페이스, 도메인별 간편 검색, 인증서 세부 정보 및 SAN 항목 표시.          | 빠르고 쉬운 검색, 하위 도메인 식별, 인증서 발급 내역 확인.        | 무료이며 사용하기 쉽고 등록이 필요하지 않습니다. | 필터링 및 분석 옵션이 제한적입니다.     |
| [Censys](https://search.censys.io/) | 인터넷에 연결된 기기를 위한 강력한 검색 엔진이며, 도메인, IP, 인증서 속성별로 고급 필터링이 가능합니다. | 인증서에 대한 심층 분석, 잘못된 구성 식별, 관련 인증서 및 호스트 찾기. | 광범위한 데이터와 필터링 옵션, API 접근.   | 등록이 필요합니다(무료 단계도 가능합니다). |

### crt.sh 조회 명령
```curl -s "https://crt.sh/?q=domain.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u```
