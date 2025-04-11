# 1.WHOIS

### 도메인 정보 수집
```whois domain.com```
<br/><br/>
# 2.DNS

### DNS Tools
```dig domain.com```<br/>
```nslookup domain.com```<br/>
```host domain.com```
<br/><br/>
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

### DNS 서버에 도메인 전체 zone transfer(axfr)을 요청
```dig axfr @<DNS> domain.com```
<br/><br/>
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
<br/><br/>
## Certificate Transparency 도구
| 도구                                  | 주요 특징                                                         | 사용 사례                                      | 장점                          | 단점                       |
| ----------------------------------- | ------------------------------------------------------------- | ------------------------------------------ | --------------------------- | ------------------------ |
| [crt.sh](https://crt.sh/)           | 사용자 친화적인 웹 인터페이스, 도메인별 간편 검색, 인증서 세부 정보 및 SAN 항목 표시.          | 빠르고 쉬운 검색, 하위 도메인 식별, 인증서 발급 내역 확인.        | 무료이며 사용하기 쉽고 등록이 필요하지 않습니다. | 필터링 및 분석 옵션이 제한적입니다.     |
| [Censys](https://search.censys.io/) | 인터넷에 연결된 기기를 위한 강력한 검색 엔진이며, 도메인, IP, 인증서 속성별로 고급 필터링이 가능합니다. | 인증서에 대한 심층 분석, 잘못된 구성 식별, 관련 인증서 및 호스트 찾기. | 광범위한 데이터와 필터링 옵션, API 접근.   | 등록이 필요합니다(무료 단계도 가능합니다). |

### crt.sh 조회 명령
```curl -s "https://crt.sh/?q=domain.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u```
<br/><br/>
# 3.Fingerprinting

### curl 명령
```curl -I inlanefreight.com```

### Wafw00f 툴 명령
```
pip3 install git+https://github.com/EnableSecurity/wafw00f
wafw00f inlanefreight.com
```

### Nikto 툴 명령
```
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program
chmod +x ./nikto.pl
```
```nikto -h <domain> -Tuning b```
<br/><br/>
# 4.Crawling

### Scrapy 툴(ReconSpider) 명령
```
pip3 install scrapy
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip
python3 ReconSpider.py http://domain.com
```
<br/><br/>
# 5.Search Engine 검색

### 검색 연산자
| 연산자                  | 운영자 설명                             | 예                                                   | 예시 설명                                                           |
| :------------------- | :--------------------------------- | :-------------------------------------------------- | :-------------------------------------------------------------- |
| `site:`              | 결과를 특정 웹사이트나 도메인으로 제한합니다.          | `site:example.com`                                  | example.com에서 공개적으로 접근 가능한 모든 페이지를 찾아보세요.                       |
| `inurl:`             | URL에 특정 용어가 포함된 페이지를 찾습니다.         | `inurl:login`                                       | 모든 웹사이트의 로그인 페이지를 검색하세요.                                        |
| `filetype:`          | 특정 유형의 파일을 검색합니다.                  | `filetype:pdf`                                      | 다운로드 가능한 PDF 문서를 찾으세요.                                          |
| `intitle:`           | 제목에 특정 용어가 포함된 페이지를 찾습니다.          | `intitle:"confidential report"`                     | "기밀 보고서" 또는 이와 비슷한 제목이 붙은 문서를 찾아보세요.                            |
| `intext:`또는`inbody:` | 페이지 본문 내에서 용어를 검색합니다.              | `intext:"password reset"`                           | "비밀번호 재설정"이라는 용어가 포함된 웹 페이지를 식별합니다.                             |
| `cache:`             | 웹 페이지의 캐시된 버전을 표시합니다(가능한 경우).      | `cache:example.com`                                 | example.com의 캐시된 버전을 보면 이전 콘텐츠를 볼 수 있습니다.                       |
| `link:`              | 특정 웹페이지에 링크된 페이지를 찾습니다.            | `link:example.com`                                  | example.com에 링크되는 웹사이트를 식별합니다.                                  |
| `related:`           | 특정 웹페이지와 관련된 웹사이트를 찾습니다.           | `related:example.com`                               | example.com와 유사한 웹사이트를 찾아보세요.                                   |
| `info:`              | 웹 페이지에 대한 정보 요약을 제공합니다.            | `info:example.com`                                  | example.com의 제목과 설명 등 기본적인 세부 정보를 알아보세요.                        |
| `define:`            | 단어나 문구의 정의를 제공합니다.                 | `define:phishing`                                   | 다양한 출처에서 "피싱"의 정의를 알아보세요.                                       |
| `numrange:`          | 특정 범위 내에서 숫자를 검색합니다.               | `site:example.com numrange:1000-2000`               | example.com에서 1000에서 2000 사이의 숫자가 포함된 페이지를 찾아보세요.               |
| `allintext:`         | 본문에 지정된 단어가 모두 포함된 페이지를 찾습니다.      | `allintext:admin password reset`                    | 본문에 "admin"과 "password reset"이 모두 포함된 페이지를 검색합니다.               |
| `allinurl:`          | URL에 지정된 모든 단어가 포함된 페이지를 찾습니다.     | `allinurl:admin panel`                              | URL에 "admin"과 "panel"이 포함된 페이지를 찾으세요.                           |
| `allintitle:`        | 제목에 지정된 단어가 모두 포함된 페이지를 찾습니다.      | `allintitle:confidential report 2023`               | 제목에 "기밀", "보고서", "2023"이 포함된 페이지를 검색하세요.                        |
| `AND`                | 모든 용어가 반드시 존재해야 하므로 검색 결과가 좁아집니다.  | `site:example.com AND (inurl:admin OR inurl:login)` | example.com의 관리자 또는 로그인 페이지를 찾아보세요.                             |
| `OR`                 | 해당 용어가 포함된 페이지를 포함시켜 검색 결과를 확대합니다. | `"linux" OR "ubuntu" OR "debian"`                   | Linux, Ubuntu 또는 Debian을 언급하는 웹 페이지를 검색하세요.                     |
| `NOT`                | 지정된 용어가 포함된 결과를 제외합니다.             | `site:bank.com NOT inurl:login`                     | 로그인 페이지를 제외한 bank.com의 페이지를 찾으세요.                               |
| `*`(와일드카드)           | 모든 문자나 단어를 나타냅니다.                  | `site:socialnetwork.com filetype:pdf user* manual`  | socialnetwork.com에서 PDF 형식의 사용자 매뉴얼(사용자 가이드, 사용자 핸드북)을 검색해 보세요. |
| `..`(범위 검색)          | 지정된 숫자 범위 내에서 결과를 찾습니다.            | `site:ecommerce.com "price" 100..500`               | 전자상거래 웹사이트에서 100~500달러 사이의 제품을 찾아보세요.                           |
| `" "`(따옴표)           | 정확한 구문을 검색합니다.                     | `"information security policy"`                     | "정보 보안 정책"이라는 문구가 정확하게 언급된 문서를 찾으세요.                            |
| `-`(빼기 기호)           | 검색 결과에서 해당 용어를 제외합니다.              | `site:news.com -inurl:sports`                       | 스포츠 관련 콘텐츠를 제외한 뉴스 기사를 news.com에서 검색해 보세요.                      |

### Google Dorking
- 로그인 페이지 찾기:
    - `site:example.com inurl:login`
    - `site:example.com (inurl:login OR inurl:admin)`
- 노출된 파일 식별:
    - `site:example.com filetype:pdf`
    - `site:example.com (filetype:xls OR filetype:docx)`
- 구성 파일 찾기:
    - `site:example.com inurl:config.php`
    - `site:example.com (ext:conf OR ext:cnf)`(구성 파일에 일반적으로 사용되는 확장자를 검색합니다)
- 데이터베이스 백업 위치:
    - `site:example.com inurl:backup`
    - `site:example.com filetype:sql`
<br/><br/>
# 6. Wayback Machine 검색
```https://web.archive.org/ 접속하여 사이트 스냅샷 검색```
<br/><br/>
# 7. Auto Recon Framework
- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon) : SSL 인증서 검사, Whois 정보 수집, 헤더 분석, 크롤링과 같은 다양한 작업을 위한 다양한 모듈을 제공하는 Python 기반 정찰 도구입니다. 모듈식 구조로 특정 요구 사항에 맞게 쉽게 사용자 정의할 수 있습니다.
- [Recon-ng](https://github.com/lanmaster53/recon-ng) : 다양한 정찰 작업을 위한 다양한 모듈이 있는 모듈식 구조를 제공하는 Python으로 작성된 강력한 프레임워크입니다. DNS 열거, 하위 도메인 검색, 포트 스캐닝, 웹 크롤링을 수행하고 알려진 취약성을 악용할 수도 있습니다.
- [theHarvester](https://github.com/laramies/theHarvester) : 검색 엔진, PGP 키 서버, SHODAN 데이터베이스와 같은 다양한 공개 소스에서 이메일 주소, 하위 도메인, 호스트, 직원 이름, 오픈 포트, 배너를 수집하도록 특별히 설계되었습니다. Python으로 작성된 명령줄 도구입니다.
- [SpiderFoot](https://github.com/smicallef/spiderfoot) : IP 주소, 도메인 이름, 이메일 주소, 소셜 미디어 프로필을 포함하여 대상에 대한 정보를 수집하기 위해 다양한 데이터 소스와 통합되는 오픈소스 인텔리전스 자동화 도구입니다. DNS 조회, 웹 크롤링, 포트 스캐닝 등을 수행할 수 있습니다.
- [OSINT 프레임워크](https://osintframework.com/) : 오픈소스 정보 수집을 위한 다양한 도구와 리소스 모음입니다. 소셜 미디어, 검색 엔진, 공개 기록 등 광범위한 정보 소스를 포괄합니다.

### FinalRecon 명령
```
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py
./finalrecon.py --help
```
```./finalrecon.py --headers --whois --url http://domain.com```
