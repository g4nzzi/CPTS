# Tmux

### 새로운 tmux session 시작
```tmux new -s <name>```
<br/>
### 새로운 tmux session을 시작하거나 이미 열려있는 session에 attach
```tmux new-session -A -s <name>```
<br/>
### 모든 session 리스트
```tmux ls```
<br/>
### kill/delete session
```tmux kill-session -t <name>```
<br/>
### 현재 session을 제외한 모든 session kill
```tmux kill-session -a```
<br/>
### 마지막 session attach
```tmux a```<br/>```tmux a -t <name>```
<br/>
### tmux 기본 prefix
```[Ctrl + b]```
<br/>
### tmux logger 로깅 시작/중지 
```prefix + [Shift + P]```
<br/>
### tmux 수직 화면 분할
```prefix + [Shift + %]```
<br/>
### tmux 수평 화면 분할
```prefix + [Shift + "]```
<br/>
#### tmux 화면 전환
```prefix + [Shift + O]```
