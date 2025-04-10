# Tmux

### 새로운 tmux session 시작
```tmux new -s <name>```

### 새로운 tmux session을 시작하거나 이미 열려있는 session에 attach
```tmux new-session -A -s <name>```

### 모든 session 리스트
```tmux ls```

### kill/delete session
```tmux kill-session -t <name>```

### 현재 session을 제외한 모든 session kill
```tmux kill-session -a```

### 마지막 session attach
```
tmux a
tmux a -t <name>
```

### tmux 기본 prefix
```[Ctrl + b]```

### tmux logger 로깅 시작/중지 
```prefix + [Shift + P]```

### tmux 수직 화면 분할
```prefix + [Shift + %]```

### tmux 수평 화면 분할
```prefix + [Shift + "]```

#### tmux 화면 전환
```prefix + [Shift + O]```
