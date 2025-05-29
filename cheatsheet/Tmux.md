# Tmux

## 설정
```git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm```<br/>
```git clone https://github.com/tmux-plugins/tmux-logging ~/.tmux/plugins/tmux-logging```<br/>
```
$ cat .tmux.conf 

# List of plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'
set -g history-limit 50000

# remap prefix from 'C-b' to 'C-a'
unbind C-b
set-option -g prefix C-a
bind-key C-a send-prefix

# split panes using | and -
bind | split-window -h
bind - split-window -v
unbind '"'
unbind %

# switch panes using Alt-arrow without prefix
bind -n M-Left select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up select-pane -U
bind -n M-Down select-pane -D

# Enable mouse control (clickable windows, panes, resizable panes)
set -g mouse on

# Initialize TMUX plugin manager (keep at bottom)
run '~/.tmux/plugins/tpm/tpm'
run-shell ~/.tmux/plugins/tmux-logging/logging.tmux
```

## 새로운 tmux session 시작
```tmux new -s <name>```

### 새로운 tmux session을 시작하거나 이미 열려있는 session에 attach
```tmux new-session -A -s <name>```

## 모든 session 리스트
```tmux ls```

## 열려있는 session에 attach
```tmux attach -t <name>```

### kill/delete session
```tmux kill-session -t <name>```

### 현재 session을 제외한 모든 session kill
```tmux kill-session -a```

### 마지막 session attach
```tmux a```<br/>```tmux a -t <name>```

## tmux 기본 prefix
```[Ctrl + a]```

## tmux logger 로깅 시작/중지 
```prefix + [Shift + p]```

## tmux logger 로깅 소급 적용 
```prefix + [Alt + Shift + p]```

## tmux 화면 스크롤 켜기
```prefix + [Shift + [ ]```

## tmux 수평 화면 분할
```prefix + [Shift + " ]```

### tmux 수직 화면 분할
```prefix + [Shift + % ]```

## tmux 분할화면 이동
```prefix + [방향키]```

## tmux 윈도우 창 추가 (기본 0, 1번부터 추가)
```prefix + [c]```

## tmux 윈도우 창 전환 (번호 사용)
```prefix + [1,2,3...]```

## tmux 윈도우 창 이름 변경
```prefix + [,]```

## tmux 분할화면 또는 윈도우 삭제
```prefix + [x]```
