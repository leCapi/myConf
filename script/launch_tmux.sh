#!/bin/sh

# use inside a fresh tmux session with an alias
# like this :
# alias setupEnv1='source PATH_SCRIPT/launch_tmux.sh ~/FOLDER1 ~/FOLDER2 ~/FOLDER3'

cd "$1";clear
tmux split-window -h -p 60 -c "$2"
tmux split-window -v -c "$3"
tmux split-window -h  'python'
