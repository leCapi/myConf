# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
*) return;;
esac

export LANG="en_US.UTF-8"

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=100000
HISTFILESIZE=200000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
        # We have color support; assume it's compliant with Ecma-48
        # (ISO/IEC-6429). (Lack of such support is extremely rare, and such
        # a case would tend to support setf rather than setaf.)
        color_prompt=yes
    else
        color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
#case "$TERM" in
#    xterm*|rxvt*)
#        PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
#        ;;
#    *)
#        ;;
#esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
    if [ -f /usr/share/bash-completion/bash_completion ]; then
        . /usr/share/bash-completion/bash_completion
    elif [ -f /etc/bash_completion ]; then
        . /etc/bash_completion
    fi
fi


parse_git_branch() 
{
    local BRANCH=$(git branch 2>/dev/null | grep '^*' | colrm 1 2)
    if [[ ! -z "$BRANCH" ]]
    then
        echo "($BRANCH)"
    fi
}

parse_git_changes() 
{
  local CHANGES=$(git status 2>/dev/null --short |wc -l)
    if [[  ! $CHANGES -eq "0" ]]
    then
        echo "[$CHANGES CHANGES]"
    fi
}

# PROMPT COLOURS
BLACK='\e[0;30m'      # Black - Regular
RED='\e[0;31m'        # Red
GREEN='\e[0;32m'      # Green
YELLOW='\[\033[0;33m\]'     # Yellow
BLUE='\e[0;34m'       # Blue
PURPLE='\e[0;35m'     # Purple
CYAN='\e[0;36m'       # Cyan
WHITE='\[\e[0;37m\]'      # White
BLACK_BOLD='\e[1;30m'   # Black - Bold
RED_BOLD='\[\033[1;31m\]'     # Red - Bold
GREEN_BOLD='\[\033[1;32m\]'   # Green - Bold
YELLOW_BOLD='\e[1;33m'  # Yellow - Bold
BLUE_BOLD='\[\033[1;34m\]'    # Blue - Bold
PURPLE_BOLD='\e[1;35m'  # Purple - Bold
CYAN_BOLD='\e[1;36m'    # Cyan - Bold
WHITE_BOLD='\[\033[1;37m\]'   # White - Bold
RESET='\e[0m'         # Text Reset

#
# DEFINING THE PROMPT
#
#export PS1="${GREEN_BOLD}\u : ${GREEN}\w ${YELLOW}\$(parse_git_branch)${WHITE_BOLD}\n> ${WHITE}"
export PS1="${WHITE_BOLD}\t ${BLUE_BOLD}\u${WHITE_BOLD}@${RED_BOLD}\h ${GREEN_BOLD}\w ${YELLOW}\$(parse_git_branch) ${RED_BOLD}\$(parse_git_changes)\n${WHITE_BOLD}> \[$(tput sgr0)\]"
#export PS1="${WHITE_BOLD}\t ${BLUE_BOLD}\u${WHITE_BOLD}@${RED_BOLD}\h ${GREEN_BOLD}\w ${YELLOW}\$(parse_git_branch)\n${WHITE_BOLD}> ${WHITE}"

#-------------------------------------------------------------
# The 'ls' family (this assumes you use a recent GNU ls).
#-------------------------------------------------------------
# Add colors for filetype and  human-readable sizes by default on 'ls':
alias ls='ls -h --color'
alias lx='ls -lXB'         #  Sort by extension.
alias lk='ls -lSr'         #  Sort by size, biggest last.
alias lt='ls -ltr'         #  Sort by date, most recent last.
alias lc='ls -ltcr'        #  Sort by/show change time,most recent last.
alias lu='ls -ltur'        #  Sort by/show access time,most recent last.

# The ubiquitous 'll': directories first, with alphanumeric sorting:
alias ll="ls -lv --group-directories-first"
alias lm='ll |more'        #  Pipe through 'more'
alias lr='ll -R'           #  Recursive ls.
alias la='ll -A'           #  Show hidden files.
alias tree='tree -Csuh'    #  Nice alternative to 'recursive ls' ...


# SSH AGENT
#eval $(ssh-agent -s)
SSH_ENV="$HOME/.ssh/agent-environment"
function start_agent {
    echo "Initialising new SSH agent..."
    /usr/bin/ssh-agent | sed 's/^echo/#echo/' >"$SSH_ENV"
    echo succeeded
    chmod 600 "$SSH_ENV"
    . "$SSH_ENV" >/dev/null
    /usr/bin/ssh-add;
}

if [ -f "$SSH_ENV" ]; then
    . "$SSH_ENV" >/dev/null
    #ps $SSH_AGENT_PID doesn't work under Cygwin
    ps -ef | grep $SSH_AGENT_PID | grep ssh-agent$ >/dev/null || {
        start_agent
    }
else
    start_agent
fi

# TMUX
SOURCE=${BASH_SOURCE[0]}
while [ -L "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
    DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )
    SOURCE=$(readlink "$SOURCE")
    # if $SOURCE was a relative symlink,
    # we need to resolve it relative to the path where the symlink file was located
    [[ $SOURCE != /* ]] && SOURCE=$DIR/$SOURCE
done
DIR_BASHRC_GIT=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )

tm(){
  session=${1:-main}
  tmux new -A -s "$session"
}

tms(){
  cwd=$(pwd)
  tmux split $@
  cd $cwd
}

alias setupEnv1='source $DIR_BASHRC_GIT/../script/launch_tmux.sh ~/git ~/git ~/git python'
