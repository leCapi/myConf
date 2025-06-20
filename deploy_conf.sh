#!/bin/bash

REPO_DIR="$(pwd)"
HOME_DIR=~
BACKUP_DIR="$HOME_DIR/backup_conf"

linking_files_from_repo() {
  echo "linking "$1"..."
  ln -snf "$REPO_DIR"/config_files/"$1" "$HOME_DIR"/"$1"
}

echo "Backup old conf to $BACKUP_DIR"
if [ -d "$BACKUP_DIR" ]
then
  echo "Backup directory $BACKUP_DIR already exists. Aborting..."
  exit 1
fi

cd "$HOME_DIR"
mkdir "$BACKUP_DIR"
mkdir "$BACKUP_DIR"/.ssh
mv .vimrc .bashrc .gitconfig .gitignore "$BACKUP_DIR"
mv .ssh/config "$BACKUP_DIR"/.ssh/config
mv .config/Code/User/settings.json "$BACKUP_DIR"

linking_files_from_repo ".gitconfig"
linking_files_from_repo ".gitignore"
linking_files_from_repo ".vimrc"
linking_files_from_repo ".bashrc"
linking_files_from_repo ".drain3.ini"
linking_files_from_repo ".tmux.conf"
linking_files_from_repo ".ssh/config"
echo "linking visual code conf..."
ln -snf "$REPO_DIR"/config_files/settings.json "$HOME_DIR"/.config/Code/User/settings.json

