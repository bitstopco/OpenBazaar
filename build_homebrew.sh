#!/bin/bash

mv /Library/Caches/Homebrew/openbazaar--git ~/openbazaar #move file to users root
cd ~/openbazaar

#python prerequisites
#python may be owned by root, or it may be owned by the user
PYTHON_OWNER=$(stat -n -f %u `which python`)
if [ "$PYTHON_OWNER" == "0" ]; then
  #root owns python
  EASY_INSTALL="sudo easy_install"
  PIP="sudo pip"
else
  EASY_INSTALL="easy_install"
  PIP="pip"
fi

#install pip if it is not installed
if ! command_exists pip ; then
  $EASY_INSTALL pip
fi

#install python's virtualenv if it is not installed
if ! command_exists virtualenv ; then
  $PIP install virtualenv
fi

#create a virtualenv for OpenBazaar
if [ ! -d "./env" ]; then
  virtualenv env
fi

./env/bin/pip install ./pysqlcipher
./env/bin/pip install -r requirements.txt