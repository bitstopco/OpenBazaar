#!/bin/bash

#exit on error
set -e

function command_exists {
  #this should be a very portable way of checking if something is on the path
  #usage: "if command_exists foo; then echo it exists; fi"
  type "$1" &> /dev/null
}

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

# set compile flags for brew's openssl instead of using brew link --force
export CFLAGS="-I$(brew --prefix openssl)/include"
export LDFLAGS="-L$(brew --prefix openssl)/lib"

#install python deps inside our virtualenv
./env/bin/pip install ./pysqlcipher
./env/bin/pip install -r requirements.txt

doneMessage

function doneMessage {
  echo ""
  echo "OpenBazaar configuration finished."
  echo "type './run.sh; tail -f logs/production.log' to start your OpenBazaar servent instance and monitor logging output."
  echo ""
  echo ""
  echo ""
  echo ""
}
