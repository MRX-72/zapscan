#!/bin/bash

printf "[Setup has started]\n\n"

apt-get install clang
apt-get install nmap

g++ Zapscan.cpp -o zap

mv zap $PATH

printf "\n\n -> Zap scan is successfully installed\n\n"

printf "\n\b [Info]> Type: (zap zs --help) for more information\n\n"

