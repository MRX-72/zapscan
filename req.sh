!#/bin/bash

echo '[Setup has started]\n\n'

apt-get install clang
apt-get install nmap

g++ Zapscan.cpp -o zap

mv zap $PATH

echo 'Zap scan is successfully installed\n\n'

echo 'Type: (zap zs --help) for more information\n\n'

