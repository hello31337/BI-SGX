#! /bin/sh

./bootstrap
./configure --with-openssldir=/opt/openssl/1.1.0i
make
