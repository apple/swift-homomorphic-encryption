#!/bin/bash

echo "installing jemalloc"
apt-get update -y
apt-get install -y bzip2 make curl tar
curl https://github.com/jemalloc/jemalloc/releases/download/5.3.0/jemalloc-5.3.0.tar.bz2 -L -o jemalloc-5.3.0.tar.bz2
tar -xf jemalloc-5.3.0.tar.bz2
cd jemalloc-5.3.0 && ./configure && make && make install
