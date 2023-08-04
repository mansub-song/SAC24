#! /bin/bash


sudo rm -rf ~/gopath/pkg/mod/github.com/ipfs && \
sudo cp -rf  opt_ipfs-package ipfs
sudo mv ipfs ~/gopath/pkg/mod/github.com/ && \
cd opt_kubo && make install
