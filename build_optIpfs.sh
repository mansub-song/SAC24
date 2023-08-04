#! /bin/bash


sudo rm -rf ~/gopath/pkg/mod/github.com/ipfs && \
sudo mv opt_ipfs-package ipfs
sudo cp -rf ipfs ~/gopath/pkg/mod/github.com/ && \
cd opt_kubo && make install
