#! /bin/bash


sudo rm -rf ~/gopath/pkg/mod/github.com/ipfs && \
sudo cp -rf ipfs-package ipfs
sudo mv ipfs ~/gopath/pkg/mod/github.com/ && \
cd kubo && make install
