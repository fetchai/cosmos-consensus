#!/usr/bin/env bash

echo "Building tendermint docker image"
sleep 2

docker build -t tendermint_drb -f tendermint_container/Dockerfile  ../