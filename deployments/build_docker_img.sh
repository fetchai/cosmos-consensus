#!/usr/bin/env bash

while true; do
	read -p "Please choose build enivironment - Local or Cloud: " lc
    case $lc in
    	[Cc]* )
        upload=true
        break
        ;;
        [Ll]* )
        upload=false
        break
        ;;
        * ) echo "Please answer Local or Cloud.";;
    esac
done

git submodule init
git submodule update

echo "Building tendermint docker image"
sleep 2

docker build -t tendermint_drb -f tendermint_container/Dockerfile  ../


if [ $upload = true ] ; 
then
	DEVREGISTRY="gcr.io/fetch-ai-sandbox/"
	VERSION=$(git describe --always --dirty=-WIP)

    REGISTRY=$DEVREGISTRY

    echo "Tagging and pusing tendermint_drb image"
    sleep 2
    docker tag tendermint_drb ${REGISTRY}tendermint_drb:${VERSION}
    docker tag tendermint_drb ${REGISTRY}tendermint_drb:latest
    docker push ${REGISTRY}tendermint_drb:${VERSION}
    docker push ${REGISTRY}tendermint_drb:latest
fi