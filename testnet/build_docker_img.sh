#!/usr/bin/env bash
set -e

if [[ $# -ne 2 ]]; then
    echo "Provide: docker_name docker_tag"
    exit 1
fi

CONTAINER_NAME="$1"
CONTAINER_TAG="$2"

# Archive the project so docker can build it
echo "Archiving the project"
git-archive-all project.tar.gz --prefix project
echo "done."

# Required for the docker container
if [[ ! -f ./go1.14.2.linux-amd64.tar.gz ]]; then
    wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
fi

echo "Building tendermint docker image $CONTAINER_NAME"

docker build -t ${CONTAINER_NAME} .
docker tag ${CONTAINER_NAME} ${CONTAINER_NAME}:${CONTAINER_TAG}
