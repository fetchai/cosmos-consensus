#!/usr/bin/env bash
set -e

CONTAINER_NAME="gcr.io/fetch-ai-sandbox/traders"
CONTAINER_TAG="latest"

echo "Building docker image $CONTAINER_NAME"

docker build -t ${CONTAINER_NAME} .
docker tag ${CONTAINER_NAME} ${CONTAINER_NAME}:${CONTAINER_TAG}
docker push ${CONTAINER_NAME}:${CONTAINER_TAG}
