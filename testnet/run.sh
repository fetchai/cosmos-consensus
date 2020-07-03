#!/usr/bin/env bash

# https://github.com/stakater/til/blob/master/ibm/ibm-pvc-lost-found-directory-issue.md
# On some systems PVCs will be mounted with a lost+found folder so it is not neccessarily
# empty
rm -rf ./data/lost+found

if [ "$(ls -A ./data)" ]; then
     echo "Dir not empty - doing nothing!"
     ls ./data
else
    cp priv_validator_state.json ./data
fi

echo "Copying config."
mkdir -p config
cp config_ro/* config

if [ -z "$REDIRECT_LOCALHOST" ]; then
    echo "Note: expected REDIRECT_LOCALHOST environment variable to be set"
fi

if [ "$REDIRECT_LOCALHOST" == "1" ]; then
    echo "forwarding to localhost port"
    socat tcp-l:26654,fork,reuseaddr tcp:127.0.0.1:26657 &
else
    echo "not forwarding to localhost port: $REDIRECT_LOCALHOST"
fi

echo "Executing command tendermint $@"

tendermint $@

if [ $? == 33 ]; then
    echo -e "\n\nTHIS FAILED! Attempting file corruption healing and a restart"

    echo "running wal2json"
    ./wal2json ./data/cs.wal/wal > wal.json

    echo "running json2wal to replace data wal file"
    rm -rf ./data/cs.wal/wal
    ./json2wal wal.json ./data/cs.wal/wal

    echo "restarting tendermint"
    tendermint $@
else
    echo "Failed with code $?"
fi
