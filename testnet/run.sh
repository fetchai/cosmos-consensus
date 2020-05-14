#!/usr/bin/env bash
set -e

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


echo "forwarding to localhost port"
socat tcp-l:26654,fork,reuseaddr tcp:127.0.0.1:26657 &

echo "Executing command tendermint $@"

tendermint $@
