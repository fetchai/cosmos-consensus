#!/usr/bin/env bash
set -e

if [ "$(ls -A ./data)" ]; then
     echo "Dir not empty - doing nothing"
else
    cp priv_validator_state.json ./data
fi

mkdir -p config
cp config_ro/* config

echo "Executing command tendermint $@"

tendermint $@
