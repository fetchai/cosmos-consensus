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

# Loop through nodes printing their IP addresses for reference
for i in `seq 0 1000`;do
        SERVERNAME=node$i
        nslookup $SERVERNAME &> /dev/null

        if [ $? -ne 0 ]
        then
                break
        fi

        RESULT=`nslookup $SERVERNAME | tail -n 2 | head -n 1 | sed -E 's/Address: (.*)/\1/g'`
        echo "$SERVERNAME is $RESULT"
done

# If the DELVE_ENABLED environment variable is set we will start with delve remote debugger. This should be port-forwarded to your machine
# on port 1234 and you can remotely debug the program. By design delve does not stop even if the program panics or quits, so if on a
# restart tendermint crashes due to file corruption, the wal2json recovery will not be reached.

if [ "$DELVE_ENABLED" == "1" ]; then
    echo "Enabling Delve for remote debug!"
    echo "Executing command tendermint dlv --listen=:1234 --headless=true --api-version=2 --accept-multiclient exec --continue /usr/bin/tendermint_dbg \"--\" $@"
    dlv --listen=:1234 --headless=true --api-version=2 --accept-multiclient exec --continue /usr/bin/tendermint "--" $@
else
    echo "Executing command tendermint $@"
    tendermint $@
fi

if [ $? == 33 ]; then
    echo -e "\n\nTHIS FAILED (error code 33 == file corruption)! Attempting file corruption healing and a restart"

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
