#!/usr/bin/env bash

counter=0

while true
do
    for nodename in "$@"
    do
        for sub_word in $nodename
        do
            rand_str=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 100000)
            echo "sending TX $rand_str, count $counter to $sub_word"
            echo "curl -m 2 '$sub_word:26654/broadcast_tx_sync?tx=\"rnd_$rand_str\"'"
            curl -m 2 "$sub_word:26654/broadcast_tx_sync?tx=\"rnd_$rand_str\""

            if [ $? -ne 0 ]
            then
                echo "Note: this failed."
            fi
            ((counter++))
        done
    done

    sleep 0.1
done

echo $@
