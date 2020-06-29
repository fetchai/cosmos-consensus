#!/usr/bin/env bash

counter=0

while true
do
    for nodename in "$@"
    do
        for sub_word in $nodename
        do
            echo "sending TX $counter to $sub_word"
            echo "curl -m 2 '$sub_word:26654/broadcast_tx_sync?tx=\"rnd_$counter\"'"
            curl -m 2 "$sub_word:26654/broadcast_tx_sync?tx=\"rnd_${counter}\""

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
