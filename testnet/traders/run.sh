#!/usr/bin/env bash


for nodename in "$@"
do
    (
    counter=0
    name=$nodename
    while true
    do
        for sub_word in $name
        do
            rand_str=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 1000)
            echo "sending TX $rand_str, count $counter to $sub_word"
            echo "curl -m 2 '$sub_word:26654/broadcast_tx_async?tx=\"rnd_$rand_str\"'"
            curl -m 2 "$sub_word:26654/broadcast_tx_sync?tx=\"rnd_$rand_str\""

            if [ $? -ne 0 ]
            then
                echo "Note: this failed."
            fi
            ((counter++))
        done
    done
    ) &
done

echo $@
wait $!
