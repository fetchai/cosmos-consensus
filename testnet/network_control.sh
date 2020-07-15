#!/usr/bin/env bash
set -e

# usage: ./network_control.sh reset
# usage: ./network_control.sh delay 100ms 192.168.1.1 192.168.1.3...

if [ "$1" == "reset" ]; then
    echo "Resetting the networking"

    # https://serverfault.com/questions/389290
    tc qdisc del dev eth0 root || true
    tc qdisc add dev eth0 root handle 1: prio

elif [ "$1" == "delay" ]; then

    #!/bin/bash
    for i in "${@:3}"; do
        echo "delaying $i by $2"

        IP_TRANSLATED=`./dns_lookup.sh $i`
        echo "Delaying..."

        # For subsequent delays this first command will return an EC so suppress it with || true
        echo "tc qdisc add dev eth0 parent 1:3 handle 30: netem delay $2"
        tc qdisc add dev eth0 parent 1:3 handle 30: netem delay $2 || true

        echo "tc filter add dev eth0 protocol ip parent 1:0 prio 3 u32 match ip dst $IP_TRANSLATED flowid 1:3"
        tc filter add dev eth0 protocol ip parent 1:0 prio 3 u32 match ip dst $IP_TRANSLATED flowid 1:3
    done
else
    echo "Expected the first argument to the script to be reset or delay. Quitting."
    exit 1
fi

# test this for example with curl -o /dev/null -s -w 'Total: %{time_total}s\n' node1:26660
