#!/usr/bin/env bash
set -e

# usage: ./network_control.sh reset
# usage: ./network_control.sh delay 192.168.1.1 100ms

if [ "$1" == "reset" ]; then
    echo "Resetting the networking"

    # https://serverfault.com/questions/389290
    tc qdisc del dev eth0 root || true
    tc qdisc add dev eth0 root handle 1: prio

elif [ "$1" == "delay" ]; then

    IP_TRANSLATED=`./dns_lookup.sh $2`
    echo "Delaying "

    # For subsequent delays this first command will return an EC so suppress it with || true
    tc qdisc add dev eth0 parent 1:3 handle 30: netem delay $3 || true
    tc filter add dev eth0 protocol ip parent 1:0 prio 3 u32 match ip dst $IP_TRANSLATED flowid 1:3
else
    echo "Expected the first argument to the script to be reset or delay. Quitting."
    exit 1
fi

# test this with curl -o /dev/null -s -w 'Total: %{time_total}s\n' google.com
