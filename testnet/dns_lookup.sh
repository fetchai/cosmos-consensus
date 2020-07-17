#!/usr/bin/env bash
set -e

# usage: ./dns_lookup.sh node1

RESULT=`nslookup $1 | tail -n 2 | head -n 1 | sed -E 's/Address: (.*)/\1/g'`

echo "$RESULT"
