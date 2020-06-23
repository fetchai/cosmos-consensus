#!/usr/bin/env python3

import subprocess
import os
import sys
import time
from pathlib import Path
import shutil
import fileinput
import requests

# This test runs a 4 node network, locally, and just verifies that everything is working correctly,
# that is, that the network can generate entropy, and a TX submitted to the chain is seen.
# metrics are used to determine whether things are ok.
# Assumes that tendermint is installed and new. Node 0 will display its logs.

NODE_0_PRINTS=True
VALIDATORS=4
TEST_TIMEOUT_S=60*2
THIS_FILE_DIR = os.path.dirname(os.path.realpath(__file__))
os.chdir(THIS_FILE_DIR)

# Possibly there is old files in the mytestnet directory. Clear it.
dirpath = Path('mytestnet')
if dirpath.exists() and dirpath.is_dir():
    shutil.rmtree(dirpath)

# Init the files needed
return_obj = subprocess.run(["tendermint", "testnet", "--v", f"{VALIDATORS}"])

if return_obj.returncode:
    print(f"Failed to init testnet files when running end to end test - is tendermint installed?")
    sys.exit(1)

# Turn on metrics for node 0
pathlist = Path("mytestnet/node0").glob('**/config.toml')
for path in pathlist:
    with fileinput.FileInput(path, inplace=True) as file:
        for line in file:
            print(line.replace("prometheus = false", "prometheus = true"), end='')

node_ids = []
nodes = []

# Collect the nodes IDs
for i in range(0, VALIDATORS):
    node_ids = [*node_ids, subprocess.check_output(f"tendermint show_node_id --home mytestnet/node{i}".split()).decode().strip()]
    print(node_ids)

# Start the nodes
# P2P addresses will start from 3000, RPC from 7000
for i in range(0, VALIDATORS):
    p2p_addr =f"tcp://127.0.0.1:{3000+i}"
    rpc_addr=f"tcp://127.0.0.1:{7000+i}"

    # Builds up peers in the format ID1@127.0.0.1:P1 (not including self)
    peers = [node_ids[x]+"@127.0.0.1:"+str(3000+x) for x in range(0, VALIDATORS) if x != i]
    peers = ",".join(peers)

    persist_peers = f"--p2p.persistent_peers={peers}" if VALIDATORS > 1 else ""

    cmd = f"tendermint node --home mytestnet/node{i} --proxy_app=kvstore --p2p.laddr={p2p_addr} --rpc.laddr={rpc_addr} {persist_peers}".split()

    print(" ".join(cmd))

    std_out = None if (i == 0 and NODE_0_PRINTS) else subprocess.DEVNULL
    std_err = None

    nodes = [*nodes, subprocess.Popen(cmd, stdout=std_out, stderr=std_err)]

def get_metric(metric: str):
    r = requests.get('http://127.0.0.1:26660')
    for line in r.text.split('\n'):
        if metric in line and '#' not in line:
            #print("line")
            return float(line.split('} ')[1])

# Wait until entropy is seen
time_now=time.time()
timed_out=False

# Wait until entropy started generating to collect result
while True:
    if time.time() - time_now >= TEST_TIMEOUT_S:
        print("\nThe test has run for too long! Quitting.")
        timed_out = True
        break

    has_entropy = 0.0

    try:
        has_entropy = get_metric("tendermint_beacon_block_with_entropy")
    except:
        pass

    if has_entropy == 1.0:
        break

    time.sleep(2)

if timed_out == False:
    # Submit a TX to node 0
    tx_string="random_tx"
    print(f"Submitting {tx_string}...")
    print(subprocess.check_output(f"curl localhost:7000/broadcast_tx_sync?tx=\"{tx_string}\"".split()).decode().strip())

    while True:
        if time.time() - time_now >= TEST_TIMEOUT_S:
            print("\nThe test has run for too long (waiting for tx)! Quitting.")
            timed_out = True
            break

        total_txs = 0.0

        try:
            total_txs = get_metric("tendermint_consensus_total_txs")
        except:
            pass

        if total_txs == 1.0:
            print("Found TX. Quitting test.")
            break

for node in nodes:
    node.kill()

for node in nodes:
    node.wait(timeout=5)

if timed_out:
    sys.exit(1)

sys.exit(0)
