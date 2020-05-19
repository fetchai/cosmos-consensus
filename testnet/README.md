This directory allows creating a tendermint DRB testnet with prom + grafana logging

To use, first set up kubernetes in a cluster and get the permissions to use it, and push docker images.
Note you should create your own namespace.
The deployment folder can be used if there is no prom + grafana set up already, note that the
namespace needs to be updated:

```
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
```

The final 'default' here should be the namespace it is in.

If there is already a cluster set up, you may only need to create your own namespace to deploy in: `kubectl create namespace xxx`.

Build and push a docker image with the current working directory

./setup-cluster.py -b -p

Then run:

./setup-cluster.py -v 3

To set up a three node network. Refer to the `-h` flag for more options
