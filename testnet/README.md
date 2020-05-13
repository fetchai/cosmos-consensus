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

Then run:

./setup-cluster.py

This will default to a three node network. Use the help flag for usage.
