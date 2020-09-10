# Random Beacon

The changes outlined below have been made to allow for random block proposer selection.  This is an improvement upon Tendermint’s deterministic proposer selection algorithm, which requires validators to hide their identities in the P2P network to be resistant to DOS attacks. The scheme discussed here makes use of threshold signatures to compute a random value that acts as the seed for randomly shuffling the validator set. 

## Validator Responsibilities

Validators are required, in addition to running Tendermint’s consensus protocol, to perform a key setup phase and use this to generate random values, referred below as entropy. The setup phase, which is described below, equips each validator with a private key with which it can contribute to entropy generation and requires some time to complete. In order to avoid frequently running the key setup phase, the validator set is updated every `AeonLength` rather than on every block. 

## Distributed Key Generation

In order to compute the threshold signatures required to generate the entropy the validators need to perform a key setup phase known as Distributed Key Generation (DKG). The DKG protocol implemented follows the GLOW scheme described in [[1]](#1). For *N* participants and a threshold *t*, the cryptographic protocol ensures that all honest participants agree on:
- The set of successful participants, *Q*, which is of size no less than *t*
- The public key *pk<sub>i* of each validator in *Q*
- A group public key
Each validator in *Q* also has a secret key *sk<sub>i* corresponding to *pk<sub>i*. These keys allow any subset of *t* successful participants to generate group signatures that can be verified with the group public key.

The current DKG implementation uses the blockchain to reliably broadcast information by packing messages into transactions and only processing messages when they have been included into a committed block. The encryption and decryption of private messages is done using one-way handshakes in [Noise](https://github.com/flynn/noise). The default duration of states in the DKG depends on the number of participants, which increases by a factor of `dkgIterationDurationMultiplier` with each DKG failure, up to a maximum of `maxDKGStateDuration` blocks. This is done to prevent the DKG repeatedly failing due to a misconfiguration of the state duration. Durations are measured in blocks rather than time.
 
Nodes not participating in the DKG, such as sentries, collect the output of the DKG from the final round of messages in order to verify individual signatures computed with *sk<sub>i* and group signatures.

## Entropy Generation

Entropy is a group signature of the previously generated signature, which is a signature of the previous and so on. Prior to generating block *X*, the validators must first compute the entropy value for that block height. This involves each validator signing the previous entropy value with their secret key and gossiping this signature to its peers. Once a node has received *t* valid signatures it can combine them into a single group signature, the SHA256 hash of which is the entropy value. The entropy value of block *X* is used to shuffle the validator set and the block proposer for height *X* round *i* is the validator at position *i* in the shuffled order. When a block contains empty entropy, which can arise when the DKG has many successive failures, the block proposer selection algorithm falls back to that of original Tendermint.

To minimise the impact of entropy generation on block time validators are allowed to produce `
EntropyChannelCapacity` entropy values ahead of their current block height. This parameter sets a bound on how far in advance nodes can compute the next block proposer, which does not exist in original Tendermint. These changes limit the time window in which DOS attacks on validators can be coordinated and executed. 

## References

<a id="2">[1]</a>
Galindo, D., Liu, J., Ordean, M., and Wong, J. (2020) Fully Distributed Verifiable Random Functions and their Application to Decentralised Random Beacons.