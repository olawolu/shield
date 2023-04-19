# tss-lib

Contains methods to facilitate two party ecdsa threshold signing scheme

## DKG

Each party

- generates a random x, computes Q=x.G where G is the generator of the curve
- creates a comittment to Q
- a zk proof of knowledge of x and the discrete log of Q
- the committments and proofs are shared among parties

## Signing

An example ethereum transaction

```json
{
    "transaction": {
        "chainId": 1,
        "nonce": 0,
        "maxFeePerGas": "0x000000",
        "maxPriorityFeePerGas": "0x000000",
        "gasLimit": "0x000000",
        "destination": "0x000000",
        "amount": "0x000000",
        "data": "0x000000",
    }
}
```

### What happens during signing

- RLP encode the transaction
- hash the RLP encoded transaction
- run the signing process on the hash
