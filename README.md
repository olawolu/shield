# tss-lib
Contains methods to facilitate two party ecdsa threshold signing scheme 

## DKG

Each party

- generates a random x, computes Q=x.G where G is the generator of the curve
- creates a comittment to Q
- a zk proof of knowledge of x and the discrete log of Q
- the committments and proofs are shared among parties
- 