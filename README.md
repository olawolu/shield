# Shield

This is a golang implementation of threshold ECDSA between two parties. Adapted from [ZenGo-X/multi-party-ecdsa](https://github.com/ZenGo-X/multi-party-ecdsa).

Threshold ECDSA consists of two protocols:

- Key generation to generate the key shares
- Signing to use the key shares to generate a signature.

Here is an overview of [Threshold signatures](https://academy.binance.com/en/articles/threshold-signatures-explained)
