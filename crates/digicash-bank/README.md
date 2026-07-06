# digicash-bank

Bank server for the digicash e-cash prototype: account ledger, denomination keys, spent-serial store, and the withdraw/deposit protocol.

Part of [digicash](https://github.com/ChronoCoders/digicash).

## Security

The RSA blind-signature path depends (via `blind-rsa-signatures`) on the `rsa` crate, which is subject to **RUSTSEC-2023-0071** (Marvin attack: potential key recovery through timing sidechannels; medium severity, no upstream fix available). It affects RSA private-key operations, i.e. the bank's blind-signing only, and is bounded by this prototype's trusted-network assumption.

**Experimental and unaudited. Do not use in production.**

## License

MIT License - Copyright (c) 2026 Altug Tatlisu (ChronoCoders)
