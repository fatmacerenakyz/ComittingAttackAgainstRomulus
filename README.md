**Project Description**

This repository provides a Python proof-of-concept implementation of a committing attack against the Romulus mode, reproducing theoretical weaknesses reported in the paper “Committing AE from Sponges”. 
https://eprint.iacr.org/2023/1525.pdf

The project demonstrates that Romulus, one of the NIST Lightweight Cryptography finalists, does not achieve committing (CMT) security under the studied setting. By exploiting the invertibility of certain 
state-update and processing steps, the same ciphertext–tag pair (C, T) can be validated under two different contexts (K, N, A).

The implementation includes minimal cryptographic routines for Romulus, the reversing steps required to construct alternate states and contexts, and a verification stage confirming the attack in practice. 
This code is intended for research and educational purposes only, not for production use.
