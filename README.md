<img
    src="https://upload.wikimedia.org/wikipedia/commons/thumb/e/e2/The_Lady_of_the_Lake_by_Speed_Lancelot.jpg/302px-The_Lady_of_the_Lake_by_Speed_Lancelot.jpg?download"
    align="right"
    width=33%/>

Nimue: a Fiat-Shamir library
=========

**This library has not been externally reviewed yet and shouldn't be considered ready for deployments.**

Nimue is a hash-agnostic library that believes in random oracles.
It facilitates the writing of multi-round public coin protocols.
Built on the top of the SAFE framework and provides an API for generating the verifier's and prover's random coins.

# Features

**Automatic transcript generation.** nimue comes with batteries included for serializing/deserializing algebraic elements such as field/group elements in [arkworks](https://github.com/arkworks-rs/algebra) and [zkcrypto](https://github.com/zkcrypto/group). Users can build the top of it via extension trait.

**Support custom hash function.**
To build a secure Fiat-Shamir transform, the minimal requirement is a permutation function over some set that supports byte-encoding. I can be a `u8` representing $\mathbb{F}_{2^8}$ or any large-characteristic prime field $\mathbb{F}_p$.

**Retro-compatibility.**
We have a legacy interface for any hash function that satisfies the [`digest::Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html) trait, including [`sha2`](https://crates.io/crates/sha2), [`blake2`](https://crates.io/crates/blake2).

- **Preprocessing**.
In recursive SNARKs, minimizing the number of hash invocations
while maintaining security is crucial. We offer tools for preprocessing the Transcript (i.e., the state of the Fiat-Shamir transform) to achieve this goal.

- **Private randomness generation**.
It is vital to avoid providing two different challenges for the same prover message. We do our best to avoid it by tying down the prover randomness to the protocol transcript, without making the proof deterministic.

Check out the [documentation](https://docs.rs/nimue/latest/nimue/) and some [`examples/`](https://github.com/mmaker/nimue/tree/main/examples).
