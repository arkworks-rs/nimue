<img
    src="https://upload.wikimedia.org/wikipedia/commons/thumb/e/e2/The_Lady_of_the_Lake_by_Speed_Lancelot.jpg/302px-The_Lady_of_the_Lake_by_Speed_Lancelot.jpg?download"
    align="right"
    width=33%/>

Nimue: a Fiat-Shamir library
=========

Nimue is a hash-agnostic library that believes in random oracles.
It facilitates the writing of multi-round public coin protocols.
It provides a generic API for generating the verifier's random coins and the prover randomness.
The project has the following crates:

- `nimue`: the core library, with bindings for [`group`](https://github.com/zkcrypto/group) and [`ark-ff`](https://arkworks.rs). This crate provides the basic traits for hashes bases on **compression functions** and **sponge-based hash functions**, both via Rust's generic [`Digest`](https://docs.rs/digest/latest/digest/) API and a (more fine-grained and efficient) permutation function API
- `nimue-pow`: an extension for challenges computed via grinding / proof-of-work;
- `nimue-poseidon`: a **WORK IN PROGRESS** implementation of the [Poseidon](https://anemoi-hash.github.io/) hash function (in arkworks).
- `nimue-anemoi`: a **WORK IN PROGRESS** implementation of the [Anemoi](https://anemoi-hash.github.io/) hash function (in arkworks);


# Features

**Automatic transcript generation.** nimue comes with batteries included for serializing/deserializing algebraic elements such as field/group elements in [arkworks](https://github.com/arkworks-rs/algebra) and [zkcrypto](https://github.com/zkcrypto/group). Users can build the top of it via extension traits.

**Support custom hash function.**
To build a secure Fiat-Shamir transform, the minimal requirement is a permutation function over some set that supports byte-encoding. It can be a `u8` representing $\mathbb{F}_{2^8}$ or any large-characteristic prime field $\mathbb{F}_p$.

**Retro-compatibility.**
We have a legacy interface for any hash function that satisfies the [`digest::Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html) trait, such as [`sha2`](https://crates.io/crates/sha2) and [`blake2`](https://crates.io/crates/blake2).

- **Preprocessing**.
In recursive SNARKs, minimizing the number of hash invocations
while maintaining security is crucial. We offer tools for preprocessing the Transcript (i.e., the state of the Fiat-Shamir transform) to achieve this goal.

- **Private randomness generation**.
It is vital to avoid providing two different challenges for the same prover message. We do our best to avoid it by tying down the prover randomness to the protocol transcript, without making the proof deterministic.

## More information
Check out the [documentation](https://arkworks.rs/nimue/) and some [`examples/`](https://github.com/arkworks-rs/nimue/tree/main/examples).
