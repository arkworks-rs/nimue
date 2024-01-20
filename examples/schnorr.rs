/// Example: simple Schnorr proofs.
///
/// Schnorr proofs allow to prove knowledge of a secret key over a group $\mathbb{G}$ of prime order $p$ where the discrete logarithm problem is hard.
/// The protocols is as follows:
///
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use nimue::plugins::arkworks::*;
use nimue::{DuplexHash, ProofResult};
use rand::rngs::OsRng;

/// The key generation algorithm otuputs
/// a secret key `sk` in $\mathbb{Z}_p$
/// and its respective public key `pk` in $\mathbb{G}$.
fn keygen<G: CurveGroup>() -> (G::ScalarField, G) {
    let sk = G::ScalarField::rand(&mut OsRng);
    let pk = G::generator() * sk;
    (sk, pk)
}

/// The prove algorithm takes as input
/// - the prover state `Arthur`, that has access to a random oracle `H` and can absorb/squeeze elements from the group `G`.
/// - the secret key $x \in \mathbb{Z}_p$
/// It returns a zero-knowledge proof of knowledge of `x` as a sequence of bytes.
#[allow(non_snake_case)]
fn prove<H: DuplexHash<u8>, G: CurveGroup>(
    // `ArkGroupArthur` is a wrapper around `Arthur` that is aware of serialization/deserialization of group elements
    // the hash function `H` works over bytes, unless otherwise denoted with an additional type argument implementing `nimue::Unit`.
    arthur: &mut ArkGroupArthur<G, H>,
    // the generator
    P: G,
    // the secret key
    x: G::ScalarField,
) -> ProofResult<&[u8]> {
    // `Arthur` types implement a cryptographically-secure random number generator that is tied to the protocol transcript
    // and that can be accessed via the `rng()` funciton.
    let k = G::ScalarField::rand(arthur.rng());
    let K = P * k;

    // Add a sequence of points to the protocol transcript.
    // An error is returned in case of failed serialization, or inconsistencies with the IO pattern provided (see below).
    arthur.add_points(&[K])?;

    // Fetch a challenge from the current transcript state.
    let [c] = arthur.challenge_scalars()?;

    let r = k + c * x;
    // Add a sequence of scalar elements to the protocol transcript.
    arthur.add_scalars(&[r])?;

    // Output the current protocol transcript as a sequence of bytes.
    Ok(arthur.transcript())
}

/// The verify algorithm takes as input
/// - the verifier state `Merlin`, that has access to a random oracle `H` and can deserialize/squeeze elements from the group `G`.
/// - the secret key `witness`
/// It returns a zero-knowledge proof of knowledge of `witness` as a sequence of bytes.
#[allow(non_snake_case)]
fn verify<G: CurveGroup, H: DuplexHash>(
    // `ArkGroupMelin` contains the veirifier state, including the messages currently read. In addition, it is aware of the group `G`
    // from which it can serialize/deserialize elements.
    merlin: &mut ArkGroupMerlin<G, H>,
    // The group generator `P``
    P: G,
    // The public key `X`
    X: G,
) -> ProofResult<()> {
    // Read the protocol from the transcript:
    let [K] = merlin.next_points().unwrap();
    let [c] = merlin.squeeze_scalars().unwrap();
    let [r] = merlin.next_scalars().unwrap();

    // Check the verification equation, otherwise return a verification error.
    if P * r == K + X * c {
        Ok(())
    } else {
        Err(nimue::ProofError::InvalidProof)
    }
}

#[allow(non_snake_case)]
fn main() {
    // Instantiate the group and the random oracle:
    // Set the group:
    type G = ark_curve25519::EdwardsProjective;
    // Set the hash function (commented out other valid choices):
    type H = nimue::hash::Keccak;
    // type H = nimue::legacy::DigestBridge<blake2::Blake2s256>;
    // type H = nimue::legacy::DigestBridge<sha2::Sha256>;

    // Set up the IO for the protocol transcript with domain separator "nimue::examples::schnorr"
    let io = ArkGroupIOPattern::<G, H>::new("nimue::examples::schnorr")
        .add_points(1, "P")
        .add_points(1, "X")
        .ratchet()
        .add_points(1, "commitment (K)")
        .challenge_scalars(1, "challenge (c)")
        .add_scalars(1, "response (r)");

    // Set up the elements to prove
    let P = G::generator();
    let (x, X) = keygen();

    // Create the prover transcript, add the statement to it, and then invoke the prover.
    let mut arthur = io.to_arthur();
    arthur.public_points(&[P, X]).unwrap();
    arthur.ratchet().unwrap();
    let proof = prove(&mut arthur, P, x).expect("Invalid proof");

    // Print out the hex-encoded schnorr proof.
    println!("Here's a Schnorr signature:\n{}", hex::encode(proof));

    // Verify the proof: create the verifier transcript, add the statement to it, and invoke the verifier.
    let mut merlin = io.to_merlin(proof);
    merlin.public_points(&[P, X]).unwrap();
    merlin.ratchet().unwrap();
    verify(&mut merlin, P, X).expect("Invalid proof");
}
