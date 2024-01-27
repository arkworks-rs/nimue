/// This code is pretty much the same as the one in `schnorr.rs`,
/// except that
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use nimue::plugins::ark::*;

use rand::{rngs::OsRng, CryptoRng, RngCore};

/// Extend the IO pattern with the Schnorr protocol.
trait SchnorrIOPattern<G: CurveGroup> {
    /// Adds the entire Schnorr protocol to the IO pattern (statement and proof).
    fn add_schnorr_io(self) -> Self;
}

impl<G, H, U> SchnorrIOPattern<G> for IOPattern<H, U>
where
    G: CurveGroup,
    U: Unit,
    H: DuplexHash<U>,
    IOPattern<H, U>: GroupIOPattern<G> + ByteIOPattern,
{
    fn add_schnorr_io(self) -> Self {
        self.add_points(1, "generator (P)")
            .add_points(1, "public key (X)")
            .ratchet()
            .add_points(1, "commitment (K)")
            .challenge_bytes(16, "challenge (c)")
            .add_points(1, "response (r)")
    }
}

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
/// - The generator `P` in the group.
/// - the secret key $x \in \mathbb{Z}_p$
/// It returns a zero-knowledge proof of knowledge of `x` as a sequence of bytes.
#[allow(non_snake_case)]
fn aprove<G, H, R>(
    // the hash function `H` works over bytes.
    // Algebraic hashes over a particular domain can be denoted with an additional type argument implementing `nimue::Unit`.
    arthur: &mut Arthur<H, R, G::BaseField>,
    // the generator
    P: G,
    // the secret key
    x: G::ScalarField,
) -> ProofResult<&[u8]>
where
    G::BaseField: Unit,
    R: CryptoRng + RngCore,
    H: DuplexHash<G::BaseField>,
    G: CurveGroup,
    Arthur<H, R, G::BaseField>: GroupWriter<G> + ByteChallenges,
{
    // `Arthur` types implement a cryptographically-secure random number generator that is tied to the protocol transcript
    // and that can be accessed via the `rng()` funciton.
    let k = G::ScalarField::rand(arthur.rng());
    let K = P * k;

    // Add a sequence of points to the protocol transcript.
    // An error is returned in case of failed serialization, or inconsistencies with the IO pattern provided (see below).
    arthur.add_points(&[K])?;

    // Fetch a challenge from the current transcript state.
    let c_bytes = arthur.challenge_bytes::<16>()?;
    let c = G::ScalarField::from_le_bytes_mod_order(&c_bytes);

    let _r = k + c * x;
    // Add a sequence of scalar elements to the protocol transcript.
    // arthur.add_scalars(&[r])?;

    // Output the current protocol transcript as a sequence of bytes.
    Ok(arthur.transcript())
}

/// The verify algorithm takes as input
/// - the verifier state `Merlin`, that has access to a random oracle `H` and can deserialize/squeeze elements from the group `G`.
/// - the secret key `witness`
/// It returns a zero-knowledge proof of knowledge of `witness` as a sequence of bytes.
#[allow(non_snake_case)]
fn averify<'a, G, H>(
    // `ArkGroupMelin` contains the veirifier state, including the messages currently read. In addition, it is aware of the group `G`
    // from which it can serialize/deserialize elements.
    merlin: &mut Merlin<'a, H, G::BaseField>,
    // The group generator `P``
    P: G,
    // The public key `X`
    X: G,
) -> ProofResult<()>
where
    G::BaseField: Unit,
    G: CurveGroup,
    H: DuplexHash<G::BaseField>,
    Merlin<'a, H, G::BaseField>: GroupReader<G> + ByteChallenges,
{
    // Read the protocol from the transcript:
    let [K] = merlin.next_points().unwrap();
    let c_bytes = merlin.challenge_bytes::<16>().unwrap();
    let c = G::ScalarField::from_le_bytes_mod_order(&c_bytes);
    let r = G::ScalarField::from(0);
    // let [r] = merlin.next_scalars().unwrap();

    // Check the verification equation, otherwise return a verification error.
    // The type ProofError is an enum that can report:
    // - InvalidProof: the proof is not valid
    // - InvalidIO: the transcript does not match the IO pattern
    // - SerializationError: there was an error serializing/deserializing an element
    if P * r == K + X * c {
        Ok(())
    } else {
        Err(ProofError::InvalidProof)
    }

    // from here, another proof can be verified using the same merlin instance
    // and proofs can be composed.
}

#[allow(non_snake_case)]
fn main() {
    // Instantiate the group and the random oracle:
    // Set the group:
    type G = ark_bls12_381::G1Projective;
    type Fq = ark_bls12_381::Fq;
    // Set the hash function (commented out other valid choices):
    // type H = nimue::hash::Keccak;
    // type H = nimue::hash::legacy::DigestBridge<blake2::Blake2s256>;
    // type H = nimue::hash::legacy::DigestBridge<sha2::Sha256>;
    type H = nimue::plugins::ark::poseidon::PoseidonHash;

    // Set up the IO for the protocol transcript with domain separator "nimue::examples::schnorr"
    let io = IOPattern::<H, Fq>::new("nimue::examples::schnorr");
    let io = SchnorrIOPattern::<G>::add_schnorr_io(io);

    // Set up the elements to prove
    let P = G::generator();
    let (x, X) = keygen();

    // Create the prover transcript, add the statement to it, and then invoke the prover.
    let mut arthur: Arthur<H, OsRng, Fq> = Arthur::<H, _, Fq>::new(&io, OsRng);
    arthur.public_points(&[P, X]).unwrap();
    arthur.ratchet().unwrap();
    let proof = aprove(&mut arthur, P, x).expect("Invalid proof");

    // Print out the hex-encoded schnorr proof.
    println!("Here's a Schnorr signature:\n{}", hex::encode(proof));

    // Verify the proof: create the verifier transcript, add the statement to it, and invoke the verifier.
    let mut merlin = Merlin::<H, Fq>::new(&io, &proof);
    merlin.public_points(&[P, X]).unwrap();
    merlin.ratchet().unwrap();
    averify(&mut merlin, P, X).expect("Invalid proof");
}
