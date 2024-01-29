/// Example: simple Schnorr proofs.
///
/// Schnorr proofs allow to prove knowledge of a secret key over a group $\mathbb{G}$ of prime order $p$ where the discrete logarithm problem is hard. In `nimue`, we play with 3 data structures:
///
/// 1. `nimue::IOPattern``
/// The IOPattern describes the protocol.
/// In the case of Schnorr proofs we have also some public information (the generator $P$ and the public key $X$).
/// The protocol, roughly speaking is:
///
/// - P -> V: K, a commitment (point)
/// - V -> P: c, a challenge (scalar)
/// - P -> V: r, a response (scalar)
///
/// 2. `nimue::Arthur`, describes the prover state. It contains the transcript, but not only:
/// it also provides a CSPRNG and a reliable way of serializing elements into a proof, so that the prover does not have to worry about them.
/// It can be instantiated via `IOPattern::to_arthur()`.
///
/// 3. `nimue::Merlin`, describes the verifier state.
/// It internally will read the transcript, and deserialize elements as requested making sure that they match with the IO Pattern.
/// It can be used to verify a proof.
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use nimue::plugins::ark::*;
use rand::rngs::OsRng;

/// Extend the IO pattern with the Schnorr protocol.
trait SchnorrIOPattern<G: CurveGroup> {
    /// Adds the entire Schnorr protocol to the IO pattern (statement and proof).
    fn add_schnorr_io(self) -> Self;
}

impl<G, H> SchnorrIOPattern<G> for IOPattern<H>
where
    G: CurveGroup,
    H: DuplexHash,
    IOPattern<H>: GroupIOPattern<G> + FieldIOPattern<G::ScalarField>,
{
    fn add_schnorr_io(self) -> Self {
        self.add_points(1, "generator (P)")
            .add_points(1, "public key (X)")
            .ratchet()
            .add_points(1, "commitment (K)")
            .challenge_scalars(1, "challenge (c)")
            .add_scalars(1, "response (r)")
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
fn prove<H, G>(
    // the hash function `H` works over bytes.
    // Algebraic hashes over a particular domain can be denoted with an additional type argument implementing `nimue::Unit`.
    arthur: &mut Arthur<H>,
    // the generator
    P: G,
    // the secret key
    x: G::ScalarField,
) -> ProofResult<&[u8]>
where
    H: DuplexHash,
    G: CurveGroup,
    Arthur<H>: GroupWriter<G> + FieldChallenges<G::ScalarField>,
{
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
fn verify<G, H>(
    // `ArkGroupMelin` contains the veirifier state, including the messages currently read. In addition, it is aware of the group `G`
    // from which it can serialize/deserialize elements.
    merlin: &mut Merlin<H>,
    // The group generator `P``
    P: G,
    // The public key `X`
    X: G,
) -> ProofResult<()>
where
    G: CurveGroup,
    H: DuplexHash,
    for<'a> Merlin<'a, H>:
        GroupReader<G> + FieldReader<G::ScalarField> + FieldChallenges<G::ScalarField>,
{
    // Read the protocol from the transcript:
    // XXX. possible inconsistent implementations:
    // if the point is not validated here (but the public key is) then the proof may fail with InvalidProof, instead of SerializationError
    let [K] = merlin.next_points().unwrap();
    let [c] = merlin.challenge_scalars().unwrap();
    let [r] = merlin.next_scalars().unwrap();

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
    type G = ark_curve25519::EdwardsProjective;
    // Set the hash function (commented out other valid choices):
    // type H = nimue::hash::Keccak;
    type H = nimue::hash::legacy::DigestBridge<blake2::Blake2s256>;
    // type H = nimue::hash::legacy::DigestBridge<sha2::Sha256>;

    // Set up the IO for the protocol transcript with domain separator "nimue::examples::schnorr"
    let io = IOPattern::<H>::new("nimue::examples::schnorr");
    let io = SchnorrIOPattern::<G>::add_schnorr_io(io);

    // Set up the elements to prove
    let P = G::generator();
    let (x, X) = keygen();

    // Create the prover transcript, add the statement to it, and then invoke the prover.
    let mut arthur = io.to_arthur();
    arthur.public_points(&[P, P * x]).unwrap();
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
