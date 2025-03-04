/// Example: simple Schnorr proofs.
///
/// Schnorr proofs allow to prove knowledge of a secret key over a group $\mathbb{G}$ of prime order $p$ where the discrete logarithm problem is hard. In `spongefish`, we play with 3 data structures:
///
/// 1. `spongefish::DomainSeparator``
/// The DomainSeparator describes the protocol.
/// In the case of Schnorr proofs we have also some public information (the generator $P$ and the public key $X$).
/// The protocol, roughly speaking is:
///
/// - P -> V: K, a commitment (point)
/// - V -> P: c, a challenge (scalar)
/// - P -> V: r, a response (scalar)
///
/// 2. `spongefish::ProverState`, describes the prover state. It contains the transcript, but not only:
/// it also provides a CSPRNG and a reliable way of serializing elements into a proof, so that the prover does not have to worry about them.
/// It can be instantiated via `DomainSeparator::to_merlin()`.
///
/// 3. `spongefish::VerifierState`, describes the verifier state.
/// It internally will read the transcript, and deserialize elements as requested making sure that they match with the IO Pattern.
/// It can be used to verify a proof.
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use spongefish::codecs::arkworks_algebra::*;
use rand::rngs::OsRng;

/// Extend the IO pattern with the Schnorr protocol.
trait SchnorrDomainSeparator<G: CurveGroup> {
    /// Shortcut: create a new schnorr proof with statement + proof.
    fn new_schnorr_proof(domsep: &str) -> Self;

    /// Add the statement of the Schnorr proof
    fn add_schnorr_statement(self) -> Self;
    /// Add the Schnorr protocol to the IO pattern.
    fn add_schnorr_io(self) -> Self;
}

impl<G, H> SchnorrDomainSeparator<G> for DomainSeparator<H>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
    DomainSeparator<H>: GroupDomainSeparator<G> + FieldDomainSeparator<G::ScalarField>,
{
    fn new_schnorr_proof(domsep: &str) -> Self {
        DomainSeparator::new(domsep)
            .add_schnorr_statement()
            .add_schnorr_io()
    }

    fn add_schnorr_statement(self) -> Self {
        self.add_points(1, "generator (P)")
            .add_points(1, "public key (X)")
            .ratchet()
    }

    fn add_schnorr_io(self) -> Self {
        self.add_points(1, "commitment (K)")
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
/// - the prover state `ProverState`, that has access to a random oracle `H` and can absorb/squeeze elements from the group `G`.
/// - The generator `P` in the group.
/// - the secret key $x \in \mathbb{Z}_p$
/// It returns a zero-knowledge proof of knowledge of `x` as a sequence of bytes.
#[allow(non_snake_case)]
fn prove<H, G>(
    // the hash function `H` works over bytes.
    // Algebraic hashes over a particular domain can be denoted with an additional type argument implementing `spongefish::Unit`.
    merlin: &mut ProverPrivateState<H>,
    // the generator
    P: G,
    // the secret key
    x: G::ScalarField,
) -> ProofResult<&[u8]>
where
    H: DuplexSpongeInterface,
    G: CurveGroup,
    ProverPrivateState<H>: GroupToUnit<G> + UnitToField<G::ScalarField>,
{
    // `ProverState` types implement a cryptographically-secure random number generator that is tied to the protocol transcript
    // and that can be accessed via the `rng()` function.
    let k = G::ScalarField::rand(merlin.rng());
    let K = P * k;

    // Add a sequence of points to the protocol transcript.
    // An error is returned in case of failed serialization, or inconsistencies with the IO pattern provided (see below).
    merlin.add_points(&[K])?;

    // Fetch a challenge from the current transcript state.
    let [c] = merlin.challenge_scalars()?;

    let r = k + c * x;
    // Add a sequence of scalar elements to the protocol transcript.
    merlin.add_scalars(&[r])?;

    // Output the current protocol transcript as a sequence of bytes.
    Ok(merlin.narg_string())
}

/// The verify algorithm takes as input
/// - the verifier state `VerifierState`, that has access to a random oracle `H` and can deserialize/squeeze elements from the group `G`.
/// - the secret key `witness`
/// It returns a zero-knowledge proof of knowledge of `witness` as a sequence of bytes.
#[allow(non_snake_case)]
fn verify<G, H>(
    // `ArkGroupMelin` contains the veirifier state, including the messages currently read. In addition, it is aware of the group `G`
    // from which it can serialize/deserialize elements.
    arthur: &mut VerifierState<H>,
    // The group generator `P``
    P: G,
    // The public key `X`
    X: G,
) -> ProofResult<()>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
    for<'a> VerifierState<'a, H>:
        DeserializeGroup<G> + DeserializeField<G::ScalarField> + UnitToField<G::ScalarField>,
{
    // Read the protocol from the transcript.
    // [[Side note:
    // The method `next_points` internally performs point validation.
    // Another implementation that does not use spongefish might choose not to validate the point here, but only validate the public-key.
    // This leads to different errors to be returned: here the proof fails with SerializationError, whereas the other implementation would fail with InvalidProof.
    // ]]
    let [K] = arthur.next_points().unwrap();
    let [c] = arthur.challenge_scalars().unwrap();
    let [r]: [G::ScalarField; 1] = arthur.next_scalars().unwrap();

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

    // From here, another proof can be verified using the same arthur instance
    // and proofs can be composed. The transcript holds the whole proof,
}

#[allow(non_snake_case)]
fn main() {
    // Instantiate the group and the random oracle:
    // Set the group:
    type G = ark_curve25519::EdwardsProjective;
    // Set the hash function (commented out other valid choices):
    // type H = spongefish::hash::Keccak;
    type H = spongefish::duplex_sponge::legacy::DigestBridge<blake2::Blake2s256>;
    // type H = spongefish::hash::legacy::DigestBridge<sha2::Sha256>;

    // Set up the IO for the protocol transcript with domain separator "spongefish::examples::schnorr"
    let io: DomainSeparator<H> = SchnorrDomainSeparator::<G>::new_schnorr_proof("spongefish::example");

    // Set up the elements to prove
    let P = G::generator();
    let (x, X) = keygen();

    // Create the prover transcript, add the statement to it, and then invoke the prover.
    let mut merlin = io.to_merlin();
    merlin.public_points(&[P, P * x]).unwrap();
    merlin.ratchet().unwrap();
    let proof = prove(&mut merlin, P, x).expect("Invalid proof");

    // Print out the hex-encoded schnorr proof.
    println!("Here's a Schnorr signature:\n{}", hex::encode(proof));

    // Verify the proof: create the verifier transcript, add the statement to it, and invoke the verifier.
    let mut arthur = io.to_verifier_state(proof);
    arthur.public_points(&[P, X]).unwrap();
    arthur.ratchet().unwrap();
    verify(&mut arthur, P, X).expect("Invalid proof");
}
