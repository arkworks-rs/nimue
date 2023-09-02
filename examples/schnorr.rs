use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use nimue::ark_plugins::{Absorbable, Absorbs, AlgebraicIO, FieldChallenges};
use nimue::{Arthur, Duplexer, IOPattern, InvalidTag, Merlin};

trait SchnorrIOPattern {
    fn schnorr_statement<G, H: Duplexer>(&self) -> Self
    where
        G: AffineRepr + Absorbable<H::L>;

    fn schnorr_io<G, H: Duplexer>(&self) -> Self
    where
        G: AffineRepr + Absorbable<H::L>;
}

impl SchnorrIOPattern for IOPattern {
    fn schnorr_statement<G, H: Duplexer>(&self) -> Self
    where
        G: AffineRepr + Absorbable<H::L>,
    {
        // the statement: generator and public key
        AlgebraicIO::<H>::from(self)
            .absorb_point::<G>(2)
            // (optional) allow for preprocessing of the generators
            .into()
    }

    /// A Schnorr signature's IO Pattern.
    fn schnorr_io<G, H: Duplexer>(&self) -> IOPattern
    where
        G: AffineRepr + Absorbable<H::L>,
    {
        AlgebraicIO::<H>::from(self)
            // absorb the commitment
            .absorb_point::<G>(1)
            // challenge in bytes
            .squeeze_field::<G::ScalarField>(1)
            .into()
    }
}

fn prove<H: Duplexer, G: AffineRepr + Absorbable<H::L>>(
    transcript: &mut Arthur<H>,
    witness: G::ScalarField,
) -> Result<(G::ScalarField, G::ScalarField), InvalidTag> {
    // Commitment: use the prover transcript to seed randomness.
    let k = G::ScalarField::rand(&mut transcript.rng());
    let commitment = G::generator() * k;
    transcript.append_element(&commitment.into_affine())?;
    // Get a challenge over the field Fr.
    let challenge: G::ScalarField = transcript.field_challenge()?;

    let response = k + challenge * witness;
    let proof = (challenge, response);
    Ok(proof)
}

fn verify<H: Duplexer, G: AffineRepr + Absorbable<H::L>>(
    transcript: &mut Merlin<H>,
    g: G,
    pk: G,
    proof: (G::ScalarField, G::ScalarField),
) -> Result<(), InvalidTag> {
    let (challenge, response) = proof;
    let commitment = g * response - pk * challenge;
    transcript.append_element(&commitment.into_affine())?;
    let challenge2 = transcript.field_challenge::<G::ScalarField>()?;
    if challenge == challenge2 {
        Ok(())
    } else {
        Err("Invalid proof".into())
    }
}

fn main() {
    use rand::rngs::OsRng;

    // type H = nimue::legacy::DigestBridge<blake2::Blake2s256>;
    // type H = nimue::legacy::DigestBridge<sha2::Sha256>;
    type H = nimue::keccak::Keccak;
    type G = ark_bls12_381::G1Affine;
    type F = ark_bls12_381::Fr;

    let io_pattern = IOPattern::new("the domain separator goes here")
        // append the statement (generator, public key)
        .schnorr_statement::<G, H>()
        // process the statement separating it from the rest of the protocol
        .ratchet()
        // add the schnorr io pattern
        .schnorr_io::<G, H>();
    let sk = F::rand(&mut OsRng);
    let g = G::generator();
    let mut writer = Vec::new();
    g.serialize_compressed(&mut writer).unwrap();
    let pk = (g * &sk).into();

    let mut prover_transcript = Arthur::<H>::from(io_pattern.clone());
    prover_transcript.append_elements(&[g, pk]).unwrap();
    prover_transcript.process().unwrap();
    let proof = prove::<H, G>(&mut prover_transcript, sk).expect("Valid proof");

    let mut verifier_transcript = Merlin::from(io_pattern.clone());
    verifier_transcript.append_elements(&[g, pk]).unwrap();
    verifier_transcript.process().unwrap();
    verify::<H, G>(&mut verifier_transcript, g, pk, proof).expect("Valid proof");
}
