use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use nimue::arkworks_plugins::{Absorbable, Absorbs, AlgebraicIO, FieldChallenges};
use nimue::{Duplexer, IOPattern, InvalidTag, Merlin, Transcript};

trait SchnorrIOPattern {
    fn schnorr_io<G, S: Duplexer>(&self) -> Self
    where
        G: AffineRepr + Absorbable<S::L>;
}

impl SchnorrIOPattern for IOPattern {
    /// A Schnorr signature's IO Pattern.
    fn schnorr_io<G, S: Duplexer>(&self) -> IOPattern
    where
        G: AffineRepr + Absorbable<S::L>,
    {
        AlgebraicIO::<S>::from(self)
            // the statement: generator and public key
            .absorb_point::<G>(2)
            // (optional) allow for preprocessing of the generators
            .process()
            // absorb the commitment
            .absorb_point::<G>(1)
            // challenge in bytes
            .squeeze_field::<G::ScalarField>(1)
            .into()
    }
}

fn schnorr_proof<S: Duplexer, G: AffineRepr + Absorbable<S::L>>(
    transcript: &mut Transcript<S>,
    sk: G::ScalarField,
    g: G,
    pk: G,
) -> Result<(G::ScalarField, G::ScalarField), InvalidTag> {
    // Absorb the statement: generator and public key.
    transcript.append_elements(&[g, pk])?;
    // Finish the block.
    transcript.process()?;

    // Commitment: use the prover transcript to seed randomness.
    let k = G::ScalarField::rand(&mut transcript.rng());
    let commitment = G::generator() * k;
    transcript.append_element(&commitment.into_affine())?;
    // Get a challenge over the field Fr.
    let _challenge: G::ScalarField = transcript.field_challenge()?;
    let challenge = transcript.field_challenge()?;


    let response = k + challenge * sk;
    let proof = (challenge, response);
    Ok(proof)
}

fn verify<S: Duplexer, G: AffineRepr + Absorbable<S::L>>(
    transcript: &mut Merlin<S>,
    g: G,
    pk: G,
    proof: (G::ScalarField, G::ScalarField),
) -> Result<(), InvalidTag> {
    transcript.append_elements(&[g, pk])?;
    transcript.process()?;
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

    let io_pattern = IOPattern::new("domsep").schnorr_io::<G, H>();
    let sk = F::rand(&mut OsRng);
    let g = G::generator();
    let mut writer = Vec::new();
    g.serialize_compressed(&mut writer).unwrap();
    let pk = (g * &sk).into();
    let mut prover_transcript = Transcript::<H>::from(io_pattern.clone());
    let mut verifier_transcript = Merlin::from(io_pattern.clone());
    let proof = schnorr_proof::<H, G>(&mut prover_transcript, sk, g, pk).expect("Valid proof");
    verify::<H, G>(&mut verifier_transcript, g, pk, proof).expect("Valid proof");
}
