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
    fn schnorr_io<G, S: Duplexer>(&self) -> IOPattern
    where
        G: AffineRepr + Absorbable<S::L>,
    {
        AlgebraicIO::<S>::from(self)
            .absorb_point::<G>(2)
            .process()
            .absorb_point::<G>(1)
            .squeeze_bytes(16)
            .into()
    }
}

fn schnorr_proof<S: Duplexer, G: AffineRepr + Absorbable<S::L>>(
    transcript: &mut Transcript<S>,
    sk: G::ScalarField,
    g: G,
    pk: G,
) -> Result<(G::ScalarField, G::ScalarField), InvalidTag> {
    // Absorb the statement.
    transcript.append_element(&g)?;
    transcript.append_element(&pk)?.process()?;

    // Commitment: use the prover transcript to seed randomness.
    let k = G::ScalarField::rand(&mut transcript.rng());
    let commitment = G::generator() * k;
    transcript.append_element(&commitment.into_affine())?;
    // Get a challenge of 16 bytes and map it into the field Fr.
    let challenge = transcript.short_field_challenge::<G::ScalarField>(16)?;
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
    transcript.append_element(&g)?;
    transcript.append_element(&pk)?.process()?;
    let (challenge, response) = proof;
    let commitment = g * response - pk * challenge;
    transcript.append_element(&commitment.into_affine())?;
    let challenge2 = transcript.short_field_challenge::<G::ScalarField>(16)?;
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
    // type H = nimue::keccak::Keccak;
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
