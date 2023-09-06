use ark_ec::{CurveGroup, Group};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use nimue::{Arthur, DuplexHash, IOPattern, InvalidTag, Merlin};

use nimue::plugins::arkworks::prelude::*;

trait SchnorrIOPattern {
    fn schnorr_statement<G>(self) -> Self
    where
        G: CurveGroup;

    fn schnorr_io<G>(self) -> Self
    where
        G: CurveGroup;
}

impl<H: DuplexHash<U = u8>> SchnorrIOPattern for IOPattern<H> {
    fn schnorr_statement<G>(self) -> Self
    where
        G: CurveGroup,
    {
        // the statement: generator and public key
        self.absorb_serializable::<G>(1, "generator")
            .absorb_serializable::<G>(1, "public-key")
            // (optional) allow for preprocessing of the generators
            .ratchet()
    }

    /// A Schnorr signature's IO Pattern.
    fn schnorr_io<G>(self) -> IOPattern<H>
    where
        G: CurveGroup,
    {
        self
            // absorb the commitment
            .absorb_serializable::<G>(1, "commitment")
            // challenge in bytes
            .absorb_serializable::<G::ScalarField>(1, "challenge")
            .ratchet()
    }
}

fn prove<H: DuplexHash<U = u8>, G: CurveGroup>(
    arthur: &mut Arthur<H>,
    witness: G::ScalarField,
) -> Result<(G::ScalarField, G::ScalarField), InvalidTag> {
    // Commitment: use the prover transcript to seed randomness.
    let k = G::ScalarField::rand(&mut arthur.rng());
    let commitment = G::generator() * k;
    arthur.absorb_serializable(&[commitment]).unwrap();
    // Get a challenge over the field Fr.
    let challenge: G::ScalarField = arthur.squeeze_pfelt()?;

    let response = k + challenge * witness;
    let proof = (challenge, response);
    Ok(proof)
}

fn verify<H: DuplexHash<U=u8>, G: CurveGroup>(
    transcript: &mut Merlin<H, u8>,
    g: G,
    pk: G,
    proof: (G::ScalarField, G::ScalarField),
) -> Result<(), &'static str> {
    let (challenge, response) = proof;
    let commitment = g * response - pk * challenge;
    transcript.absorb_serializable(&[commitment]).unwrap();
    let challenge2 = transcript.squeeze_pfelt::<G::ScalarField>().unwrap();
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
    type H = nimue::hash::Keccak;
    type G = ark_bls12_381::G1Projective;
    type F = ark_bls12_381::Fr;

    let io = IOPattern::new("the domain separator goes here")
        // append the statement (generator, public key)
        .schnorr_statement::<G>()
        // process the statement separating it from the rest of the protocol
        .ratchet()
        // add the schnorr io pattern
        .schnorr_io::<G>();
    let sk = F::rand(&mut OsRng);
    let g = G::generator();
    let mut writer = Vec::new();
    g.serialize_compressed(&mut writer).unwrap();
    let pk = (g * &sk).into();

    let mut prover_transcript = Arthur::<H>::from(&io);
    prover_transcript.absorb_serializable(&[g, pk]).unwrap();
    prover_transcript.ratchet().unwrap();
    let proof = prove::<H, G>(&mut prover_transcript, sk).expect("Valid proof");

    let mut verifier_transcript = Merlin::from(&io);
    verifier_transcript.absorb_serializable(&[g, pk]).unwrap();
    verifier_transcript.ratchet().unwrap();
    verify::<H, G>(&mut verifier_transcript, g, pk, proof).expect("Valid proof");
}
