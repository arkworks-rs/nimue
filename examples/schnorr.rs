use std::ops::Deref;

use ark_ec::{CurveGroup, Group};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use nimue::{Arthur, DuplexHash, InvalidTag};

use nimue::plugins::arkworks::prelude::*;

fn prove<H: DuplexHash<u8>, G: CurveGroup>(
    arthur: &mut Arthur<H>,
    witness: G::ScalarField,
) -> Result<&[u8], InvalidTag>
where
    Arthur<H>: ArkArthur<G, u8>,
{
    let k = G::ScalarField::rand(&mut arthur.rng());
    let commitment = G::generator() * k;
    arthur.absorb_points(&[commitment])?;

    let [challenge] = arthur.squeeze_scalars()?;

    let response = k + challenge * witness;
    arthur.absorb_scalars(&[response])?;

    Ok(arthur.transcript())
}

fn verify<H: DuplexHash<u8>, G: CurveGroup>(
    merlin: &mut Merlin<H, u8>,
    g: G,
    pk: G,
) -> Result<(), &'static str>
where
    for<'a> Merlin<'a, H, u8>: ArkMerlin<G, u8>,
{
    let [commitment] = merlin.absorb_points().unwrap();
    let [challenge] = merlin.squeeze_scalars().unwrap();
    let [response] = merlin.absorb_scalars().unwrap();

    let expected = g * response - pk * challenge;
    if commitment == expected {
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

    let io = AlgebraicIOPattern::<G, H>::new("nimue::examples::schnorr")
        .absorb_points(1, "g")
        .absorb_points(1, "pk")
        .ratchet()
        .absorb_points(1, "commitment")
        .squeeze_scalars(1, "challenge")
        .absorb_scalars(1, "response");
    let sk = F::rand(&mut OsRng);
    let g = G::generator();
    let mut writer = Vec::new();
    g.serialize_compressed(&mut writer).unwrap();
    let pk = (g * &sk).into();

    let mut arthur = Arthur::<H>::new(&io, OsRng);
    arthur.absorb_points(&[g, pk]).unwrap();
    arthur.ratchet().unwrap();
    let proof = prove::<H, G>(&mut arthur, sk).expect("Valid proof");

    // let mut verifier_transcript = Merlin::from(&io);
    // verifier_transcript.absorb_points(&[g, pk]).unwrap();
    // verifier_transcript.ratchet().unwrap();
    // verify::<H, G>(&mut verifier_transcript, g, pk, proof).expect("Valid proof");
}
