use ark_ec::{CurveGroup, Group};
use ark_std::UniformRand;
use nimue::{Arthur, DuplexHash, InvalidTag};

use nimue::plugins::arkworks::prelude::*;
use rand::rngs::OsRng;

fn keygen<G: CurveGroup>() -> (G::ScalarField, G) {
    let sk = G::ScalarField::rand(&mut OsRng);
    let pk = G::generator() * sk;
    (sk, pk)
}

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

fn verify<H, G>(merlin: &mut Merlin<H, u8>, g: G, pk: G) -> Result<(), &'static str>
where
    H: DuplexHash<u8>,
    G: CurveGroup,
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
    // type H = nimue::legacy::DigestBridge<blake2::Blake2s256>;
    // type H = nimue::legacy::DigestBridge<sha2::Sha256>;
    type H = nimue::hash::Keccak;
    type G = ark_curve25519::EdwardsProjective;

    let g = G::generator();
    let (sk, pk) = keygen();

    let io = AlgebraicIOPattern::<G, H>::new("nimue::examples::schnorr")
        .absorb_points(1, "g")
        .absorb_points(1, "pk")
        .ratchet()
        .absorb_points(1, "commitment")
        .squeeze_scalars(1, "challenge")
        .absorb_scalars(1, "response");


    let mut arthur = Arthur::<H>::new(&io, OsRng);
    arthur.public_points(&[g, pk]).unwrap();
    arthur.ratchet().unwrap();
    let proof = prove::<H, G>(&mut arthur, sk).expect("Valid proof");

    println!("Here's a Schnorr signature:\n{}", hex::encode(proof));

    let mut merlin = Merlin::new(&io, proof);
    merlin.public_points(&[g, pk]).unwrap();
    merlin.ratchet().unwrap();
    verify::<H, G>(&mut merlin, g, pk).expect("Valid proof");
}
