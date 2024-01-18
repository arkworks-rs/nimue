use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use nimue::{DuplexHash, ProofResult};

use nimue::plugins::arkworks::*;
use rand::rngs::OsRng;

fn keygen<G: CurveGroup>() -> (G::ScalarField, G) {
    let sk = G::ScalarField::rand(&mut OsRng);
    let pk = G::generator() * sk;
    (sk, pk)
}

fn prove<H: DuplexHash<u8>, G: CurveGroup>(
    arthur: &mut ArkGroupArthur<G, H>,
    witness: G::ScalarField,
) -> ProofResult<&[u8]> {
    let k = G::ScalarField::rand(&mut arthur.rng());
    let commitment = G::generator() * k;
    arthur.add_points(&[commitment])?;

    let [challenge] = arthur.challenge_scalars()?;

    let response = k + challenge * witness;
    arthur.add_scalars(&[response])?;

    Ok(arthur.transcript())
}

fn verify<H, G>(merlin: &mut ArkGroupMerlin<G, H>, g: G, pk: G) -> ProofResult<()>
where
    H: DuplexHash<u8>,
    G: CurveGroup,
{
    let [commitment] = merlin.next_points().unwrap();
    let [challenge] = merlin.squeeze_scalars().unwrap();
    let [response] = merlin.next_scalars().unwrap();

    if commitment == g * response - pk * challenge {
        Ok(())
    } else {
        Err(nimue::ProofError::InvalidProof)
    }
}

fn main() {
    // type H = nimue::legacy::DigestBridge<blake2::Blake2s256>;
    // type H = nimue::legacy::DigestBridge<sha2::Sha256>;
    type H = nimue::hash::Keccak;
    type G = ark_curve25519::EdwardsProjective;

    let g = G::generator();
    let (sk, pk) = keygen();

    let io = ArkGroupIOPattern::<G, H>::new("nimue::examples::schnorr")
        .add_points(1, "g")
        .add_points(1, "pk")
        .ratchet()
        .add_points(1, "commitment")
        .challenge_scalars(1, "challenge")
        .add_scalars(1, "response");

    let mut arthur = io.to_arthur();
    arthur.public_points(&[g, pk]).unwrap();
    arthur.ratchet().unwrap();
    let proof = prove(&mut arthur, sk).expect("Valid proof");

    println!("Here's a Schnorr signature:\n{}", hex::encode(proof));

    let mut merlin = io.to_merlin(proof);
    merlin.public_points(&[g, pk]).unwrap();
    merlin.ratchet().unwrap();
    verify(&mut merlin, g, pk).expect("Valid proof");
}
