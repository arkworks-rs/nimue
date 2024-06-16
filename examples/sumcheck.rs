//! This is the example of a.
//!
//! Sumcheck proofs allow to prove that, given a multilinear polynomial $g$
//! defined over field $\mathbb{F}$, the sum of $g$ over boolean hypercube
//! is equal to $C$.
//!

// TODO Add doc for rust-analyzer.cargo.features for examples.
use ark_ff::PrimeField;
use ark_poly::MultilinearExtension;
use nimue::plugins::ark::{FieldChallenges, FieldIOPattern, FieldReader, FieldWriter};
use nimue::{Arthur, IOPattern, Merlin, ProofError, ProofResult};

trait SumcheckIOPattern<F: PrimeField> {
    fn add_sumcheck(self, num_var: usize) -> Self;
}

impl<F> SumcheckIOPattern<F> for IOPattern
where
    F: PrimeField,
    IOPattern: FieldIOPattern<F>,
{
    fn add_sumcheck(mut self, num_var: usize) -> Self {
        for _ in 0..num_var {
            self = self
                .add_scalars(1, "partial evaluation, constant term")
                .challenge_scalars(1, "sumcheck challenge");
        }
        self = self.add_scalars(1, "folded polynomial");
        self
    }
}

fn prove<'a, F>(
    merlin: &'a mut Merlin,
    polynomial: &impl MultilinearExtension<F>,
) -> ProofResult<&'a mut Merlin>
where
    F: PrimeField,
    Merlin: FieldWriter<F> + FieldChallenges<F>,
{
    let mut round_polynomial = polynomial.clone();
    for _round in 0..polynomial.num_vars() {
        let eval = round_polynomial.to_evaluations();
        // The partial polynomial of each round is of the form b * x + a.
        let round_message = eval.iter().step_by(2).sum();
        merlin.add_scalars(&[round_message])?;
        let [challenge] = merlin.challenge_scalars()?;
        round_polynomial = round_polynomial.fix_variables(&[challenge]);
    }
    // The last round message
    let folded_polynomial = round_polynomial.to_evaluations()[0];
    // One may also check that the folded polynomial is equal to the polynomial evaluated at the challenges
    // defining `challenges` as the vector of challenges in each round.
    // debug_assert_eq!(polynomial.evaluate(&challenges), folded);
    merlin.add_scalars(&[folded_polynomial])?;
    Ok(merlin)
}

fn verify<F>(
    arthur: &mut Arthur,
    polynomial: &impl MultilinearExtension<F>,
    mut value: F,
) -> ProofResult<()>
where
    F: PrimeField,
    for<'a> Arthur<'a>: FieldReader<F> + FieldChallenges<F>,
{
    let num_vars = polynomial.num_vars();
    for _ in 0..num_vars {
        let [a] = arthur.next_scalars()?;
        let b = value - a.double();
        let [r] = arthur.challenge_scalars()?;
        value = b * r + a;
    }
    let [folded] = arthur.next_scalars()?;
    if folded != value {
        Err(ProofError::InvalidProof)
    } else {
        Ok(())
    }
}

fn main() {
    use ark_curve25519::Fq;
    use ark_poly::DenseMultilinearExtension;
    use rand::rngs::OsRng;

    let num_vars = 4;

    // Initialize the IO Pattern putting the domain separator
    let iopattern = IOPattern::new("test sumcheck protocol");

    // !Warning! A good practice would be to add here the statement of the proof being performed,
    // but this example is just performing the information-theoretic part of protocol and is not a full proof.

    // Add the IO of the sumcheck protocol (the transcript)
    let iopattern = SumcheckIOPattern::<Fq>::add_sumcheck(iopattern, num_vars);

    let polynomial: DenseMultilinearExtension<Fq> = DenseMultilinearExtension::rand(num_vars, &mut OsRng);
    let statement = polynomial.to_evaluations().iter().sum::<Fq>();

    let mut merlin = iopattern.to_merlin();
    // merlin.ratchet().unwrap();
    let proof = prove(&mut merlin, &polynomial).expect("Error proving");
    println!(
        "Here's the transcript for the sumcheck protocol over a polynomial in {} variables:\n{}",
        num_vars,
        hex::encode(proof.transcript())
    );

    let mut arthur = iopattern.to_arthur(proof.transcript());
    verify(&mut arthur, &polynomial, statement).expect("Invalid proof");
}
