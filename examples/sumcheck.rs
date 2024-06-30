//! Example: multilinear sumcheck proofs.
//!
//! Sumcheck proofs allow to prove that, given a multilinear polynomial $g$
//! defined over field $\mathbb{F}$, the sum of $g$ over boolean hypercube
//! is equal to $C$.
//!
//! In the interactive version of the protocol, the number of rounds is equal
//! to the number of variables. In each round, the prover sums the
//! "round polynomial" over all the variables except for the first variable,
//! and gets a linear polynomial described by two points. Then, it sends the
//! description to the verifier, gets a challenge from the verifier, fixes the
//! first variable of round polynomial on that challenge and obtains the next
//! round polynomial (with one fewer variable).
//!
//! The verifier in each round checks whether the sum of received polynomial
//! over boolean hypercube is equal to the expected value set in the previous
//! round. If not, it rejects. In the final round, it checks whether the
//! evaluation of the received polynomial at the challenge is equal to
//! evaluation of the $g$ at the tuple of all challenges. If not, it rejects.
//!
//! In the Fiat-Shamir-transformed sumcheck, we do the same, with a minor
//! optimization to reduce the transcript size. The prover, sends only one
//! point as the description of the sent polynomial in each round. The verifier
//! "deduces" the second point using the expected value that is set in the
//! previous round. In the case of dishonest prover, this deduction results in
//! the rejection in the last round.

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
        // The message polynomial is of the form $b * x + a$. As explained at
        //the beginning of the file, the prover is required to send only $a$.
        let round_message = eval.iter().step_by(2).sum();
        merlin.add_scalars(&[round_message])?;
        let [challenge] = merlin.challenge_scalars()?;
        round_polynomial = round_polynomial.fix_variables(&[challenge]);
    }
    // The last round message
    let folded_polynomial = round_polynomial.to_evaluations()[0];
    // One may also check that the folded polynomial is equal to the polynomial evaluated at the challenges
    // defining `challenges` as the vector of challenges in each round.
    // debug_assert_eq!(polynomial.evaluate(&challenges), folded_polynomial);
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
        // The message polynomial is of the form $b * x + a$. The verifier
        // expects $value = (b * 0 + a) + (b * 1 + a)$.
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

    let polynomial: DenseMultilinearExtension<Fq> =
        DenseMultilinearExtension::rand(num_vars, &mut OsRng);
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
