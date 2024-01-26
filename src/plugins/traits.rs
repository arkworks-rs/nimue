#[macro_export]
macro_rules! field_traits {
    ($Field:path) => {
        pub trait FieldIOPattern<F: $Field> {
            fn add_scalars(self, count: usize, label: &str) -> Self;

            fn challenge_scalars(self, count: usize, label: &str) -> Self;
        }

        pub trait FieldChallenges<F: $Field> {
            fn fill_challenge_scalars(&mut self, output: &mut [F]) -> crate::ProofResult<()>;

            fn challenge_scalars<const N: usize>(&mut self) -> crate::ProofResult<[F; N]> {
                let mut output = [F::default(); N];
                self.fill_challenge_scalars(&mut output).map(|()| output)
            }
        }

        pub trait FieldPublic<F: $Field> {
            type Repr;
            fn public_scalars(&mut self, input: &[F]) -> crate::ProofResult<Self::Repr>;
        }

        pub trait FieldWriter<F: $Field>: FieldChallenges<F> + FieldPublic<F> {
            fn add_scalars(&mut self, input: &[F]) -> crate::ProofResult<()>;
        }

        pub trait FieldReader<F: $Field>: FieldChallenges<F> + FieldPublic<F> {
            fn fill_next_scalars(&mut self, output: &mut [F]) -> crate::ProofResult<()>;

            fn next_scalars<const N: usize>(&mut self) -> crate::ProofResult<[F; N]> {
                let mut output = [F::default(); N];
                self.fill_next_scalars(&mut output).map(|()| output)
            }
        }
    };
}

#[macro_export]
macro_rules! group_traits {
    ($Group:path, $ScalarField:path : $Field:path) => {
        pub trait GroupIOPattern<G: $Group>: FieldIOPattern<$ScalarField> {
            fn add_points(self, count: usize, label: &str) -> Self;
        }

        pub trait GroupWriter<G: $Group>: FieldWriter<$ScalarField> {
            fn add_points(&mut self, input: &[G]) -> crate::ProofResult<()>;
        }

        pub trait GroupReader<G: $Group + Default>: FieldReader<$ScalarField> {
            fn fill_next_points(&mut self, output: &mut [G]) -> crate::ProofResult<()>;

            fn next_points<const N: usize>(&mut self) -> crate::ProofResult<[G; N]> {
                let mut output = [G::default(); N];
                self.fill_next_points(&mut output).map(|()| output)
            }
        }

        pub trait GroupPublic<G: $Group> {
            type Repr;
            fn public_points(&mut self, input: &[G]) -> crate::ProofResult<Self::Repr>;
        }
    };
}

#[cfg(any(feature = "group", feature = "ark"))]
pub(super) use {field_traits, group_traits};
