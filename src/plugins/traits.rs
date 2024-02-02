macro_rules! field_traits {
    ($Field:path) => {
        /// Absorb and squeeze field elements to the IO pattern.
        pub trait FieldIOPattern<F: $Field> {
            fn add_scalars(self, count: usize, label: &str) -> Self;
            fn challenge_scalars(self, count: usize, label: &str) -> Self;
        }

        /// Interpret verifier messages as uniformly distributed field elements.
        ///
        /// The implementation of this trait **MUST** ensure that the field elements
        /// are uniformly distributed and valid.
        pub trait FieldChallenges<F: $Field> {
            fn fill_challenge_scalars(&mut self, output: &mut [F]) -> $crate::ProofResult<()>;

            fn challenge_scalars<const N: usize>(&mut self) -> crate::ProofResult<[F; N]> {
                let mut output = [F::default(); N];
                self.fill_challenge_scalars(&mut output).map(|()| output)
            }
        }

        /// Add field elements as shared public information.
        pub trait FieldPublic<F: $Field> {
            type Repr;
            fn public_scalars(&mut self, input: &[F]) -> crate::ProofResult<Self::Repr>;
        }

        /// Add field elements to the protocol transcript.
        pub trait FieldWriter<F: $Field>: FieldPublic<F> {
            fn add_scalars(&mut self, input: &[F]) -> crate::ProofResult<()>;
        }

        /// Retrieve field elements from the protocol trainscript.
        ///
        /// The implementation of this trait **MUST** ensure that the field elements
        /// are correct encodings.
        pub trait FieldReader<F: $Field>: FieldPublic<F> {
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
    ($Group:path, Scalar: $Field:path) => {
        /// Send group elements in the IO pattern.
        pub trait GroupIOPattern<G: $Group> {
            fn add_points(self, count: usize, label: &str) -> Self;
        }

        /// Add points to the protocol transcript.
        pub trait GroupWriter<G: $Group>: GroupPublic<G> {
            fn add_points(&mut self, input: &[G]) -> $crate::ProofResult<()>;
        }

        /// Receive (and deserialize) group elements from the IO pattern.
        ///
        /// The implementation of this trait **MUST** ensure that the points decoded are
        /// valid group elements.
        pub trait GroupReader<G: $Group + Default> {
            /// Deserialize group elements from the protocol transcript into `output`.
            fn fill_next_points(&mut self, output: &mut [G]) -> $crate::ProofResult<()>;

            /// Deserialize group elements from the protocol transcript and return them.
            fn next_points<const N: usize>(&mut self) -> $crate::ProofResult<[G; N]> {
                let mut output = [G::default(); N];
                self.fill_next_points(&mut output).map(|()| output)
            }
        }

        /// Add group elements to the protocol transcript.
        pub trait GroupPublic<G: $Group> {
            /// In order to be added to the sponge, elements may be serialize into another format.
            /// This associated type represents the format used, so that other implementation can potentially
            /// re-use the serialized element.
            type Repr;

            /// Incorporate group elments into the proof without adding them to the final protocol transcript.
            fn public_points(&mut self, input: &[G]) -> $crate::ProofResult<Self::Repr>;
        }
    };
}

#[cfg(any(feature = "group", feature = "ark"))]
pub(super) use {field_traits, group_traits};
