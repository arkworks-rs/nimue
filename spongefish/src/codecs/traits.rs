macro_rules! field_traits {
    ($Field:path) => {
        /// Absorb and squeeze field elements to the IO pattern.
        pub trait FieldDomainSeparator<F: $Field> {
            fn add_scalars(self, count: usize, label: &str) -> Self;
            fn challenge_scalars(self, count: usize, label: &str) -> Self;
        }

        /// Interpret verifier messages as uniformly distributed field elements.
        ///
        /// The implementation of this trait **MUST** ensure that the field elements
        /// are uniformly distributed and valid.
        pub trait UnitToField<F: $Field> {
            fn fill_challenge_scalars(&mut self, output: &mut [F]) -> $crate::ProofResult<()>;

            fn challenge_scalars<const N: usize>(&mut self) -> crate::ProofResult<[F; N]> {
                let mut output = [F::default(); N];
                self.fill_challenge_scalars(&mut output).map(|()| output)
            }
        }

        /// Add field elements as shared public information.
        pub trait CommonFieldToUnit<F: $Field> {
            type Repr;
            fn public_scalars(&mut self, input: &[F]) -> crate::ProofResult<Self::Repr>;
        }

        /// Add field elements to the protocol transcript.
        pub trait FieldToUnit<F: $Field>: CommonFieldToUnit<F> {
            fn add_scalars(&mut self, input: &[F]) -> crate::ProofResult<()>;
        }

        /// Retrieve field elements from the protocol transcript.
        ///
        /// The implementation of this trait **MUST** ensure that the field elements
        /// are correct encodings.
        pub trait DeserializeField<F: $Field>: CommonFieldToUnit<F> {
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
        pub trait GroupDomainSeparator<G: $Group> {
            fn add_points(self, count: usize, label: &str) -> Self;
        }

        /// Adds a new prover message consisting of an EC element.
        pub trait GroupToUnit<G: $Group>: CommonGroupToUnit<G> {
            fn add_points(&mut self, input: &[G]) -> $crate::ProofResult<()>;
        }

        /// Receive (and deserialize) group elements from the IO pattern.
        ///
        /// The implementation of this trait **MUST** ensure that the points decoded are
        /// valid group elements.
        pub trait DeserializeGroup<G: $Group + Default> {
            /// Deserialize group elements from the protocol transcript into `output`.
            fn fill_next_points(&mut self, output: &mut [G]) -> $crate::ProofResult<()>;

            /// Deserialize group elements from the protocol transcript and return them.
            fn next_points<const N: usize>(&mut self) -> $crate::ProofResult<[G; N]> {
                let mut output = [G::default(); N];
                self.fill_next_points(&mut output).map(|()| output)
            }
        }

        /// Add group elements to the protocol transcript.
        pub trait CommonGroupToUnit<G: $Group> {
            /// In order to be added to the sponge, elements may be serialize into another format.
            /// This associated type represents the format used, so that other implementation can potentially
            /// re-use the serialized element.
            type Repr;

            /// Incorporate group elements into the proof without adding them to the final protocol transcript.
            fn public_points(&mut self, input: &[G]) -> $crate::ProofResult<Self::Repr>;
        }
    };
}

#[cfg(any(feature = "zkcrypto-group", feature = "arkworks-algebra"))]
pub(super) use {field_traits, group_traits};
