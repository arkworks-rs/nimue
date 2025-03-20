use rand::RngCore;

use crate::duplex_sponge::legacy::DigestBridge;
use crate::permutations::keccak::Keccak;
use crate::{
    VerifierMessageBytes, CommonProverMessageBytes, ByteReader, ByteWriter, DuplexInterface, DomainSeparator,
    ProverState, StatefulHashObject,
};

type Sha2 = DigestBridge<sha2::Sha256>;
type Blake2b512 = DigestBridge<blake2::Blake2b512>;
type Blake2s256 = DigestBridge<blake2::Blake2s256>;

/// How should a protocol without actual IO be handled?
#[test]
fn test_domain_separator() {
    // test that the byte separator is always added
    let domain_separator = DomainSeparator::<Keccak>::new("example.com");
    assert!(domain_separator.as_bytes().starts_with(b"example.com"));
}

/// Test ProverState's rng is not doing completely stupid things.
#[test]
fn test_merlin_rng_basic() {
    let domain_separator = DomainSeparator::<Keccak>::new("example.com");
    let mut merlin = domain_separator.to_merlin();
    let rng = merlin.rng();

    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);
    let random_u32 = rng.next_u32();
    let random_u64 = rng.next_u64();
    assert_ne!(random_bytes, [0u8; 32]);
    assert_ne!(random_u32, 0);
    assert_ne!(random_u64, 0);
    assert!(random_bytes.iter().any(|&x| x != random_bytes[0]));
}

/// Test adding of public bytes and non-public elements to the transcript.
#[test]
fn test_merlin_bytewriter() {
    let domain_separator = DomainSeparator::<Keccak>::new("example.com").absorb(1, "🥕");
    let mut merlin = domain_separator.to_merlin();
    assert!(merlin.add_bytes(&[0u8]).is_ok());
    assert!(merlin.add_bytes(&[1u8]).is_err());
    assert_eq!(
        merlin.narg_string(),
        b"\0",
        "Protocol Transcript survives errors"
    );

    let mut merlin = domain_separator.to_merlin();
    assert!(merlin.public_bytes(&[0u8]).is_ok());
    assert_eq!(merlin.narg_string(), b"");
}

/// A protocol flow that does not match the DomainSeparator should fail.
#[test]
fn test_invalid_io_sequence() {
    let duplexinterface = DomainSeparator::new("example.com").absorb(3, "").squeeze(1, "");
    let mut arthur = StatefulHashObject::<Keccak>::new(&iop);
    assert!(arthur.squeeze(&mut [0u8; 16]).is_err());
}

// Hiding for now. Should it panic ?
// /// A protocol whose IO pattern is not finished should panic.
// #[test]
// #[should_panic]
// fn test_unfinished_io() {
//     let domain_separator = DomainSeparator::new("example.com").absorb(3, "").squeeze(1, "");
//     let _arthur = VerifierState::<Keccak>::new(&iop);
// }

/// Challenges from the same transcript should be equal.
#[test]
fn test_deterministic() {
    let domain_separator = DomainSeparator::new("example.com")
        .absorb(3, "elt")
        .squeeze(16, "another_elt");
    let mut first_sponge = StatefulHashObject::<Keccak>::new(&iop);
    let mut second_sponge = StatefulHashObject::<Keccak>::new(&iop);

    let mut first = [0u8; 16];
    let mut second = [0u8; 16];

    first_sponge.absorb(b"123").unwrap();
    second_sponge.absorb(b"123").unwrap();

    first_sponge.squeeze(&mut first).unwrap();
    second_sponge.squeeze(&mut second).unwrap();
    assert_eq!(first, second);
}

/// Basic statistical test to check that the squeezed output looks random.
#[test]
fn test_statistics() {
    let domain_separator = DomainSeparator::new("example.com")
        .absorb(4, "statement")
        .ratchet()
        .squeeze(2048, "gee");
    let mut arthur = StatefulHashObject::<Keccak>::new(&iop);
    arthur.absorb(b"seed").unwrap();
    arthur.ratchet().unwrap();
    let mut output = [0u8; 2048];
    arthur.squeeze(&mut output).unwrap();

    let frequencies = (0u8..=255)
        .map(|i| output.iter().filter(|&&x| x == i).count())
        .collect::<Vec<_>>();
    // each element should appear roughly 8 times on average. Checking we're not too far from that.
    assert!(frequencies.iter().all(|&x| x < 32 && x > 0));
}

#[test]
fn test_transcript_readwrite() {
    let domain_separator = DomainSeparator::<Keccak>::new("domain separator")
        .absorb(10, "hello")
        .squeeze(10, "world");

    let mut merlin = domain_separator.to_merlin();
    merlin.add_units(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    let merlin_challenges = merlin.challenge_bytes::<10>().unwrap();
    let transcript = merlin.narg_string();

    let mut arthur = domain_separator.to_verifier_state(transcript);
    let mut input = [0u8; 5];
    arthur.fill_next_units(&mut input).unwrap();
    assert_eq!(input, [0, 1, 2, 3, 4]);
    arthur.fill_next_units(&mut input).unwrap();
    assert_eq!(input, [5, 6, 7, 8, 9]);
    let arthur_challenges = arthur.challenge_bytes::<10>().unwrap();
    assert_eq!(arthur_challenges, merlin_challenges);
}

/// An IO that is not fully finished should fail.
#[test]
#[should_panic]
fn test_incomplete_io() {
    let domain_separator = DomainSeparator::<Keccak>::new("domain separator")
        .absorb(10, "hello")
        .squeeze(1, "nop");

    let mut merlin = domain_separator.to_merlin();
    merlin.add_units(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    merlin.fill_challenge_bytes(&mut [0u8; 10]).unwrap();
}

/// The user should respect the IO pattern even with empty length.
#[test]
fn test_merlin_empty_absorb() {
    let domain_separator = DomainSeparator::<Keccak>::new("domain separator")
        .absorb(1, "in")
        .squeeze(1, "something");

    assert!(domain_separator.to_merlin().fill_challenge_bytes(&mut [0u8; 1]).is_err());
    assert!(domain_separator.to_verifier_state(b"").next_bytes::<1>().is_err());
}

/// Absorbs and squeeze over byte-Units should be streamable.
fn test_streaming_absorb_and_squeeze<H: DuplexInterface>()
where
    ProverState<H>: ByteWriter + VerifierMessageBytes,
{
    let bytes = b"yellow submarine";

    let domain_separator = DomainSeparator::<H>::new("domain separator")
        .absorb(16, "some bytes")
        .squeeze(16, "control challenge")
        .absorb(1, "level 2: use this as a prng stream")
        .squeeze(1024, "that's a long challenge");

    let mut merlin = domain_separator.to_merlin();
    merlin.add_bytes(bytes).unwrap();
    let control_chal = merlin.challenge_bytes::<16>().unwrap();
    let control_transcript = merlin.narg_string();

    let mut stream_merlin = domain_separator.to_merlin();
    stream_merlin.add_bytes(&bytes[..10]).unwrap();
    stream_merlin.add_bytes(&bytes[10..]).unwrap();
    let first_chal = stream_merlin.challenge_bytes::<8>().unwrap();
    let second_chal = stream_merlin.challenge_bytes::<8>().unwrap();
    let transcript = stream_merlin.narg_string();

    assert_eq!(transcript, control_transcript);
    assert_eq!(&first_chal[..], &control_chal[..8]);
    assert_eq!(&second_chal[..], &control_chal[8..]);

    merlin.add_bytes(&[0x42]).unwrap();
    stream_merlin.add_bytes(&[0x42]).unwrap();

    let control_chal = merlin.challenge_bytes::<1024>().unwrap();
    for control_chunk in control_chal.chunks(16) {
        let chunk = stream_merlin.challenge_bytes::<16>().unwrap();
        assert_eq!(control_chunk, &chunk[..]);
    }
}

#[test]
fn test_streaming_sha2() {
    test_streaming_absorb_and_squeeze::<Sha2>();
}

#[test]
fn test_streaming_blake2() {
    test_streaming_absorb_and_squeeze::<Blake2b512>();
    test_streaming_absorb_and_squeeze::<Blake2s256>();
}

#[test]
fn test_streaming_keccak() {
    test_streaming_absorb_and_squeeze::<Keccak>();
}
