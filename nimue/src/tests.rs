use rand::RngCore;

use crate::hash::keccak::Keccak;
use crate::hash::legacy::DigestBridge;
use crate::{
    ByteChallenges, BytePublic, ByteReader, ByteWriter, DuplexHash, IOPattern, Merlin, Safe,
};

type Sha2 = DigestBridge<sha2::Sha256>;
type Blake2b512 = DigestBridge<blake2::Blake2b512>;
type Blake2s256 = DigestBridge<blake2::Blake2s256>;

/// How should a protocol without actual IO be handled?
#[test]
fn test_iopattern() {
    // test that the byte separator is always added
    let iop = IOPattern::<Keccak>::new("example.com");
    assert!(iop.as_bytes().starts_with(b"example.com"));
}

/// Test Merlin's rng is not doing completely stupid things.
#[test]
fn test_merlin_rng_basic() {
    let iop = IOPattern::<Keccak>::new("example.com");
    let mut merlin = iop.to_merlin();
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
    let iop = IOPattern::<Keccak>::new("example.com").absorb(1, "🥕");
    let mut merlin = iop.to_merlin();
    assert!(merlin.add_bytes(&[0u8]).is_ok());
    assert!(merlin.add_bytes(&[1u8]).is_err());
    assert_eq!(
        merlin.transcript(),
        b"\0",
        "Protocol Transcript survives errors"
    );

    let mut merlin = iop.to_merlin();
    assert!(merlin.public_bytes(&[0u8]).is_ok());
    assert_eq!(merlin.transcript(), b"");
}

/// A protocol flow that does not match the IOPattern should fail.
#[test]
fn test_invalid_io_sequence() {
    let iop = IOPattern::new("example.com").absorb(3, "").squeeze(1, "");
    let mut arthur = Safe::<Keccak>::new(&iop);
    assert!(arthur.squeeze(&mut [0u8; 16]).is_err());
}

// Hiding for now. Should it panic ?
// /// A protocol whose IO pattern is not finished should panic.
// #[test]
// #[should_panic]
// fn test_unfinished_io() {
//     let iop = IOPattern::new("example.com").absorb(3, "").squeeze(1, "");
//     let _arthur = Arthur::<Keccak>::new(&iop);
// }

/// Challenges from the same transcript should be equal.
#[test]
fn test_deterministic() {
    let iop = IOPattern::new("example.com")
        .absorb(3, "elt")
        .squeeze(16, "another_elt");
    let mut first_sponge = Safe::<Keccak>::new(&iop);
    let mut second_sponge = Safe::<Keccak>::new(&iop);

    let mut first = [0u8; 16];
    let mut second = [0u8; 16];

    first_sponge.absorb(b"123").unwrap();
    second_sponge.absorb(b"123").unwrap();

    first_sponge.squeeze(&mut first).unwrap();
    second_sponge.squeeze(&mut second).unwrap();
    assert_eq!(first, second);
}

/// Basic scatistical test to check that the squeezed output looks random.
#[test]
fn test_statistics() {
    let iop = IOPattern::new("example.com")
        .absorb(4, "statement")
        .ratchet()
        .squeeze(2048, "gee");
    let mut arthur = Safe::<Keccak>::new(&iop);
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
    let io = IOPattern::<Keccak>::new("domain separator")
        .absorb(10, "hello")
        .squeeze(10, "world");

    let mut merlin = io.to_merlin();
    merlin.add_units(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    let merlin_challenges = merlin.challenge_bytes::<10>().unwrap();
    let transcript = merlin.transcript();

    let mut arthur = io.to_arthur(transcript);
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
    let io = IOPattern::<Keccak>::new("domain separator")
        .absorb(10, "hello")
        .squeeze(1, "nop");

    let mut merlin = io.to_merlin();
    merlin.add_units(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    merlin.fill_challenge_bytes(&mut [0u8; 10]).unwrap();
}

/// The user should respect the IO pattern even with empty length.
#[test]
fn test_merlin_empty_absorb() {
    let io = IOPattern::<Keccak>::new("domain separator")
        .absorb(1, "in")
        .squeeze(1, "something");

    assert!(io.to_merlin().fill_challenge_bytes(&mut [0u8; 1]).is_err());
    assert!(io.to_arthur(b"").next_bytes::<1>().is_err());
}

/// Absorbs and squeeze over byte-Units should be streamable.
fn test_streaming_absorb_and_squeeze<H: DuplexHash>()
where
    Merlin<H>: ByteWriter + ByteChallenges,
{
    let bytes = b"yellow submarine";

    let io = IOPattern::<H>::new("domain separator")
        .absorb(16, "some bytes")
        .squeeze(16, "control challenge")
        .absorb(1, "level 2: use this as a prng stream")
        .squeeze(1024, "that's a long challenge");

    let mut merlin = io.to_merlin();
    merlin.add_bytes(bytes).unwrap();
    let control_chal = merlin.challenge_bytes::<16>().unwrap();
    let control_transcript = merlin.transcript();

    let mut stream_merlin = io.to_merlin();
    stream_merlin.add_bytes(&bytes[..10]).unwrap();
    stream_merlin.add_bytes(&bytes[10..]).unwrap();
    let first_chal = stream_merlin.challenge_bytes::<8>().unwrap();
    let second_chal = stream_merlin.challenge_bytes::<8>().unwrap();
    let transcript = stream_merlin.transcript();

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
