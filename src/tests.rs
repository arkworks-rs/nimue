use crate::hash::keccak::Keccak;
use crate::safe::IOPattern;
use crate::{Arthur, Merlin, Safe};

/// How should a protocol without IOPattern be handled?
#[test]
fn test_iopattern() {
    // test that the byte separator is always added
    let iop = IOPattern::<Keccak>::new("example.com");
    assert!(iop.as_bytes().starts_with(b"example.com"));
}

/// A protocol flow that does not match the IOPattern should fail.
#[test]
#[should_panic]
fn test_invalid_io_sequence() {
    let iop = IOPattern::new("example.com").absorb(3, "").squeeze(1, "");
    let mut merlin = Safe::<Keccak>::new(&iop);
    merlin.squeeze(&mut [0u8; 16]).unwrap();
}

// Hiding for now. Should it panic ?
// /// A protocol whose IO pattern is not finished should panic.
// #[test]
// #[should_panic]
// fn test_unfinished_io() {
//     let iop = IOPattern::new("example.com").absorb(3, "").squeeze(1, "");
//     let _merlin = Merlin::<Keccak>::new(&iop);
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
    let mut merlin = Safe::<Keccak>::new(&iop);
    merlin.absorb(b"seed").unwrap();
    merlin.ratchet().unwrap();
    let mut output = [0u8; 2048];
    merlin.squeeze(&mut output).unwrap();

    let frequencies = (0u8..=255)
        .map(|i| output.iter().filter(|&&x| x == i).count())
        .collect::<Vec<_>>();
    // each element should appear roughly 8 times on average. Checking we're not too far from that.
    assert!(frequencies
        .iter()
        .all(|&x| x < frequencies[0] + 16 && x > 0));
}

#[test]
fn test_merlin() {
    let io = IOPattern::new("domain separator")
        .absorb(10, "hello")
        .squeeze(10, "bye bye");

    let mut arthur = Arthur::<Keccak>::from(&io);
    arthur.add(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    arthur.challenge(&mut [0u8; 10]).unwrap();
    let transcript = arthur.transcript();

    let mut merlin = Merlin::<Keccak>::new(&io, transcript);
    let mut input = [0u8; 5];
    merlin.fill_next(&mut input).unwrap();
    assert_eq!(input, [0, 1, 2, 3, 4]);
    merlin.fill_next(&mut input).unwrap();
    assert_eq!(input, [5, 6, 7, 8, 9]);
}
