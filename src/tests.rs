use crate::{keccak::Keccak, IOPattern, Merlin};

/// How should a protocol without IOPattern be handled?
#[test]
fn test_iopattern() {
    // test that the byte separator is always added
    let iop = IOPattern::new("example.com");
    assert!(iop.as_bytes().starts_with(b"example.com"));
}

/// A protocol flow that does not match the IOPattern should fail.
#[test]
#[should_panic]
fn test_invalid_io_sequence() {
    let iop = IOPattern::new("example.com").absorb(3, "").squeeze(1, "");
    let mut merlin = Merlin::<Keccak>::new(&iop);
    merlin.challenge_bytes(&mut [0u8; 16]).unwrap();
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
        .squeeze(16, "elt");
    let mut first_merlin = Merlin::<Keccak>::new(&iop);
    let mut second_merlin = Merlin::<Keccak>::new(&iop);

    let mut first = [0u8; 16];
    let mut second = [0u8; 16];

    first_merlin.append(b"123").unwrap();
    second_merlin.append(b"123").unwrap();

    first_merlin.challenge_bytes(&mut first).unwrap();
    second_merlin.challenge_bytes(&mut second).unwrap();
    assert_eq!(first, second);
}

/// Basic scatistical test to check that the squeezed output looks random.
#[test]
fn test_statistics() {
    let iop = IOPattern::new("example.com")
        .absorb(4, "statement")
        .ratchet()
        .squeeze(2048, "gee");
    let mut merlin = Merlin::<Keccak>::new(&iop);
    merlin.append(b"seed").unwrap();
    merlin.process().unwrap();
    let mut output = [0u8; 2048];
    merlin.challenge_bytes(&mut output).unwrap();

    let frequencies = (0u8..=255)
        .map(|i| output.iter().filter(|&&x| x == i).count())
        .collect::<Vec<_>>();
    // each element should appear roughly 8 times on average. Checking we're not too far from that.
    assert!(frequencies
        .iter()
        .all(|&x| x < frequencies[0] + 16 && x > 0));
}
