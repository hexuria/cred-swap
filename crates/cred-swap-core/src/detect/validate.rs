//! Cheap structural checks that turn a "looks like" regex hit into a decision.
//!
//! Regexes over-match by nature. A 16-digit run is not a card number and a
//! 32-character word is not a secret. Each function here answers one question
//! about a candidate so the detector can drop the false positives that would
//! otherwise make the tool noisy enough to be switched off.

/// Verify a card number against the Luhn check digit.
///
/// Non-digit separators (spaces, dashes) are ignored. Anything outside the
/// 12..=19 digit range used by real card schemes is rejected.
#[must_use]
pub fn luhn(candidate: &str) -> bool {
    luhn_of_length(candidate, 12..=19)
}

/// Verify a Canadian Social Insurance Number: nine digits, Luhn checked.
#[must_use]
pub fn canadian_sin(candidate: &str) -> bool {
    luhn_of_length(candidate, 9..=9)
}

/// Luhn over a number whose length belongs to some scheme other than a card.
///
/// Private because the length range is the whole decision: exposing it would
/// invite a caller to pass a range admitting a number the scheme never uses.
fn luhn_of_length(candidate: &str, lengths: std::ops::RangeInclusive<usize>) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if !lengths.contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, &digit)| {
            if index % 2 == 0 {
                digit
            } else {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Verify an IBAN against the ISO 13616 mod-97 checksum.
#[must_use]
pub fn iban_mod97(candidate: &str) -> bool {
    let compact: String = candidate
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if !(15..=34).contains(&compact.len()) || !compact.is_ascii() {
        return false;
    }
    if !compact.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }

    // Move the first four characters to the end, then map letters to numbers.
    let rotated = format!("{}{}", &compact[4..], &compact[..4]);
    let mut remainder: u32 = 0;
    for ch in rotated.chars() {
        let value = if ch.is_ascii_digit() {
            ch as u32 - '0' as u32
        } else {
            ch as u32 - 'A' as u32 + 10
        };
        // Fold in one or two decimal digits at a time to stay inside u32.
        remainder = if value > 9 {
            (remainder * 100 + value) % 97
        } else {
            (remainder * 10 + value) % 97
        };
    }
    remainder == 1
}

/// Verify an ABA routing number against its weighted checksum.
#[must_use]
pub fn aba_routing(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 9 {
        return false;
    }
    let weights = [3, 7, 1, 3, 7, 1, 3, 7, 1];
    let sum: u32 = digits
        .iter()
        .zip(weights)
        .map(|(digit, weight)| digit * weight)
        .sum();
    sum.is_multiple_of(10)
}

/// Shannon entropy of the candidate in bits per character.
///
/// Used to separate a real random secret from an ordinary identifier of the
/// same length. `deployment_configuration_v2` and a 32-byte key are both long;
/// only one of them looks random.
#[must_use]
pub fn shannon_entropy(candidate: &str) -> f64 {
    if candidate.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for byte in candidate.bytes() {
        counts[byte as usize] += 1;
        total += 1;
    }
    #[expect(clippy::cast_precision_loss, reason = "counts are far below 2^53")]
    let total_f = total as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            #[expect(clippy::cast_precision_loss, reason = "counts are far below 2^53")]
            let probability = count as f64 / total_f;
            -probability * probability.log2()
        })
        .sum()
}

/// True when a string is random-looking enough to be treated as a secret.
///
/// The threshold is deliberately conservative. A missed generic secret is
/// usually still caught by one of the vendor-specific patterns; a false
/// positive on every long identifier in a code snippet is not recoverable.
#[must_use]
pub fn looks_random(candidate: &str) -> bool {
    if candidate.len() < 16 {
        return false;
    }
    let has_digit = candidate.bytes().any(|b| b.is_ascii_digit());
    let has_alpha = candidate.bytes().any(|b| b.is_ascii_alphabetic());
    if !(has_digit && has_alpha) {
        return false;
    }
    // Dictionary-ish strings separated into words are configuration, not keys.
    let separator_count = candidate
        .bytes()
        .filter(|b| matches!(b, b'_' | b'-' | b'.' | b' '))
        .count();
    if separator_count > 2 {
        return false;
    }
    shannon_entropy(candidate) >= 3.5
}

/// Reject IPv4 addresses that carry no information about a real host.
#[must_use]
pub fn is_meaningful_ipv4(octets: [u8; 4]) -> bool {
    !matches!(
        octets,
        [0 | 127, ..] | [255, 255, 255, 255] | [169, 254, ..]
    )
}

/// Parse a dotted quad, rejecting out-of-range octets and leading zeroes.
#[must_use]
pub fn parse_ipv4(candidate: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = candidate.split('.');
    for slot in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        *slot = part.parse::<u8>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

/// Verify a Brazilian CPF against its two mod-11 check digits.
#[must_use]
pub fn cpf(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 11 {
        return false;
    }
    // A CPF of eleven identical digits satisfies the arithmetic but is never
    // issued, and these are exactly the values people type as filler.
    if digits.iter().all(|digit| *digit == digits[0]) {
        return false;
    }

    let (first, second) = cpf_check_digits(&digits);
    digits[9] == first && digits[10] == second
}

/// The two mod-11 check digits a Brazilian CPF body requires.
///
/// Shared by the validator and the generator. Two copies of this loop is two
/// chances for a generated stand-in to fail the very check its own validator
/// applies, and nothing else would catch that.
#[must_use]
pub fn cpf_check_digits(body: &[u32]) -> (u32, u32) {
    let mut digits: Vec<u32> = body.iter().copied().take(9).collect();
    for length in [9usize, 10] {
        let sum: u32 = digits[..length]
            .iter()
            .enumerate()
            .map(|(index, digit)| digit * u32::try_from(length + 1 - index).unwrap_or(0))
            .sum();
        let remainder = sum % 11;
        digits.push(if remainder < 2 { 0 } else { 11 - remainder });
    }
    (digits[9], digits[10])
}

/// The positional weights an ABN checksum uses.
const ABN_WEIGHTS: [u32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];

/// Verify an Australian Business Number against its mod-89 checksum.
#[must_use]
pub fn abn(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 11 || digits[0] == 0 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .zip(ABN_WEIGHTS)
        .enumerate()
        // The first digit has one subtracted before weighting.
        .map(|(index, (digit, weight))| if index == 0 { digit - 1 } else { *digit } * weight)
        .sum();
    sum.is_multiple_of(89)
}

/// The positional weights an NRIC check letter uses.
const NRIC_WEIGHTS: [u32; 7] = [2, 7, 6, 5, 4, 3, 2];

/// Verify a Singapore NRIC or FIN against its weighted check letter.
#[must_use]
pub fn nric(candidate: &str) -> bool {
    let bytes: Vec<u8> = candidate.bytes().map(|b| b.to_ascii_uppercase()).collect();
    if bytes.len() != 9 {
        return false;
    }
    let prefix = bytes[0];
    // S, T, F and G only. The M series uses a different check table and a
    // different century offset, and neither could be corroborated well enough
    // to ship: a wrong table silently accepts and rejects the wrong numbers,
    // and the structural test that would normally catch a mistake here holds
    // for any table at all, so it could never have caught one.
    if !matches!(prefix, b'S' | b'T' | b'F' | b'G') {
        return false;
    }
    if !bytes[1..8].iter().all(u8::is_ascii_digit) {
        return false;
    }

    let mut sum: u32 = bytes[1..8]
        .iter()
        .zip(NRIC_WEIGHTS)
        .map(|(byte, weight)| u32::from(byte - b'0') * weight)
        .sum();
    // The century offset: T and G are the 2000s.
    if matches!(prefix, b'T' | b'G') {
        sum += 4;
    }

    let table: &[u8] = match prefix {
        b'S' | b'T' => b"JZIHGFEDCBA",
        _ => b"XWUTRQPNMLK",
    };
    let index = usize::try_from(sum % 11).unwrap_or(0);
    table.get(index).copied() == Some(bytes[8])
}

/// The Verhoeff dihedral multiplication table.
const VERHOEFF_D: [[usize; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
/// The Verhoeff permutation table.
const VERHOEFF_P: [[usize; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Verify a number against the Verhoeff checksum, as India's Aadhaar uses.
#[must_use]
pub fn verhoeff(candidate: &str) -> bool {
    let digits: Vec<usize> = candidate
        .chars()
        .filter_map(|c| c.to_digit(10))
        .filter_map(|d| usize::try_from(d).ok())
        .collect();
    if digits.is_empty() {
        return false;
    }
    let mut check = 0usize;
    for (position, digit) in digits.iter().rev().enumerate() {
        check = VERHOEFF_D[check][VERHOEFF_P[position % 8][*digit]];
    }
    check == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_known_test_numbers() {
        // Publicly documented card-scheme test numbers.
        assert!(luhn("4242424242424242"));
        assert!(luhn("4111 1111 1111 1111"));
        assert!(luhn("5555-5555-5555-4444"));
        assert!(luhn("378282246310005"));
    }

    #[test]
    fn canadian_sin_is_luhn_over_nine_digits() {
        // A SIN is Luhn checked but far shorter than any card.
        assert!(canadian_sin("046 454 286"));
        assert!(!canadian_sin("046 454 287"));
        assert!(!canadian_sin("4242424242424242"), "a card is not a SIN");
        assert!(!luhn("046454286"), "nine digits is not a card length");
    }

    #[test]
    fn luhn_rejects_wrong_check_digit_and_bad_lengths() {
        assert!(!luhn("4242424242424243"));
        assert!(!luhn("1234567890123456"));
        assert!(!luhn("42424242424"));
        assert!(!luhn("42424242424242424242"));
    }

    #[test]
    fn iban_checksum_round_trip() {
        assert!(iban_mod97("GB82 WEST 1234 5698 7654 32"));
        assert!(iban_mod97("DE89370400440532013000"));
        assert!(iban_mod97("FR1420041010050500013M02606"));
        assert!(!iban_mod97("GB82WEST12345698765433"));
        assert!(!iban_mod97("GB82"));
    }

    #[test]
    fn aba_routing_checksum() {
        assert!(aba_routing("021000021"));
        assert!(aba_routing("011401533"));
        assert!(!aba_routing("021000022"));
        assert!(!aba_routing("02100002"));
    }

    #[test]
    fn cpf_check_digits() {
        // Published example values.
        assert!(cpf("529.982.247-25"));
        assert!(cpf("111.444.777-35"));
        assert!(!cpf("529.982.247-26"));
        assert!(!cpf("111.111.111-11"), "a repdigit is never issued");
        assert!(!cpf("529.982.247"));
    }

    #[test]
    fn abn_checksum() {
        assert!(abn("51 824 753 556"));
        assert!(abn("53004085616"));
        assert!(!abn("51 824 753 557"));
        assert!(!abn("01824753556"), "an ABN never starts with zero");
    }

    #[test]
    fn nric_check_letter() {
        // A published example. The rest is checked as a property rather than
        // against invented values: for any stem, exactly one of the eleven
        // check letters can be right, which is what makes the letter useful.
        assert!(nric("S1234567D"));
        assert!(!nric("S1234567A"));
        assert!(!nric("X1234567D"), "X is not an NRIC prefix");
        assert!(
            !nric("M1234567X"),
            "the M series is deliberately not covered"
        );
        assert!(!nric("S123456D"), "too short");

        for prefix in ["S", "T", "F", "G"] {
            let valid = (b'A'..=b'Z')
                .filter(|letter| nric(&format!("{prefix}1234567{}", char::from(*letter))))
                .count();
            assert_eq!(valid, 1, "prefix {prefix} accepted {valid} check letters");
        }
    }

    #[test]
    fn verhoeff_checksum() {
        assert!(verhoeff("2363"));
        assert!(verhoeff("123451"));
        assert!(!verhoeff("2364"));
        assert!(!verhoeff(""));
    }

    #[test]
    fn entropy_separates_words_from_keys() {
        assert!(looks_random("aG7xQ92mZk1pLw83Tb5R"));
        assert!(!looks_random("deployment_config_v2_staging"));
        assert!(!looks_random("shortkey1"));
        assert!(!looks_random("aaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn ipv4_parsing_is_strict() {
        assert_eq!(parse_ipv4("192.168.1.10"), Some([192, 168, 1, 10]));
        assert_eq!(parse_ipv4("256.1.1.1"), None);
        assert_eq!(parse_ipv4("010.1.1.1"), None);
        assert_eq!(parse_ipv4("1.2.3"), None);
        assert_eq!(parse_ipv4("1.2.3.4.5"), None);
    }

    #[test]
    fn loopback_and_broadcast_are_not_worth_masking() {
        assert!(is_meaningful_ipv4([203, 0, 113, 7]));
        assert!(!is_meaningful_ipv4([127, 0, 0, 1]));
        assert!(!is_meaningful_ipv4([169, 254, 1, 1]));
    }
}
