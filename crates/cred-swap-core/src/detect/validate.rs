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
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(12..=19).contains(&digits.len()) {
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
    sum % 10 == 0
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
    sum % 10 == 0
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
