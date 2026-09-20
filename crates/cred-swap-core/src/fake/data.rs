//! Word lists for human-readable surrogates.
//!
//! Deliberately small and bland. A surrogate has to read as an ordinary value
//! so the model treats it normally, without being memorable enough that a
//! reader mistakes it for the real thing.

/// Unisex given names, so a stand-in never implies a gender the original did not.
pub const GIVEN_NAMES: &[&str] = &[
    "Avery", "Rowan", "Quinn", "Harper", "Emerson", "Finley", "Sawyer", "Reese", "Marlow", "Ellis",
    "Hollis", "Sutton", "Tatum", "Blake", "Cameron", "Devon", "Elliot", "Frankie", "Greer",
    "Haven", "Indigo", "Jules", "Kendall", "Lennox", "Mercer", "Noel", "Oakley", "Parker", "Remy",
    "Sloane", "Teagan", "Vale", "Wren", "Arden", "Briar", "Cassidy", "Dallas", "Eden", "Flynn",
    "Gale", "Hayden", "Isley", "Jordan", "Kai", "Lane", "Monroe", "Nova", "Onyx", "Payton",
    "Reagan", "Shiloh", "Tory", "Umber", "Vesper", "Winter", "Xen", "Yael", "Zephyr", "Ainsley",
    "Bellamy", "Caelan", "Darby", "Ever", "Fable",
];

/// Family names with no strong national association.
pub const FAMILY_NAMES: &[&str] = &[
    "Ashford",
    "Barlow",
    "Cartwright",
    "Delacroix",
    "Ellington",
    "Fairbanks",
    "Granger",
    "Halloway",
    "Ingram",
    "Jennings",
    "Kingsley",
    "Lockhart",
    "Merriweather",
    "Northcott",
    "Oakhurst",
    "Pemberton",
    "Quillon",
    "Ravensworth",
    "Sinclair",
    "Thorncroft",
    "Underwood",
    "Vandermeer",
    "Whitfield",
    "Yarborough",
    "Abernathy",
    "Blackwood",
    "Castellan",
    "Dunmore",
    "Eastwick",
    "Fenwick",
    "Gilchrist",
    "Hartwell",
    "Ironside",
    "Jarrow",
    "Kerrigan",
    "Lindqvist",
    "Mortimer",
    "Nightingale",
    "Oberlin",
    "Prescott",
    "Quimby",
    "Rutherford",
    "Stanhope",
    "Trelawney",
    "Ulverston",
    "Vexley",
    "Windermere",
    "Zabrowski",
];

/// Street name stems, also reused for URL path segments.
pub const STREET_NAMES: &[&str] = &[
    "Alder",
    "Birch",
    "Cedar",
    "Dogwood",
    "Elm",
    "Fernway",
    "Grove",
    "Hawthorn",
    "Ironwood",
    "Juniper",
    "Kestrel",
    "Laurel",
    "Maple",
    "Nightjar",
    "Orchard",
    "Poplar",
    "Quarry",
    "Rosewood",
    "Sycamore",
    "Tamarack",
    "Union",
    "Vinewood",
    "Willow",
    "Yarrow",
    "Amberly",
    "Brookfield",
    "Clearwater",
    "Dovecote",
    "Eastgate",
    "Foxglove",
    "Granite",
    "Harborview",
    "Inlet",
    "Jasper",
    "Kingfisher",
    "Longmeadow",
    "Millrace",
    "Northfield",
    "Oldbridge",
    "Prairie",
];

/// Street type suffixes.
pub const STREET_SUFFIXES: &[&str] = &[
    "Street", "Avenue", "Road", "Lane", "Drive", "Court", "Way", "Terrace",
];

/// Second-level labels under a reserved TLD.
///
/// Every generated hostname sits under `.example`, `.invalid` or `.test`,
/// which RFC 2606 and RFC 6761 reserve. A surrogate can therefore never
/// resolve to a domain someone owns.
pub const DOMAIN_LABELS: &[&str] = &[
    "northwind",
    "contoso",
    "initech",
    "umbrella",
    "hooli",
    "vandelay",
    "globex",
    "soylent",
    "acme",
    "stark",
    "wayne",
    "tyrell",
];

/// Top-level domains reserved by RFC 2606 and RFC 6761.
pub const RESERVED_TLDS: &[&str] = &["example", "invalid", "test"];

/// Invented place names, used in generated passphrases.
pub const CITIES: &[&str] = &[
    "Fairhaven",
    "Brookvale",
    "Northport",
    "Westmere",
    "Ashbourne",
    "Greenridge",
    "Stonebrook",
    "Lakemont",
    "Rivermouth",
    "Highfield",
    "Elmcrest",
    "Bayside",
];

/// Uppercase alphanumeric, used where a format demands it (AWS key ids, BICs).
pub const UPPER_ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Mixed alphanumeric, the common case for opaque tokens.
pub const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// URL-safe base64 alphabet, for JWT segments and similar.
pub const BASE64_URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Standard base64 alphabet, for AWS secret keys and basic-auth blobs.
pub const BASE64_STD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Lowercase hexadecimal, for MAC addresses, IPv6 groups and UUIDs.
pub const HEX_LOWER: &[u8] = b"0123456789abcdef";

/// Base58 without the visually ambiguous characters, for crypto addresses.
pub const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Bech32 data alphabet, for `bc1` addresses.
pub const BECH32: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
