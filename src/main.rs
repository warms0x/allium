
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use regex;
use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;

fn main() {
    let mut found = false;
    let mut csprng = rand::thread_rng();
    let matcher = regex::Regex::new("(?i)^test").expect("Failed to make regex");

    while ! found {
        let     secret = EphemeralSecret::new(&mut csprng);
        let     public = PublicKey::from(&secret);

        let b32_public = base32::encode(base32::Alphabet::RFC4648 { padding: false }, public.as_bytes());

        if matcher.is_match(&b32_public) {
            found = true;

            let secret = secret.diffie_hellman(&public);
            let b32_secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, secret.as_bytes());
            println!("secret: {}", b32_secret);
            println!("public: {}", b32_public);
            println!("hostname: {}", format_hostname(public.as_bytes().to_vec()));
       }
    }
}

/**
 * This function handles formatting a public key into the appropriate .onion address.
 *
 * Will panic if the `public_key` is not a 32-byte Vec
 */
fn format_hostname(public_key: Vec<u8>) -> String {
    assert_eq!(32, public_key.len());
    // create a SHA3-256 object
    let mut hasher = Sha3::sha3_256();
    hasher.input_str(".onion checksum");
    hasher.input(&public_key);
    hasher.input(&[0x03]);

    let mut checksum = vec![0; hasher.output_bytes()];
    hasher.result(&mut checksum);
    hasher.reset();

	let mut output = vec![];
    output.extend_from_slice(&public_key);
    output.extend_from_slice(&checksum[0..2]);
    output.push(0x03);

	let output = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &output);
    format!("{}.onion", output.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::*;

    /**
     * Test formatting a hostname with a known public key
     */
    #[test]
    fn test_format_hostname() {
        let bytes = read("test/hs_ed25519_public_key")
            .expect("Falied to open pub key file");
        // The last 32 bytes of the buffer are the actual public key
        let pubkey = &bytes[32..];
        let hostname = "test6bvdm2jfhevm2d622bhopvzyuy5mxez2gyflqii5p3jszeeodvad.onion";

        assert_eq!(hostname, format_hostname(pubkey.to_vec()));
    }
}
