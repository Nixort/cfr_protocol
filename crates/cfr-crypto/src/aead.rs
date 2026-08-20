// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Authenticated encryption helpers.
use crate::CryptoError;
use aegis::aegis256::Aegis256;
use alloc::vec::Vec;

/// Width of the AEGIS-256 authentication tag used by CFR.
pub const TAG_LEN: usize = 32;

/// Width of the short authentication tag used for audio, where a 32 byte tag
/// would be a large fraction of the payload.
pub const TAG_LEN_SHORT: usize = 16;

type Cipher = Aegis256<TAG_LEN>;
type CipherShort = Aegis256<TAG_LEN_SHORT>;

/// Encrypts `plaintext`, returning `ciphertext || tag`.
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let mut ct = plaintext.to_vec();
    let tag = Cipher::new(key, nonce).encrypt_in_place(&mut ct, ad);
    ct.extend_from_slice(&tag);
    ct
}

/// Decrypts `ciphertext || tag`.
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 32],
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < TAG_LEN {
        return Err(CryptoError::Truncated);
    }
    let (body, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
    let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| CryptoError::Truncated)?;
    let mut plaintext = body.to_vec();
    Cipher::new(key, nonce)
        .decrypt_in_place(&mut plaintext, &tag, ad)
        .map_err(|_| CryptoError::BadTag)?;
    Ok(plaintext)
}

/// Encrypts `buf` in place and returns the detached tag.
pub fn aead_seal_detached(
    key: &[u8; 32],
    nonce: &[u8; 32],
    buf: &mut [u8],
    ad: &[u8],
) -> [u8; TAG_LEN] {
    Cipher::new(key, nonce).encrypt_in_place(buf, ad)
}

/// Decrypts `buf` in place against a detached tag.
///
/// On failure `buf` is left with unauthenticated keystream output. Callers must
/// treat the buffer as destroyed and must not release it downstream; the media
/// layer decrypts into a scratch copy for exactly this reason.
pub fn aead_open_detached(
    key: &[u8; 32],
    nonce: &[u8; 32],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
    ad: &[u8],
) -> Result<(), CryptoError> {
    Cipher::new(key, nonce)
        .decrypt_in_place(buf, tag, ad)
        .map_err(|_| CryptoError::BadTag)
}

/// Encrypts `buf` in place and returns a detached 128-bit tag.
pub fn aead_seal_detached_short(
    key: &[u8; 32],
    nonce: &[u8; 32],
    buf: &mut [u8],
    ad: &[u8],
) -> [u8; TAG_LEN_SHORT] {
    CipherShort::new(key, nonce).encrypt_in_place(buf, ad)
}

/// Decrypts `buf` in place against a detached 128-bit tag.
pub fn aead_open_detached_short(
    key: &[u8; 32],
    nonce: &[u8; 32],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN_SHORT],
    ad: &[u8],
) -> Result<(), CryptoError> {
    CipherShort::new(key, nonce)
        .decrypt_in_place(buf, tag, ad)
        .map_err(|_| CryptoError::BadTag)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official test vectors from draft-irtf-cfrg-aegis-aead, AEGIS-256 with a
    // 256-bit tag. Pinning them here means a dependency update that changes
    // the cipher cannot pass CI silently.
    const K: [u8; 32] = hex_lit("1001000000000000000000000000000000000000000000000000000000000000");
    const N: [u8; 32] = hex_lit("1000020000000000000000000000000000000000000000000000000000000000");

    const fn hex_lit(s: &str) -> [u8; 32] {
        let b = s.as_bytes();
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = nyb(b[2 * i]) * 16 + nyb(b[2 * i + 1]);
            i += 1;
        }
        out
    }

    const fn nyb(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => 0,
        }
    }

    #[test]
    fn cfrg_vector_1_single_block() {
        let msg = [0u8; 16];
        let out = aead_seal(&K, &N, &msg, b"");
        assert_eq!(
            hex::encode(&out),
            "754fc3d8c973246dcc6d741412a4b236\
             1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13"
                .replace([' ', '\n'], "")
        );
        assert_eq!(aead_open(&K, &N, &out, b"").unwrap(), msg);
    }

    #[test]
    fn cfrg_vector_2_empty_message() {
        let out = aead_seal(&K, &N, b"", b"");
        assert_eq!(out.len(), TAG_LEN);
        assert_eq!(
            hex::encode(&out),
            "6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a"
        );
        assert_eq!(aead_open(&K, &N, &out, b"").unwrap(), b"");
    }

    #[test]
    fn cfrg_vector_3_with_associated_data() {
        let ad = hex::decode("0001020304050607").unwrap();
        let msg = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let out = aead_seal(&K, &N, &msg, &ad);
        assert_eq!(
            hex::encode(&out),
            "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711\
             b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a"
                .replace([' ', '\n'], "")
        );
        assert_eq!(aead_open(&K, &N, &out, &ad).unwrap(), msg);
        // The tag binds the associated data.
        assert!(aead_open(&K, &N, &out, b"").is_err());
    }

    #[test]
    fn roundtrip_and_rejection() {
        let key = [7u8; 32];
        let nonce = [9u8; 32];
        let ct = aead_seal(&key, &nonce, b"payload", b"header");
        assert_eq!(aead_open(&key, &nonce, &ct, b"header").unwrap(), b"payload");

        // wrong associated data
        assert_eq!(
            aead_open(&key, &nonce, &ct, b"other"),
            Err(CryptoError::BadTag)
        );
        // wrong nonce
        assert_eq!(
            aead_open(&key, &[8u8; 32], &ct, b"header"),
            Err(CryptoError::BadTag)
        );
        // wrong key
        assert_eq!(
            aead_open(&[6u8; 32], &nonce, &ct, b"header"),
            Err(CryptoError::BadTag)
        );
        // flipped ciphertext bit
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(
            aead_open(&key, &nonce, &bad, b"header"),
            Err(CryptoError::BadTag)
        );
        // flipped tag bit
        let mut bad = ct.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert_eq!(
            aead_open(&key, &nonce, &bad, b"header"),
            Err(CryptoError::BadTag)
        );
        // truncated below the tag
        assert_eq!(
            aead_open(&key, &nonce, &ct[..8], b"header"),
            Err(CryptoError::Truncated)
        );
    }

    #[test]
    fn detached_matches_attached_and_preserves_length() {
        let key = [1u8; 32];
        let nonce = [2u8; 32];
        let pt = b"the quick brown fox".to_vec();

        let mut buf = pt.clone();
        let tag = aead_seal_detached(&key, &nonce, &mut buf, b"ad");
        assert_eq!(buf.len(), pt.len(), "AEGIS is length preserving");

        let attached = aead_seal(&key, &nonce, &pt, b"ad");
        assert_eq!(&attached[..pt.len()], &buf[..]);
        assert_eq!(&attached[pt.len()..], &tag[..]);

        aead_open_detached(&key, &nonce, &mut buf, &tag, b"ad").unwrap();
        assert_eq!(buf, pt);
    }

    #[test]
    fn short_tag_matches_the_cfrg_128_bit_vector() {
        // Test vector 1 with the 128-bit tag variant.
        let mut buf = [0u8; 16];
        let tag = aead_seal_detached_short(&K, &N, &mut buf, b"");
        assert_eq!(hex::encode(buf), "754fc3d8c973246dcc6d741412a4b236");
        assert_eq!(hex::encode(tag), "3fe91994768b332ed7f570a19ec5896e");
        aead_open_detached_short(&K, &N, &mut buf, &tag, b"").unwrap();
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn empty_plaintext_still_authenticates_ad() {
        let key = [3u8; 32];
        let nonce = [4u8; 32];
        let ct = aead_seal(&key, &nonce, b"", b"bound");
        assert!(aead_open(&key, &nonce, &ct, b"bound").is_ok());
        assert!(aead_open(&key, &nonce, &ct, b"unbound").is_err());
    }
}
