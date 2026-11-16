use orion::aead;
use orion::hazardous::kdf::hkdf;

use crate::error::Result;

/// A key for one kind of sealed value: HKDF-SHA256 over the server key, `info` naming the kind,
/// so a value sealed for one purpose never opens as another.
pub fn derive_sealing_key(ikm: &[u8], info: &[u8]) -> Result<aead::SecretKey> {
    let mut key_bytes = [0u8; 32];
    hkdf::sha256::derive_key(&[], ikm, Some(info), &mut key_bytes)?;
    Ok(aead::SecretKey::from_slice(&key_bytes)?)
}

/// bincode as `bincode::serialize` writes it, refusing trailing bytes.
pub fn decode_exact<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> bincode::Result<T> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Short {
        name: String,
    }

    #[derive(Serialize)]
    struct Long {
        name: String,
        more: u64,
    }

    #[test]
    fn test_each_purpose_gets_its_own_key() {
        let a = derive_sealing_key(b"server key", b"purpose-a").unwrap();
        let b = derive_sealing_key(b"server key", b"purpose-b").unwrap();
        let sealed = aead::seal(&a, b"payload").unwrap();
        assert_eq!(aead::open(&a, &sealed).unwrap(), b"payload");
        assert!(aead::open(&b, &sealed).is_err());
    }

    #[test]
    fn test_decode_exact_refuses_trailing_bytes() {
        let short = bincode::serialize(&Short { name: "bob".into() }).unwrap();
        assert_eq!(
            decode_exact::<Short>(&short).unwrap(),
            Short { name: "bob".into() }
        );
        let long = bincode::serialize(&Long {
            name: "bob".into(),
            more: 7,
        })
        .unwrap();
        assert!(bincode::deserialize::<Short>(&long).is_ok());
        assert!(decode_exact::<Short>(&long).is_err());
    }
}
