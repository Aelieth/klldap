#![forbid(unsafe_code)]

use generic_array::GenericArray;
use opaque_ke_legacy::{
    ClientLoginFinishParameters, ClientRegistrationFinishParameters, ServerLoginStartParameters,
    ciphersuite::CipherSuite, keypair::KeyPair,
};

// Verbatim replica of upstream LLDAP 0.6.x's ciphersuite (crates/auth/src/opaque.rs at
// opaque-ke 0.7): stored password files and server_key files only verify under these exact
// primitives and argon2 parameters.
struct ArgonHasher;

impl ArgonHasher {
    const SALT: &'static [u8] = b"lldap_opaque_salt";
    const CONFIG: &'static argon2::Config<'static> = &argon2::Config {
        ad: &[],
        hash_length: 128,
        lanes: 1,
        mem_cost: 50 * 1024,
        secret: &[],
        time_cost: 1,
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
    };
}

impl<D: opaque_ke_legacy::hash::Hash> opaque_ke_legacy::slow_hash::SlowHash<D> for ArgonHasher {
    fn hash(
        input: GenericArray<u8, <D as digest::Digest>::OutputSize>,
    ) -> Result<Vec<u8>, opaque_ke_legacy::errors::InternalPakeError> {
        argon2::hash_raw(&input, Self::SALT, Self::CONFIG)
            .map_err(|_| opaque_ke_legacy::errors::InternalPakeError::HashingFailure)
    }
}

struct LegacySuite;
impl CipherSuite for LegacySuite {
    type Group = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyExchange = opaque_ke_legacy::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = ArgonHasher;
}

type ServerSetup = opaque_ke_legacy::ServerSetup<LegacySuite>;
type ServerRegistration = opaque_ke_legacy::ServerRegistration<LegacySuite>;
type ClientLogin = opaque_ke_legacy::ClientLogin<LegacySuite>;
type ClientRegistration = opaque_ke_legacy::ClientRegistration<LegacySuite>;
type ServerLogin = opaque_ke_legacy::ServerLogin<LegacySuite>;

// oprf_seed (Sha512 output, 64) ‖ private key (32) ‖ fake private key (32).
pub const SERIALIZED_LEN: usize = 128;
const FAKE_KEY_OFFSET: usize = 96;

/// A parsed LLDAP 0.6.x `server_key` file. The current opaque-ke stores a fake *public*
/// key where 0.6.x stored a fake *private* key, so `reassemble_for_current` swaps in the
/// derived public key to produce bytes the current parser accepts; the real keypair is
/// bit-identical either way.
#[derive(Clone, PartialEq, Eq)]
pub struct LegacyServerSetup {
    bytes: Vec<u8>,
    fake_public_key: Vec<u8>,
}

impl std::fmt::Debug for LegacyServerSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LegacyServerSetup")
    }
}

pub fn parse_server_setup(bytes: &[u8]) -> Option<LegacyServerSetup> {
    if bytes.len() != SERIALIZED_LEN {
        return None;
    }
    ServerSetup::deserialize(bytes).ok()?;
    let fake_public_key =
        KeyPair::<curve25519_dalek::ristretto::RistrettoPoint>::from_private_key_slice(
            &bytes[FAKE_KEY_OFFSET..],
        )
        .ok()?
        .public()
        .to_vec();
    Some(LegacyServerSetup {
        bytes: bytes.to_vec(),
        fake_public_key,
    })
}

pub fn generate_random() -> LegacyServerSetup {
    let mut rng = rand::rngs::OsRng;
    let setup = ServerSetup::new(&mut rng);
    parse_server_setup(&setup.serialize()).expect("a freshly generated server setup parses")
}

impl LegacyServerSetup {
    fn setup(&self) -> ServerSetup {
        ServerSetup::deserialize(&self.bytes).expect("validated in parse_server_setup")
    }

    pub fn fake_public_key(&self) -> &[u8] {
        &self.fake_public_key
    }

    /// The original 0.6.x-format bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn reassemble_for_current(&self) -> Vec<u8> {
        [&self.bytes[..FAKE_KEY_OFFSET], &self.fake_public_key].concat()
    }

    /// Runs the full 0.6.x OPAQUE login ceremony in-process against a stored password
    /// file. Any protocol failure means "wrong password or not a legacy file".
    pub fn verify_password(
        &self,
        password_file_bytes: &[u8],
        username: &str,
        password: &str,
    ) -> bool {
        let attempt = || -> Result<(), opaque_ke_legacy::errors::ProtocolError> {
            let mut rng = rand::rngs::OsRng;
            let password_file = ServerRegistration::deserialize(password_file_bytes)?;
            let client_start = ClientLogin::start(&mut rng, password.as_bytes())?;
            let server_start = ServerLogin::start(
                &mut rng,
                &self.setup(),
                Some(password_file),
                client_start.message,
                username.as_bytes(),
                ServerLoginStartParameters::default(),
            )?;
            client_start
                .state
                .finish(server_start.message, ClientLoginFinishParameters::default())?;
            Ok(())
        };
        attempt().is_ok()
    }

    /// Produces a 0.6.x-format password file, for tests and migration fixtures.
    pub fn register_password(&self, username: &str, password: &str) -> Option<Vec<u8>> {
        let mut rng = rand::rngs::OsRng;
        let client_start = ClientRegistration::start(&mut rng, password.as_bytes()).ok()?;
        let server_start =
            ServerRegistration::start(&self.setup(), client_start.message, username.as_bytes())
                .ok()?;
        let client_finish = client_start
            .state
            .finish(
                &mut rng,
                server_start.message,
                ClientRegistrationFinishParameters::default(),
            )
            .ok()?;
        Some(
            ServerRegistration::finish(client_finish.message)
                .serialize()
                .to_vec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_and_reassemble_roundtrip() {
        let legacy = generate_random();
        assert_eq!(legacy.bytes.len(), SERIALIZED_LEN);
        assert_eq!(legacy.fake_public_key().len(), 32);
        let reparsed = parse_server_setup(&legacy.bytes).unwrap();
        assert_eq!(reparsed, legacy);
        assert_eq!(reparsed.fake_public_key(), legacy.fake_public_key());
        let reassembled = legacy.reassemble_for_current();
        assert_eq!(reassembled.len(), SERIALIZED_LEN);
        assert_eq!(
            &reassembled[..FAKE_KEY_OFFSET],
            &legacy.bytes[..FAKE_KEY_OFFSET]
        );
    }

    #[test]
    fn test_verify_accepts_right_password_and_rejects_wrong() {
        let legacy = generate_random();
        let password_file = legacy.register_password("bob", "bob00").unwrap();
        assert!(legacy.verify_password(&password_file, "bob", "bob00"));
        assert!(!legacy.verify_password(&password_file, "bob", "wrong"));
        assert!(!legacy.verify_password(&password_file, "alice", "bob00"));
        assert!(!legacy.verify_password(b"not a password file", "bob", "bob00"));
    }

    #[test]
    fn test_reassembled_bytes_parse_under_current_opaque() {
        let legacy = generate_random();
        assert!(
            lldap_auth::opaque::server::ServerSetup::deserialize(&legacy.reassemble_for_current())
                .is_ok()
        );
        let current =
            lldap_auth::opaque::server::ServerSetup::deserialize(&legacy.reassemble_for_current())
                .unwrap();
        // The real private key carries over bit-identically.
        assert_eq!(
            current.serialize()[64..96],
            legacy.bytes[64..FAKE_KEY_OFFSET]
        );
    }

    // The migration guide rests on the 0.6.x and current seed derivations disagreeing.
    #[test]
    fn test_key_seed_derivation_verdict_divergent() {
        use rand::SeedableRng;
        let seed = [7u8; 32];
        let legacy = ServerSetup::new(&mut rand_chacha::ChaCha20Rng::from_seed(seed));
        let current = {
            let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
            lldap_auth::opaque::server::ServerSetup::new(&mut rng)
        };
        let legacy_private = &legacy.serialize()[64..96];
        let current_private = &current.serialize()[64..96];
        assert_ne!(
            legacy_private, current_private,
            "the 0.6.x and current key_seed derivations now agree; key_seed continuity \
             is possible, revisit the migration guide"
        );
    }
}
