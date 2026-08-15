use crate::{
    cli::{
        GeneralConfigOpts, HealthcheckOpts, LdapsOpts, RunOpts, SmtpEncryption, SmtpOpts,
        TestEmailOpts, TrueFalseAlways,
    },
    database_string::DatabaseUrl,
};
use anyhow::{Context, Result, anyhow, bail};
use figment::{
    Figment, Provider,
    providers::{Env, Format, Serialized, Toml},
};
use figment_file_provider_adapter::FileAdapter;
use lldap_auth::opaque::{
    KeyPair,
    server::{ServerSetup, generate_random_private_key},
};
use lldap_domain::types::{AttributeName, UserId};
use lldap_sql_backend_handler::sql_tables::{
    ConfigLocation, PrivateKeyHash, PrivateKeyInfo, PrivateKeyLocation,
};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use url::Url;

#[derive(
    Clone, Deserialize, Serialize, derive_more::FromStr, derive_more::Debug, derive_more::Display,
)]
#[debug(r#""{_0}""#)]
#[display("{_0}")]
pub struct Mailbox(pub lettre::message::Mailbox);

#[derive(Clone, derive_more::Debug, Deserialize, Serialize, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct MailOptions {
    #[builder(default = "false")]
    pub enable_password_reset: bool,
    #[builder(default)]
    pub from: Option<Mailbox>,
    #[builder(default = "None")]
    pub reply_to: Option<Mailbox>,
    #[builder(default = r#""localhost".to_string()"#)]
    pub server: String,
    #[builder(default = "587")]
    pub port: u16,
    #[builder(default)]
    pub user: String,
    #[builder(default = r#"SecUtf8::from("")"#)]
    pub password: SecUtf8,
    #[builder(default = "SmtpEncryption::Tls")]
    pub smtp_encryption: SmtpEncryption,
    /// Deprecated.
    #[debug(skip)]
    #[serde(skip)]
    #[builder(default = "None")]
    pub tls_required: Option<bool>,
}

impl std::default::Default for MailOptions {
    fn default() -> Self {
        MailOptionsBuilder::default().build().unwrap()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct LdapsOptions {
    #[builder(default = "false")]
    pub enabled: bool,
    #[builder(default = "6360")]
    pub port: u16,
    #[builder(default = r#"String::from("cert.pem")"#)]
    pub cert_file: String,
    #[builder(default = r#"String::from("key.pem")"#)]
    pub key_file: String,
}

impl std::default::Default for LdapsOptions {
    fn default() -> Self {
        LdapsOptionsBuilder::default().build().unwrap()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct HealthcheckOptions {
    #[builder(default = r#"String::from("localhost")"#)]
    pub http_host: String,
    #[builder(default = r#"String::from("localhost")"#)]
    pub ldap_host: String,
    #[builder(default = "false")]
    pub kerberos: bool,
}

impl std::default::Default for HealthcheckOptions {
    fn default() -> Self {
        HealthcheckOptionsBuilder::default().build().unwrap()
    }
}

#[derive(Clone, Deserialize, Serialize, derive_more::Debug)]
#[debug(r#""{_0}""#)]
pub struct HttpUrl(pub Url);

#[derive(Clone, derive_more::Debug, Deserialize, Serialize, derive_builder::Builder)]
#[builder(pattern = "owned", build_fn(name = "private_build"))]
pub struct Configuration {
    #[builder(default = r#"String::from("0.0.0.0")"#)]
    pub ldap_host: String,
    #[builder(default = "3890")]
    pub ldap_port: u16,
    #[builder(default = r#"String::from("0.0.0.0")"#)]
    pub http_host: String,
    #[builder(default = "17170")]
    pub http_port: u16,
    #[builder(default)]
    pub jwt_secret: Option<SecUtf8>,
    #[builder(default = r#"String::from("dc=example,dc=com")"#)]
    pub ldap_base_dn: String,
    #[builder(default = r#"UserId::new("admin")"#)]
    pub ldap_user_dn: UserId,
    #[builder(default)]
    pub ldap_user_email: String,
    #[builder(default)]
    pub ldap_user_pass: Option<SecUtf8>,
    #[builder(default)]
    pub force_ldap_user_pass_reset: TrueFalseAlways,
    #[builder(default = "false")]
    pub force_update_private_key: bool,
    #[builder(default = r#"DatabaseUrl::from("sqlite://users.db?mode=rwc")"#)]
    pub database_url: DatabaseUrl,
    #[builder(default)]
    pub ignored_user_attributes: Vec<AttributeName>,
    #[builder(default)]
    pub ignored_group_attributes: Vec<AttributeName>,
    #[builder(default = "false")]
    pub verbose: bool,
    #[builder(default = r#"String::from("server_key")"#)]
    pub key_file: String,
    #[builder(default)]
    pub key_seed: Option<SecUtf8>,
    #[builder(default = r#"PathBuf::from("./app")"#)]
    pub assets_path: PathBuf,
    #[builder(default)]
    pub smtp_options: MailOptions,
    #[builder(default)]
    pub ldaps_options: LdapsOptions,
    #[builder(default = r#"HttpUrl(Url::parse("http://localhost").unwrap())"#)]
    pub http_url: HttpUrl,
    #[debug(skip)]
    #[serde(skip)]
    #[builder(field(private), default = "None")]
    server_setup: Option<ServerSetupConfig>,
    #[builder(default)]
    pub healthcheck_options: HealthcheckOptions,
}

impl std::default::Default for Configuration {
    fn default() -> Self {
        ConfigurationBuilder::default().build().unwrap()
    }
}

impl ConfigurationBuilder {
    pub fn build(self) -> Result<Configuration> {
        let server_setup = get_server_setup(
            self.key_file.as_deref().unwrap_or("server_key"),
            self.key_seed
                .as_ref()
                .and_then(|o| o.as_ref())
                .map(SecUtf8::unsecure)
                .unwrap_or_default(),
            PrivateKeyLocation::Default,
        )?;
        Ok(self.server_setup(Some(server_setup)).private_build()?)
    }
}

/// Sentinel value used only when constructing the default Configuration for
/// figment's Serialized::defaults and expected_keys extraction.
/// When get_server_setup sees this exact seed it short-circuits and returns
/// a throwaway in-memory ServerSetup without *any* filesystem operations on
/// the default "server_key" path. This eliminates the root cause of the
/// "Permission denied on server_key" bug (healthchecks and other commands
/// running as root creating a root-owned 0400 file in /app that the real
/// lldap user later cannot read).
const FIGMENT_DUMMY_KEY_SEED: &str = "__LLDAP_FIGMENT_DEFAULTS_DUMMY_SEED__";

fn stable_hash(val: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(val);
    hasher.finalize().into()
}

impl Configuration {
    pub fn get_server_setup(&self) -> &ServerSetup {
        &self.server_setup.as_ref().unwrap().server_setup
    }

    pub fn get_legacy_server_setup(&self) -> Option<&lldap_opaque_legacy::LegacyServerSetup> {
        self.server_setup
            .as_ref()
            .unwrap()
            .legacy_server_setup
            .as_ref()
    }

    pub fn get_server_keys(&self) -> &KeyPair {
        self.get_server_setup().keypair()
    }

    pub fn get_private_key_info(&self) -> PrivateKeyInfo {
        PrivateKeyInfo {
            private_key_hash: PrivateKeyHash(stable_hash(
                self.get_server_keys().private().serialize().as_ref(),
            )),
            private_key_location: self
                .server_setup
                .as_ref()
                .unwrap()
                .private_key_location
                .clone(),
        }
    }
}

/// Returns whether the private key is entirely new.
pub fn compare_private_key_hashes(
    previous_info: Option<&PrivateKeyInfo>,
    private_key_info: &PrivateKeyInfo,
) -> Result<bool> {
    match previous_info {
        None => Ok(true),
        Some(previous_info) => {
            if previous_info.private_key_hash == private_key_info.private_key_hash {
                Ok(false)
            } else {
                match (
                    &previous_info.private_key_location,
                    &private_key_info.private_key_location,
                ) {
                    (
                        PrivateKeyLocation::KeyFile(old_location, file_path),
                        PrivateKeyLocation::KeySeed(new_location),
                    ) => {
                        bail!(
                            "The private key is configured to be generated from a seed (from {new_location:?}), but it used to come from the file {file_path:?} (defined in {old_location:?}). Did you just upgrade from <=v0.4 to >=v0.5? The key seed was not supported, revert to just using the file."
                        );
                    }
                    (PrivateKeyLocation::Default, PrivateKeyLocation::KeySeed(new_location)) => {
                        bail!(
                            "The private key is configured to be generated from a seed (from {new_location:?}), but it used to come from default key file \"server_key\". Did you just upgrade from <=v0.4 to >=v0.5? The key seed was not yet supported, revert to just using the file."
                        );
                    }
                    (
                        PrivateKeyLocation::KeyFile(old_location, old_path),
                        PrivateKeyLocation::KeyFile(new_location, new_path),
                    ) => {
                        if old_path == new_path {
                            bail!(
                                "The contents of the private key file from {old_path:?} have changed. This usually means that the file was deleted and re-created. If using docker, make sure that the folder is made persistent (by mounting a volume or a directory). If you have several instances of LLDAP, make sure they share the same file (or switch to a key seed)."
                            );
                        } else {
                            bail!(
                                "The private key file used to be {old_path:?} (defined in {old_location:?}), but now is {new_path:?} (defined in {new_location:?}. Make sure to copy the old file in the new location."
                            );
                        }
                    }
                    (PrivateKeyLocation::Tests, _) | (_, PrivateKeyLocation::Tests) => {
                        panic!("Test keys unexpected")
                    }
                    (old_location, new_location) => {
                        bail!(
                            "The private key has changed. It used to come from {old_location:?}, but now it comes from {new_location:?}."
                        );
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
fn set_mode(permissions: &mut std::fs::Permissions) {
    use std::os::unix::fs::PermissionsExt;
    permissions.set_mode(0o400);
}

#[cfg(not(unix))]
fn set_mode(_: &mut std::fs::Permissions) {}

fn write_to_readonly_file(path: &std::path::Path, buffer: &[u8]) -> Result<()> {
    use std::{fs::File, io::Write};
    assert!(!path.exists());
    let mut file = File::create(path)?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(true);
    set_mode(&mut permissions);
    file.set_permissions(permissions)?;
    Ok(file.write_all(buffer)?)
}

#[derive(Debug, Clone)]
pub struct ServerSetupConfig {
    server_setup: ServerSetup,
    legacy_server_setup: Option<lldap_opaque_legacy::LegacyServerSetup>,
    private_key_location: PrivateKeyLocation,
}

#[derive(derive_more::From)]
enum PrivateKeyLocationOrFigment {
    Figment(Figment),
    PrivateKeyLocation(PrivateKeyLocation),
}

impl PrivateKeyLocationOrFigment {
    fn for_key_seed(&self) -> PrivateKeyLocation {
        match self {
            PrivateKeyLocationOrFigment::Figment(config) => {
                match config.find_metadata("key_seed") {
                    Some(figment::Metadata {
                        source: Some(figment::Source::File(path)),
                        ..
                    }) => PrivateKeyLocation::KeySeed(ConfigLocation::ConfigFile(
                        path.to_string_lossy().to_string(),
                    )),
                    Some(figment::Metadata {
                        source: None, name, ..
                    }) => PrivateKeyLocation::KeySeed(ConfigLocation::EnvironmentVariable(
                        name.clone().to_string(),
                    )),
                    None
                    | Some(figment::Metadata {
                        source: Some(figment::Source::Code(_)),
                        ..
                    }) => PrivateKeyLocation::Default,
                    other => panic!("Unexpected config location: {other:?}"),
                }
            }
            PrivateKeyLocationOrFigment::PrivateKeyLocation(PrivateKeyLocation::KeyFile(
                config_location,
                _,
            )) => {
                panic!("Unexpected location: {config_location:?}")
            }
            PrivateKeyLocationOrFigment::PrivateKeyLocation(location) => location.clone(),
        }
    }

    fn for_key_file(&self, server_key_file: &str) -> PrivateKeyLocation {
        match self {
            PrivateKeyLocationOrFigment::Figment(config) => {
                match config.find_metadata("key_file") {
                    Some(figment::Metadata {
                        source: Some(figment::Source::File(path)),
                        ..
                    }) => PrivateKeyLocation::KeyFile(
                        ConfigLocation::ConfigFile(path.to_string_lossy().to_string()),
                        server_key_file.into(),
                    ),
                    Some(figment::Metadata {
                        source: None, name, ..
                    }) => PrivateKeyLocation::KeyFile(
                        ConfigLocation::EnvironmentVariable(name.to_string()),
                        server_key_file.into(),
                    ),
                    None
                    | Some(figment::Metadata {
                        source: Some(figment::Source::Code(_)),
                        ..
                    }) => PrivateKeyLocation::Default,
                    other => panic!("Unexpected config location: {other:?}"),
                }
            }
            PrivateKeyLocationOrFigment::PrivateKeyLocation(PrivateKeyLocation::KeySeed(file)) => {
                panic!("Unexpected location: {file:?}")
            }
            PrivateKeyLocationOrFigment::PrivateKeyLocation(location) => location.clone(),
        }
    }
}

fn get_server_setup<L: Into<PrivateKeyLocationOrFigment>>(
    file_path: &str,
    key_seed: &str,
    private_key_location: L,
) -> Result<ServerSetupConfig> {
    let private_key_location = private_key_location.into();
    use std::fs::read;
    let path = std::path::Path::new(file_path);

    // Special case for figment defaults / healthcheck init: never touch disk
    // for the default relative "server_key". This is the key fix for the
    // Docker permission-denied bug when root healthchecks race with the
    // lldap user process.
    if key_seed == FIGMENT_DUMMY_KEY_SEED {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);
        let server_setup = ServerSetup::new(&mut rng);
        return Ok(ServerSetupConfig {
            server_setup,
            legacy_server_setup: None,
            private_key_location: PrivateKeyLocation::Default,
        });
    }

    if !key_seed.is_empty() {
        if path.exists() {
            bail!(
                "A key_seed was given, but a key file already exists at `{}`. Which one to use is ambiguous, aborting.\nNote: If you just migrated from <=v0.4 to >=v0.5, the previous version did not support key_seed, so it was falling back onto a key file. Remove the seed from the configuration.",
                file_path
            );
        } else if file_path == "server_key" {
            eprintln!(
                "WARNING: A key_seed was given, we will ignore the key_file and generate one from the seed! Set key_file to an empty string in the config to silence this message."
            );
        } else {
            println!("Generating the private key from the key_seed");
        }
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(stable_hash(key_seed.as_bytes()));
        Ok(ServerSetupConfig {
            server_setup: ServerSetup::new(&mut rng),
            legacy_server_setup: None,
            private_key_location: private_key_location.for_key_seed(),
        })
    } else if path.exists() {
        let bytes = read(file_path).context(format!("Could not read key file `{file_path}`"))?;
        // An LLDAP 0.6.x server_key stores a fake private key where the current format
        // stores a fake public key. The formats are structurally indistinguishable (same
        // length, no header; 0.6.x accepts any scalar bytes and the current parser
        // accepts ~11% of 0.6.x fake keys as points) but agree on the oprf_seed and real
        // private key — everything real-user verification uses. So carry both
        // interpretations and let bind resolve behaviorally, like the password files.
        let legacy_server_setup = lldap_opaque_legacy::parse_server_setup(&bytes);
        let server_setup = match ServerSetup::deserialize(&bytes) {
            Ok(server_setup) => server_setup,
            Err(e) => match &legacy_server_setup {
                Some(legacy) => {
                    println!(
                        "`{file_path}` is a legacy LLDAP server key; accepting it and enabling legacy password verification"
                    );
                    ServerSetup::deserialize(&legacy.reassemble_for_current())
                        .context(format!("while converting the legacy `{file_path}` file"))?
                }
                None => {
                    return Err(e).context(format!(
                        "while parsing the contents of the `{file_path}` file"
                    ));
                }
            },
        };
        Ok(ServerSetupConfig {
            server_setup,
            legacy_server_setup,
            private_key_location: private_key_location.for_key_file(file_path),
        })
    } else {
        let server_setup = generate_random_private_key();
        write_to_readonly_file(path, &server_setup.serialize()).context(format!(
            "Could not write the generated server setup to file `{file_path}`",
        ))?;
        Ok(ServerSetupConfig {
            server_setup,
            legacy_server_setup: None,
            private_key_location: private_key_location.for_key_file(file_path),
        })
    }
}

pub trait ConfigOverrider {
    fn override_config(&self, config: &mut Configuration);
}

pub trait TopLevelCommandOpts {
    fn general_config(&self) -> &GeneralConfigOpts;
}

impl TopLevelCommandOpts for RunOpts {
    fn general_config(&self) -> &GeneralConfigOpts {
        &self.general_config
    }
}

impl TopLevelCommandOpts for TestEmailOpts {
    fn general_config(&self) -> &GeneralConfigOpts {
        &self.general_config
    }
}

impl ConfigOverrider for RunOpts {
    fn override_config(&self, config: &mut Configuration) {
        self.general_config.override_config(config);

        self.server_key_file
            .as_ref()
            .inspect(|path| config.key_file = path.to_string());

        self.server_key_seed
            .as_ref()
            .inspect(|seed| config.key_seed = Some(SecUtf8::from(seed.as_str())));

        self.ldap_port.inspect(|&port| config.ldap_port = port);

        self.http_port.inspect(|&port| config.http_port = port);

        self.http_url
            .as_ref()
            .inspect(|&url| config.http_url = HttpUrl(url.clone()));

        self.database_url
            .as_ref()
            .inspect(|&database_url| config.database_url = database_url.clone());

        self.force_ldap_user_pass_reset
            .inspect(|&force_ldap_user_pass_reset| {
                config.force_ldap_user_pass_reset = force_ldap_user_pass_reset;
            });

        self.force_update_private_key
            .inspect(|&force_update_private_key| {
                config.force_update_private_key = force_update_private_key;
            });

        self.smtp_opts.override_config(config);
        self.ldaps_opts.override_config(config);
        self.healthcheck_opts.override_config(config);
    }
}

impl ConfigOverrider for TestEmailOpts {
    fn override_config(&self, config: &mut Configuration) {
        self.general_config.override_config(config);
        self.smtp_opts.override_config(config);
    }
}

impl ConfigOverrider for LdapsOpts {
    fn override_config(&self, config: &mut Configuration) {
        self.ldaps_enabled
            .inspect(|&enabled| config.ldaps_options.enabled = enabled);

        self.ldaps_port
            .inspect(|&port| config.ldaps_options.port = port);

        self.ldaps_cert_file
            .as_ref()
            .inspect(|path| config.ldaps_options.cert_file.clone_from(path));

        self.ldaps_key_file
            .as_ref()
            .inspect(|path| config.ldaps_options.key_file.clone_from(path));
    }
}

impl ConfigOverrider for GeneralConfigOpts {
    fn override_config(&self, config: &mut Configuration) {
        if self.verbose {
            config.verbose = true;
        }
    }
}

impl ConfigOverrider for SmtpOpts {
    fn override_config(&self, config: &mut Configuration) {
        self.smtp_from
            .as_ref()
            .inspect(|&from| config.smtp_options.from = Some(Mailbox(from.clone())));

        self.smtp_reply_to
            .as_ref()
            .inspect(|&reply_to| config.smtp_options.reply_to = Some(Mailbox(reply_to.clone())));

        self.smtp_server
            .as_ref()
            .inspect(|server| config.smtp_options.server.clone_from(server));

        self.smtp_port
            .inspect(|&port| config.smtp_options.port = port);

        self.smtp_user
            .as_ref()
            .inspect(|user| config.smtp_options.user.clone_from(user));

        self.smtp_password
            .as_ref()
            .inspect(|&password| config.smtp_options.password = SecUtf8::from(password.clone()));

        self.smtp_encryption.as_ref().inspect(|&smtp_encryption| {
            config.smtp_options.smtp_encryption = smtp_encryption.clone();
        });

        self.smtp_tls_required
            .inspect(|&tls_required| config.smtp_options.tls_required = Some(tls_required));

        self.smtp_enable_password_reset
            .inspect(|&enable_password_reset| {
                config.smtp_options.enable_password_reset = enable_password_reset;
            });
    }
}

impl ConfigOverrider for HealthcheckOpts {
    fn override_config(&self, config: &mut Configuration) {
        self.healthcheck_http_host
            .as_ref()
            .inspect(|host| config.healthcheck_options.http_host.clone_from(host));

        self.healthcheck_ldap_host
            .as_ref()
            .inspect(|host| config.healthcheck_options.ldap_host.clone_from(host));

        if self.healthcheck_kerberos {
            config.healthcheck_options.kerberos = true;
        }
    }
}

fn extract_keys(dict: &figment::value::Dict) -> HashSet<String> {
    use figment::value::{Dict, Value};
    fn process_value(value: &Dict, keys: &mut HashSet<String>, path: &mut Vec<String>) {
        for (key, value) in value {
            match value {
                Value::Dict(_, dict) => {
                    path.push(format!("{}__", key.to_ascii_uppercase()));
                    process_value(dict, keys, path);
                    path.pop();
                }
                _ => {
                    keys.insert(format!(
                        "LLDAP_{}{}",
                        path.join(""),
                        key.to_ascii_uppercase()
                    ));
                }
            }
        }
    }
    let mut keys = HashSet::new();
    let mut path = Vec::new();
    process_value(dict, &mut keys, &mut path);
    keys
}

fn expected_keys(dict: &figment::value::Dict) -> HashSet<String> {
    let mut keys = extract_keys(dict);
    // CLI-only values.
    keys.insert("LLDAP_CONFIG_FILE".to_string());
    keys.insert("LLDAP_TEST_EMAIL_TO".to_string());
    keys.insert("LLDAP_KERBEROS_HEALTHCHECK".to_string());
    // Container knobs read by the entrypoint.
    keys.insert("LLDAP_UID".to_string());
    keys.insert("LLDAP_GID".to_string());
    // Alternate spellings from clap.
    keys.insert("LLDAP_SERVER_KEY_FILE".to_string());
    keys.insert("LLDAP_SERVER_KEY_SEED".to_string());
    keys.insert("LLDAP_SMTP_OPTIONS__TO".to_string());
    // Deprecated
    keys.insert("LLDAP_SMTP_OPTIONS__TLS_REQUIRED".to_string());
    keys
}

fn check_for_unexpected_env_variables<P: Provider>(env_variable_provider: P) {
    use figment::Profile;
    let expected_keys = expected_keys(
        &Figment::from(Serialized::defaults(
            ConfigurationBuilder::default()
                .key_seed(Some(SecUtf8::from(FIGMENT_DUMMY_KEY_SEED)))
                .build()
                .unwrap(),
        ))
        .data()
        .unwrap()[&Profile::default()],
    );
    // LLDAP_KERB_* and LLDAP_KEYCLOAK_* belong to the kerberos and keycloak crates.
    extract_keys(&env_variable_provider.data().unwrap()[&Profile::default()])
        .iter()
        .filter(|k| !expected_keys.contains(k.as_str()))
        .filter(|k| !k.starts_with("LLDAP_KERB_") && !k.starts_with("LLDAP_KEYCLOAK_"))
        .for_each(|k| {
            eprintln!("WARNING: Unknown environment variable: {k}");
        });
}

fn generate_jwt_sample_error() -> String {
    use rand::{Rng, seq::SliceRandom};
    struct Symbols;

    impl rand::distributions::Distribution<char> for Symbols {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
            *b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+,-./:;<=>?_~!@#$%^&*()[]{}:;".choose(rng).unwrap() as char
        }
    }
    format!(
        "The JWT secret must be initialized to a random string, preferably at least 32 characters long. \
            Either set the `jwt_secret` config value or the `LLDAP_JWT_SECRET` environment variable. \
            You can generate the value by running\n\
            LC_ALL=C tr -dc 'A-Za-z0-9!#%&'\\''()*+,-./:;<=>?@[\\]^_{{|}}~' </dev/urandom | head -c 32; echo ''\n\
            or you can use this random value: {}",
        rand::thread_rng()
            .sample_iter(&Symbols)
            .take(32)
            .collect::<String>()
    )
}

/// `init`, but with real private-key material: clears the figment dummy seed so the key
/// file (or a configured seed) is actually loaded — creating the key file on first run.
/// Only the serving path may use this; auxiliary commands (healthcheck, schema export,
/// test email, create-schema) must never read or create key material, or a root-run
/// healthcheck could plant an unreadable `server_key` before the server does.
pub fn init_with_private_key<C>(overrides: C) -> Result<Configuration>
where
    C: TopLevelCommandOpts + ConfigOverrider,
{
    init_impl(overrides, true)
}

pub fn init<C>(overrides: C) -> Result<Configuration>
where
    C: TopLevelCommandOpts + ConfigOverrider,
{
    init_impl(overrides, false)
}

fn init_impl<C>(overrides: C, load_private_key: bool) -> Result<Configuration>
where
    C: TopLevelCommandOpts + ConfigOverrider,
{
    println!(
        "Loading configuration from {}",
        overrides.general_config().config_file
    );

    let ignore_keys = ["key_file", "cert_file"];
    let env_variable_provider =
        || FileAdapter::wrap(Env::prefixed("LLDAP_").split("__")).ignore(&ignore_keys);
    let figment_config = Figment::from(Serialized::defaults(
        ConfigurationBuilder::default()
            .key_seed(Some(SecUtf8::from(FIGMENT_DUMMY_KEY_SEED)))
            .build()
            .unwrap(),
    ))
    .merge(
        FileAdapter::wrap(Toml::file(&overrides.general_config().config_file)).ignore(&ignore_keys),
    )
    .merge(env_variable_provider());
    let mut config: Configuration = figment_config.extract()?;

    overrides.override_config(&mut config);
    if config.verbose {
        println!("Configuration: {:#?}", config);
    }
    // The dummy seed exists so that building the figment defaults shape (and every
    // auxiliary command) never touches key material on disk. The serving path must
    // clear the sentinel when nothing overrode it, or a key-file deployment would
    // silently run on the deterministic dummy key instead of its key file.
    if load_private_key
        && config.key_seed.as_ref().map(SecUtf8::unsecure) == Some(FIGMENT_DUMMY_KEY_SEED)
    {
        config.key_seed = None;
    }
    check_for_unexpected_env_variables(env_variable_provider());
    config.server_setup = Some(get_server_setup(
        &config.key_file,
        config
            .key_seed
            .as_ref()
            .map(SecUtf8::unsecure)
            .unwrap_or_default(),
        figment_config,
    )?);
    config
        .jwt_secret
        .as_ref()
        .ok_or_else(|| anyhow!("{}", generate_jwt_sample_error()))?;
    if config.smtp_options.tls_required.is_some() {
        println!(
            "DEPRECATED: smtp_options.tls_required field is deprecated, it never did anything. You can replace it with smtp_options.smtp_encryption."
        );
    }
    if config.smtp_options.enable_password_reset {
        println!(
            "Password reset is enabled; reset-email links will use base URL: {}",
            config.http_url.0
        );
        if is_loopback_url(&config.http_url.0) {
            println!(
                "WARNING: http_url is unset or loopback ({}); password-reset emails will link to an address recipients cannot reach. Set LLDAP_HTTP_URL to your real UI URL (e.g. https://ldap.example.com).",
                config.http_url.0
            );
        }
    }
    Ok(config)
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use clap::Parser;
    use figment::Jail;
    use pretty_assertions::assert_eq;

    #[test]
    fn loopback_url_detection() {
        for base in ["http://localhost", "http://127.0.0.1:17170", "http://[::1]"] {
            assert!(
                is_loopback_url(&Url::parse(base).unwrap()),
                "{base} should be loopback"
            );
        }
        for base in ["https://ldap.example.com", "http://10.10.10.100:17170"] {
            assert!(
                !is_loopback_url(&Url::parse(base).unwrap()),
                "{base} should not be loopback"
            );
        }
    }

    #[test]
    fn check_generated_server_key() {
        // Exercise the full key-seed code path
        let result = get_server_setup("/doesnt/exist", "key seed", PrivateKeyLocation::Tests);
        assert!(
            result.is_ok(),
            "key_seed path should succeed without a key file"
        );

        let config = result.unwrap();
        let serialized = bincode::serialize(&config.server_setup)
            .expect("ServerSetup must be bincode-serializable");

        assert!(
            !serialized.is_empty(),
            "generated server key must not be empty"
        );

        // Prove round-tripping still works after any opaque-ke / bincode updates
        let _deserialized: ServerSetup =
            bincode::deserialize(&serialized).expect("ServerSetup must round-trip through bincode");

        // The real guarantee of key_seed: same seed → identical key (determinism)
        let result2 =
            get_server_setup("/doesnt/exist", "key seed", PrivateKeyLocation::Tests).unwrap();
        let serialized2 = bincode::serialize(&result2.server_setup).unwrap();
        assert_eq!(
            serialized, serialized2,
            "identical seeds must produce identical ServerSetup bytes"
        );
    }

    #[test]
    fn figment_defaults_dummy_seed_does_not_materialize_server_key() {
        // The core of the Docker permission bug fix: constructing the shape/defaults
        // Configuration used by figment (and therefore by every healthcheck and run init)
        // must never read or write the default "server_key" file on disk. Previously the
        // unconditional ConfigurationBuilder::default().private_build() in Serialized::defaults
        // would create a root-owned 0400 "server_key" in cwd when run as root (the entrypoint
        // healthcheck polls).
        Jail::expect_with(|jail| {
            jail.clear_env();
            let key_path = jail.directory().join("server_key");
            assert!(!key_path.exists(), "precondition: no server_key yet");

            let _shape = ConfigurationBuilder::default()
                .key_seed(Some(SecUtf8::from(FIGMENT_DUMMY_KEY_SEED)))
                .build()
                .expect("dummy shape build must succeed");

            assert!(
                !key_path.exists(),
                "dummy figment defaults must not create or read a server_key file"
            );
            Ok(())
        });
    }

    fn default_run_opts() -> RunOpts {
        RunOpts::parse_from::<_, std::ffi::OsString>([])
    }

    fn write_random_key(jail: &Jail, file: &str) {
        use std::io::Write;
        let file = std::fs::File::create(jail.directory().join(file)).unwrap();
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(&generate_random_private_key().serialize())
            .unwrap();
    }

    #[test]
    fn figment_location_extraction_key_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.clear_env();
            jail.set_env("LLDAP_KEY_SEED", "a123");
            jail.set_env("LLDAP_JWT_SECRET", "secret");
            let ignore_keys = ["key_file", "cert_file"];
            let figment_config = Figment::from(Serialized::defaults(
                ConfigurationBuilder::default()
                    .key_seed(Some(SecUtf8::from(FIGMENT_DUMMY_KEY_SEED)))
                    .build()
                    .unwrap(),
            ))
            .merge(FileAdapter::wrap(Toml::file("lldap_config.toml")).ignore(&ignore_keys))
            .merge(FileAdapter::wrap(Env::prefixed("LLDAP_").split("__")).ignore(&ignore_keys));
            assert_eq!(
                PrivateKeyLocationOrFigment::Figment(figment_config).for_key_file("path"),
                PrivateKeyLocation::KeyFile(
                    ConfigLocation::ConfigFile(
                        jail.directory()
                            .join("lldap_config.toml")
                            .to_string_lossy()
                            .to_string()
                    ),
                    "path".into()
                )
            );
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_seed_success_with_nonexistant_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.clear_env();
            jail.set_env("LLDAP_KEY_SEED", "a123");
            jail.set_env("LLDAP_JWT_SECRET", "secret");
            init_with_private_key(default_run_opts()).unwrap();
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_seed_failure_with_existing_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.clear_env();
            jail.set_env("LLDAP_KEY_SEED", "a123");
            jail.set_env("LLDAP_JWT_SECRET", "secret");
            write_random_key(jail, "test");
            init_with_private_key(default_run_opts()).unwrap_err();
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_success_with_existing_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.clear_env();
            jail.set_env("LLDAP_JWT_SECRET", "secret");
            // Force the server key file value via the post-extract override (RunOpts field)
            // rather than env (which can confuse figment's Env/FileAdapter with "file path"
            // values) or the toml (key_file is ignored in the providers).
            let mut opts = default_run_opts();
            opts.server_key_file = Some("test".to_string());
            write_random_key(jail, "test");
            let config = init_with_private_key(opts).unwrap();
            // The key must come from the file — a leaked figment dummy seed would
            // deterministically generate a publicly-known key here instead.
            let file_bytes = std::fs::read(jail.directory().join("test")).unwrap();
            assert_eq!(&config.get_server_setup().serialize()[..], &file_bytes[..]);
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_success_with_nonexistent_file() {
        Jail::expect_with(|jail| {
            jail.create_file("lldap_config.toml", r#"key_file = "test""#)?;
            jail.clear_env();
            jail.set_env("LLDAP_JWT_SECRET", "secret");
            init_with_private_key(default_run_opts()).unwrap();
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_with_previous_different_file() {
        // This test exercises the "contents of the private key file have changed"
        // branch inside compare_private_key_hashes for the same named path.
        // We do it directly (constructing two different PrivateKeyInfo with the
        // same KeyFile location) to avoid any Jail + figment + BufWriter timing
        // subtleties with on-disk visibility across full init() calls.
        let loc = PrivateKeyLocation::KeyFile(
            ConfigLocation::ConfigFile("lldap_config.toml".into()),
            "test".into(),
        );
        // Two different random keys → different hashes, same location path.
        let k1 = generate_random_private_key();
        let k2 = generate_random_private_key();
        let hash = |k: &ServerSetup| {
            PrivateKeyHash(stable_hash(k.keypair().private().serialize().as_ref()))
        };
        let info1 = PrivateKeyInfo {
            private_key_hash: hash(&k1),
            private_key_location: loc.clone(),
        };
        let info2 = PrivateKeyInfo {
            private_key_hash: hash(&k2),
            private_key_location: loc,
        };
        let err = compare_private_key_hashes(Some(&info1), &info2)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("The contents of the private key file from \"test\" have changed"),
            "{err}"
        );
    }

    #[test]
    fn check_server_setup_key_extraction_file_to_seed() {
        Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("LLDAP_JWT_SECRET", "secret");
            jail.create_file("lldap_config.toml", "")?;
            write_random_key(jail, "server_key");
            init_with_private_key(default_run_opts()).unwrap();
            jail.create_file("lldap_config.toml", r#"key_seed = "test""#)?;
            let error_message = init_with_private_key(default_run_opts())
                .unwrap_err()
                .to_string();
            assert!(
                error_message.contains("A key_seed was given, but a key file already exists at",),
                "{error_message}"
            );
            Ok(())
        });
    }

    #[test]
    fn check_server_setup_key_extraction_file_to_seed_removed_file() {
        Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("LLDAP_JWT_SECRET", "secret");
            jail.create_file("lldap_config.toml", "")?;
            write_random_key(jail, "server_key");
            let config = init_with_private_key(default_run_opts()).unwrap();
            let info = config.get_private_key_info();
            std::fs::remove_file(jail.directory().join("server_key")).unwrap();
            jail.create_file("lldap_config.toml", r#"key_seed = "test""#)?;
            let new_config = init_with_private_key(default_run_opts()).unwrap();
            let error_message =
                compare_private_key_hashes(Some(&info), &new_config.get_private_key_info())
                    .unwrap_err()
                    .to_string();
            assert!(
                error_message.contains("but it used to come from default key file",),
                "{error_message}"
            );
            Ok(())
        });
    }

    #[test]
    fn server_key_file_current_format_keeps_setup_and_arms_legacy() {
        Jail::expect_with(|jail| {
            let setup = generate_random_private_key();
            let path = jail.directory().join("server_key");
            std::fs::write(&path, setup.serialize()).unwrap();
            let config =
                get_server_setup(path.to_str().unwrap(), "", PrivateKeyLocation::Tests).unwrap();
            assert_eq!(config.server_setup.serialize(), setup.serialize());
            // The 0.6.x parser accepts any scalar bytes, so the fallback arms on modern
            // files too; bind only consults it after the current check fails.
            assert!(config.legacy_server_setup.is_some());
            Ok(())
        });
    }

    #[test]
    fn server_key_file_ambiguous_legacy_bytes_arm_legacy() {
        // ~11% of 0.6.x fake private keys accidentally parse as current-format public
        // keys; such files must still arm legacy verification (P5 Issue 1).
        let legacy = std::iter::repeat_with(lldap_opaque_legacy::generate_random)
            .find(|l| ServerSetup::deserialize(l.as_bytes()).is_ok())
            .unwrap();
        Jail::expect_with(|jail| {
            let path = jail.directory().join("server_key");
            std::fs::write(&path, legacy.as_bytes()).unwrap();
            let config =
                get_server_setup(path.to_str().unwrap(), "", PrivateKeyLocation::Tests).unwrap();
            assert_eq!(config.legacy_server_setup.as_ref(), Some(&legacy));
            assert_eq!(&config.server_setup.serialize()[..], legacy.as_bytes());
            Ok(())
        });
    }

    #[test]
    fn private_key_hash_of_legacy_key_matches_stock_lldap() {
        // Stock lldap stores sha256(sk) (bytes 64..96 of the key file) in
        // metadata.private_key_hash; the value computed at boot from a migrated key must
        // match or compare_private_key_hashes refuses to start.
        let legacy = lldap_opaque_legacy::generate_random();
        Jail::expect_with(|jail| {
            let path = jail.directory().join("server_key");
            std::fs::write(&path, legacy.as_bytes()).unwrap();
            let config =
                get_server_setup(path.to_str().unwrap(), "", PrivateKeyLocation::Tests).unwrap();
            assert_eq!(
                stable_hash(config.server_setup.keypair().private().serialize().as_ref()),
                stable_hash(&legacy.as_bytes()[64..96]),
            );
            Ok(())
        });
    }

    #[test]
    fn server_key_file_legacy_format_reassembles_and_arms_legacy() {
        let legacy = std::iter::repeat_with(lldap_opaque_legacy::generate_random)
            .find(|l| ServerSetup::deserialize(l.as_bytes()).is_err())
            .unwrap();
        Jail::expect_with(|jail| {
            let path = jail.directory().join("server_key");
            std::fs::write(&path, legacy.as_bytes()).unwrap();
            let config =
                get_server_setup(path.to_str().unwrap(), "", PrivateKeyLocation::Tests).unwrap();
            assert_eq!(config.legacy_server_setup.as_ref(), Some(&legacy));
            assert_eq!(
                &config.server_setup.serialize()[..],
                &legacy.reassemble_for_current()[..]
            );
            Ok(())
        });
    }
}
