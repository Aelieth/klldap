use crate::policy::LiveClients;
use anyhow::{Context, Result, bail};
use krb5_config::{KdcConf, KdcPaths, Krb5Conf, ProfileSet, listen::ListenAddr};
use krb5_crypto::{EncryptionType, parse_enctype_list};
use krb5_kdc::{Acl, AdminSpec, PrincipalStore, SharedDump};
use krb5_types::PrincipalName;
use minijinja::{Environment, context};
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

const MASTER_KEY_TYPE: &str = "aes256-cts-hmac-sha1-96";
const CLIENT_CONFIG_TEMPLATE: &str = include_str!("../../../kerberos/krb5.template.conf");

/// The realm as the server resolved it from `[kerberos_options]`.
pub struct RealmSettings {
    pub realm: String,
    pub domain: String,
    pub ticket_lifetime: u64,
    pub renew_lifetime: u64,
    pub max_renewable_life: u64,
    pub forwardable: bool,
    pub supported_enctypes: Vec<EncryptionType>,
    pub kdc_bind: IpAddr,
    pub kdc_port: u16,
    pub kadmin_bind: SocketAddr,
    pub kadmin_acl_file: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub admin_keytab: PathBuf,
    pub keycloak_keytab: PathBuf,
    pub client_config: PathBuf,
}

const DEPRECATED: [EncryptionType; 2] = [EncryptionType::Des3CbcSha1, EncryptionType::Rc4Hmac];
const ENCTYPE_FAMILIES: [&str; 5] = ["default", "aes", "camellia", "des3", "rc4"];

/// MIT's enctype list syntax. Refuses unknown names, 3DES and RC4 (RFC 8429), and Camellia.
pub fn parse_enctypes(names: &[String]) -> Result<Vec<EncryptionType>> {
    let list = names.join(" ");
    for token in list.split(|c: char| c.is_ascii_whitespace() || c == ',') {
        let name = token.trim_start_matches(['+', '-']);
        let known = name.is_empty()
            || ENCTYPE_FAMILIES.contains(&name.to_ascii_lowercase().as_str())
            || EncryptionType::from_mit_name(name).is_ok();
        if !known {
            bail!("{token:?} is not an encryption type this realm supports");
        }
    }
    let etypes = parse_enctype_list(&list, false)
        .with_context(|| format!("no supported encryption type in {names:?}"))?;
    if let Some(old) = etypes.iter().find(|etype| DEPRECATED.contains(etype)) {
        bail!("{} is deprecated (RFC 8429) and refused", old.to_mit_name());
    }
    if let Some(weak) = etypes.iter().find(|etype| etype.is_weak()) {
        bail!("{} is not served by this KDC", weak.to_mit_name());
    }
    Ok(etypes)
}

pub(crate) struct OpenRealm {
    pub store: SharedDump,
    pub profile: ProfileSet,
    pub acl: Acl,
    pub kdc_udp: Vec<UdpSocket>,
    pub kdc_tcp: Vec<TcpListener>,
    pub kadmin: TcpListener,
}

pub(crate) fn open(settings: &RealmSettings) -> Result<OpenRealm> {
    if !krb5_types::pkinit::P384_ENABLED {
        bail!("this build lacks --cfg p384_backend=\"fiat\" (.cargo/config.toml), so P-384 is off");
    }
    let profile = profile(settings);
    let mut store = open_store(settings, &profile)?;
    store
        .policy
        .plugins
        .register_kdcpolicy(Arc::new(LiveClients));
    write_client_config(settings)?;

    let kdc_addr = ListenAddr {
        host: Some(settings.kdc_bind.to_string()),
        port: settings.kdc_port,
    };
    let kdc_udp = krb5_kdc::bind_udp_listeners(std::slice::from_ref(&kdc_addr))
        .map_err(|e| with_port_hint(e, settings.kdc_port))
        .with_context(|| format!("while binding the KDC on UDP {kdc_addr:?}"))?;
    let kdc_tcp = krb5_kdc::bind_tcp_listeners(std::slice::from_ref(&kdc_addr))
        .map_err(|e| with_port_hint(e, settings.kdc_port))
        .with_context(|| format!("while binding the KDC on TCP {kdc_addr:?}"))?;
    let kadmin = TcpListener::bind(settings.kadmin_bind)
        .map_err(|e| with_port_hint(e, settings.kadmin_bind.port()))
        .with_context(|| format!("while binding kadmin on {}", settings.kadmin_bind))?;
    Ok(OpenRealm {
        store: krb5_kdc::shared_dump(store),
        acl: acl(&settings.realm, settings.kadmin_acl_file.as_deref())?,
        profile,
        kdc_udp,
        kdc_tcp,
        kadmin,
    })
}

// The one bind failure an operator fixes with a capability or a higher port, not a restart.
pub fn with_port_hint(e: io::Error, port: u16) -> anyhow::Error {
    let refused = e.kind() == io::ErrorKind::PermissionDenied && port < 1024;
    let e = anyhow::Error::new(e);
    if refused {
        e.context(format!(
            "port {port} needs CAP_NET_BIND_SERVICE or a port above 1023; see the install guide"
        ))
    } else {
        e
    }
}

/// Opens the realm's database, creating it on first boot, and writes the admin keytab.
pub(crate) fn open_store(settings: &RealmSettings, profile: &ProfileSet) -> Result<PrincipalStore> {
    let realm = &settings.realm;
    secure_dir(&settings.data_dir)?;
    crate::migrate::migrate(settings)?;
    let paths = KdcPaths {
        profile: PathBuf::new(),
        conf: profile.kdc.clone(),
        realm: Some(realm.clone()),
        database_name: settings.data_dir.join("principal"),
        key_stash_file: settings.data_dir.join(format!(".k5.{realm}")),
        acl_file: settings.kadmin_acl_file.clone(),
        master_key_type: Some(MASTER_KEY_TYPE.to_owned()),
    };
    let admin = AdminSpec::new(admin_principal());
    let (store, booted) = krb5_kdc::open_or_create(&paths, profile, Some(admin))
        .with_context(|| format!("while opening the Kerberos realm {realm}"))?;
    let keytab = booted
        .admin_keytab
        .context("the realm returned no admin keytab")?;
    create_parent(&settings.admin_keytab)?;
    keytab
        .write_file(&settings.admin_keytab)
        .with_context(|| format!("while writing {}", settings.admin_keytab.display()))?;
    Ok(store)
}

pub(crate) fn admin_principal() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin", "admin"])
}

pub(crate) fn profile(settings: &RealmSettings) -> ProfileSet {
    let enctypes: Vec<String> = settings
        .supported_enctypes
        .iter()
        .map(|etype| etype.to_mit_name().to_owned())
        .collect();
    let krb5 = Krb5Conf {
        ticket_lifetime: Some(settings.ticket_lifetime),
        renew_lifetime: Some(settings.renew_lifetime),
        forwardable: settings.forwardable,
        default_tkt_enctypes: enctypes.clone(),
        default_tgs_enctypes: enctypes.clone(),
        permitted_enctypes: Some(enctypes.clone()),
        ..Default::default()
    };
    let kdc = KdcConf {
        realm: settings.realm.clone(),
        kdc_listen: settings.kdc_port.to_string(),
        kdc_tcp_listen: Some(settings.kdc_port.to_string()),
        max_life: settings.ticket_lifetime,
        max_renewable_life: settings.max_renewable_life,
        realm_max_renewable_life: settings.max_renewable_life,
        supported_enctypes: enctypes.iter().map(|e| format!("{e}:normal")).collect(),
        permitted_enctypes: Some(enctypes),
        master_key_type: Some(MASTER_KEY_TYPE.to_owned()),
        requires_preauth: true,
        ..Default::default()
    };
    ProfileSet::from_structs(&settings.realm, krb5, Some(kdc))
}

fn acl(realm: &str, extra: Option<&Path>) -> Result<Acl> {
    let mut text = format!("admin/admin@{realm} *\n");
    if let Some(path) = extra {
        text.push_str(
            &fs::read_to_string(path)
                .with_context(|| format!("while reading {}", path.display()))?,
        );
    }
    Acl::parse_with_realm(&text, realm).context("while parsing the kadmin ACL")
}

fn write_client_config(settings: &RealmSettings) -> Result<()> {
    let rendered = Environment::new()
        .template_from_str(CLIENT_CONFIG_TEMPLATE)
        .and_then(|template| {
            template.render(context! {
                REALM_NAME => &settings.realm,
                DOMAIN => &settings.domain,
                TICKET_LIFETIME => format!("{}s", settings.ticket_lifetime),
                RENEW_LIFETIME => format!("{}s", settings.renew_lifetime),
                FORWARDABLE => settings.forwardable,
                RDNS => false,
                KDC => SocketAddr::new(loopback_for(settings.kdc_bind), settings.kdc_port),
                ADMIN_SERVER => settings.kadmin_bind,
            })
        })
        .context("while rendering krb5.conf")?;
    create_parent(&settings.client_config)?;
    fs::write(&settings.client_config, rendered)
        .with_context(|| format!("while writing {}", settings.client_config.display()))?;
    fs::set_permissions(&settings.client_config, fs::Permissions::from_mode(0o644)).with_context(
        || {
            format!(
                "while setting the mode of {}",
                settings.client_config.display()
            )
        },
    )
}

// The database and stash are owner-only; the directory follows. One we cannot change is the
// operator's arrangement, so it only warns.
fn secure_dir(dir: &Path) -> Result<()> {
    let existed = dir.exists();
    fs::create_dir_all(dir).with_context(|| format!("while creating {}", dir.display()))?;
    let mode = fs::metadata(dir)
        .with_context(|| format!("while reading {}", dir.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode == 0o700 {
        return Ok(());
    }
    match fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
        Ok(()) if existed => info!("Tightened {} from {mode:o} to 700", dir.display()),
        Ok(()) => {}
        Err(e) => warn!(
            "{} is {mode:o}, not 700, and was left so: {e}",
            dir.display()
        ),
    }
    Ok(())
}

fn loopback_for(bind: IpAddr) -> IpAddr {
    if bind.is_unspecified() {
        IpAddr::from([127, 0, 0, 1])
    } else {
        bind
    }
}

fn create_parent(path: &Path) -> Result<()> {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => {
            fs::create_dir_all(dir).with_context(|| format!("while creating {}", dir.display()))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded::tests::TempRealm;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_enctypes() {
        let rows = [
            (
                "aes256-cts-hmac-sha1-96",
                Ok(vec![EncryptionType::Aes256CtsHmacSha196]),
            ),
            (
                "aes256-cts aes128-sha1",
                Ok(vec![
                    EncryptionType::Aes256CtsHmacSha196,
                    EncryptionType::Aes128CtsHmacSha196,
                ]),
            ),
            ("aes256-cts no-such-type", Err("not an encryption type")),
            ("des-cbc-crc", Err("not an encryption type")),
            ("des3-cbc-sha1", Err("des3-cbc-sha1 is deprecated")),
            ("des3-cbc-sha1-kd", Err("des3-cbc-sha1 is deprecated")),
            ("des3-hmac-sha1", Err("des3-cbc-sha1 is deprecated")),
            ("des3", Err("des3-cbc-sha1 is deprecated")),
            ("arcfour-hmac", Err("arcfour-hmac is deprecated")),
            ("rc4-hmac", Err("arcfour-hmac is deprecated")),
            ("arcfour-hmac-md5", Err("arcfour-hmac is deprecated")),
            ("rc4", Err("arcfour-hmac is deprecated")),
            (
                "camellia256-cts-cmac",
                Err("camellia256-cts-cmac is not served"),
            ),
            (
                "camellia128-cts-cmac",
                Err("camellia128-cts-cmac is not served"),
            ),
            (
                "aes256-cts camellia",
                Err("camellia256-cts-cmac is not served"),
            ),
            ("default", Err("des3-cbc-sha1 is deprecated")),
            ("default -des3 -rc4", Err("is not served")),
            (
                "default -des3 -rc4 -camellia",
                Ok(vec![
                    EncryptionType::Aes256CtsHmacSha196,
                    EncryptionType::Aes128CtsHmacSha196,
                    EncryptionType::Aes256CtsHmacSha384192,
                    EncryptionType::Aes128CtsHmacSha256128,
                ]),
            ),
        ];
        for (names, expected) in rows {
            let parsed = parse_enctypes(&[names.to_owned()]).map_err(|e| e.to_string());
            match (parsed, expected) {
                (Ok(got), Ok(want)) => assert_eq!(got, want, "{names}"),
                (Err(e), Err(want)) => assert!(e.contains(want), "{names}: {e}"),
                (got, _) => panic!("{names}: unexpected {got:?}"),
            }
        }
    }

    #[test]
    fn test_a_refused_low_port_says_what_it_needs() {
        use io::ErrorKind::{AddrInUse, PermissionDenied};
        let rows = [
            (PermissionDenied, 88, true),
            (PermissionDenied, 749, true),
            (PermissionDenied, 1023, true),
            (PermissionDenied, 1024, false),
            (PermissionDenied, 8888, false),
            (AddrInUse, 88, false),
        ];
        for (kind, port, hinted) in rows {
            let message = format!("{:#}", with_port_hint(io::Error::new(kind, "bind"), port));
            let hint = format!("port {port} needs CAP_NET_BIND_SERVICE or a port above 1023");
            assert_eq!(
                message.contains(&hint),
                hinted,
                "{kind:?} on {port}: {message}"
            );
            assert!(
                message.ends_with("bind"),
                "the io error stays in the chain: {message}"
            );
        }
    }

    #[test]
    fn test_data_dir_is_owner_only() {
        for looser in [None, Some(0o755)] {
            let temp = TempRealm::new();
            let dir = &temp.settings.data_dir;
            if let Some(mode) = looser {
                fs::create_dir_all(dir).unwrap();
                fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
            }
            open_store(&temp.settings, &profile(&temp.settings)).unwrap();
            let mode = fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "existing mode {looser:?}");
        }
    }

    #[test]
    fn test_profile_from_settings() {
        let mut temp = TempRealm::new();
        temp.settings.kdc_port = 8888;
        temp.settings
            .supported_enctypes
            .push(EncryptionType::Aes128CtsHmacSha196);
        let profile = profile(&temp.settings);
        let kdc = profile.kdc.as_ref().expect("a KDC profile");
        let rows = [
            ("realm", profile.realm.clone(), "EXAMPLE.COM".to_owned()),
            (
                "ticket_lifetime",
                format!("{:?}", profile.krb5.ticket_lifetime),
                "Some(86400)".to_owned(),
            ),
            (
                "renew_lifetime",
                format!("{:?}", profile.krb5.renew_lifetime),
                "Some(604800)".to_owned(),
            ),
            (
                "forwardable",
                profile.krb5.forwardable.to_string(),
                "true".to_owned(),
            ),
            ("kdc_listen", kdc.kdc_listen.clone(), "8888".to_owned()),
            (
                "max_renewable_life",
                kdc.max_renewable_life.to_string(),
                "604800".to_owned(),
            ),
            (
                "realm_max_renewable_life",
                kdc.realm_max_renewable_life.to_string(),
                "604800".to_owned(),
            ),
            (
                "supported_enctypes",
                kdc.supported_enctypes.join(" "),
                "aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal".to_owned(),
            ),
            (
                "master_key_type",
                format!("{:?}", kdc.master_key_type),
                "Some(\"aes256-cts-hmac-sha1-96\")".to_owned(),
            ),
            (
                "requires_preauth",
                kdc.requires_preauth.to_string(),
                "true".to_owned(),
            ),
        ];
        for (field, got, want) in rows {
            assert_eq!(got, want, "{field}");
        }
    }
}
