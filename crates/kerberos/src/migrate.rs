use crate::boot::RealmSettings;
use anyhow::{Context, Result, anyhow, bail};
use krb5_kdc::host::{HostPaths, KerberosStore, KerberosStoreError};
use krb5_kdc::{create_lockout_file, load_dump_with_stash_path, parse_dump};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

const DB: &str = "principal";
const DUMP: &str = "principal.dump";
const BACKUP: &str = "mit-db2.bak";
const HEADER: &[u8] = b"kdb5_util load_dump version ";
// The dump moves last, so a dump still here means the move is unfinished.
const MIT_FILES: [&str; 7] = [
    DB,
    "principal.kadm5",
    "principal.ok",
    "principal.kadm5.lock",
    "kadm5.acl",
    "kdc.conf",
    DUMP,
];

#[derive(Debug, PartialEq)]
pub(crate) enum Found {
    Dump,
    MitOnly,
    Empty,
}

pub(crate) fn detect(dir: &Path) -> Result<Found> {
    if dir.join(DUMP).exists() {
        return Ok(Found::Dump);
    }
    let db = dir.join(DB);
    let mit_db = if db.exists() {
        let mut head = Vec::new();
        File::open(&db)
            .and_then(|f| f.take(HEADER.len() as u64).read_to_end(&mut head))
            .with_context(|| format!("while reading {}", db.display()))?;
        head != HEADER
    } else {
        dir.join("principal.kadm5").exists()
    };
    Ok(if mit_db { Found::MitOnly } else { Found::Empty })
}

/// Turns an MIT realm (0.7.2) into ours: the dump goes into the database, then the MIT files
/// move to `mit-db2.bak/`. A boot that finds the dump after the realm reached the database
/// finishes the move.
pub(crate) fn migrate(
    settings: &RealmSettings,
    paths: &HostPaths,
    host: &dyn KerberosStore,
) -> Result<()> {
    let dir = &settings.data_dir;
    let backup = dir.join(BACKUP);
    match detect(dir)? {
        Found::Empty if backup.is_dir() && !paths.stash.exists() && !realm_held(host)? => bail!(
            "{} holds the MIT files of an earlier migration, but the database has no Kerberos \
             realm and {} is missing; restore the database and the stash, or move {} away to \
             start a new realm on purpose",
            backup.display(),
            paths.stash.display(),
            backup.display()
        ),
        Found::Empty => Ok(()),
        Found::MitOnly => bail!(
            "{} holds the MIT database of KLLDAP 0.7.2, which 0.8.0 cannot open; write its dump to \
             {} with the 0.7.2 image (docs/kerberos.md, Upgrading from 0.7.2) and start again",
            dir.display(),
            dir.join(DUMP).display()
        ),
        Found::Dump if realm_held(host)? => finish(dir, false),
        Found::Dump => {
            import(settings, paths, host)?;
            finish(dir, true)
        }
    }
}

fn realm_held(host: &dyn KerberosStore) -> Result<bool> {
    let loaded = host
        .load()
        .map_err(|e| anyhow!("while reading the realm from the database: {e}"))?;
    Ok(loaded.realm.is_some() || !loaded.principals.is_empty())
}

fn import(settings: &RealmSettings, paths: &HostPaths, host: &dyn KerberosStore) -> Result<()> {
    let dir = &settings.data_dir;
    let text = fs::read_to_string(dir.join(DUMP))
        .with_context(|| format!("while reading {}", dir.join(DUMP).display()))?;
    let dump = parse_dump(&text).map_err(|e| anyhow!("{DUMP} does not parse: {e}"))?;
    let realm = dump
        .realm()
        .map_err(|e| anyhow!("{DUMP} names no realm: {e}"))?;
    if realm != settings.realm {
        bail!(
            "{DUMP} is for realm {realm}, but this server serves {}",
            settings.realm
        );
    }
    if !paths.stash.exists() {
        bail!(
            "{} has a dump but no stash at {}",
            dir.display(),
            paths.stash.display()
        );
    }
    let store = load_dump_with_stash_path(&text, &paths.stash)
        .map_err(|e| anyhow!("the dump does not load: {e}"))?;
    create_lockout_file(&paths.lockout)
        .map_err(|e| anyhow!("while creating {}: {e}", paths.lockout.display()))?;
    let change = store
        .host_full_change()
        .map_err(|e| anyhow!("while sealing the imported realm: {e}"))?;
    host.commit_change(change).map_err(|e| match e {
        KerberosStoreError::Refused(why) => anyhow!(
            "the database refused the imported realm: {why}; create the user it names, or \
             remove the principal on 0.7.2 and dump again"
        ),
        e => anyhow!("while writing the imported realm to the database: {e}"),
    })?;
    info!(
        "Loaded {} Kerberos principals from {}",
        dump.princs.len(),
        dir.join(DUMP).display()
    );
    Ok(())
}

fn finish(dir: &Path, imported: bool) -> Result<()> {
    let backup = dir.join(BACKUP);
    owner_only_dir(&backup)?;
    for name in MIT_FILES {
        let from = dir.join(name);
        if !from.exists() {
            continue;
        }
        let mut to = backup.join(name);
        if to.exists() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs());
            to = backup.join(format!("{name}.{now}"));
        }
        fs::rename(&from, &to).with_context(|| format!("while moving {}", from.display()))?;
    }
    if imported {
        info!(
            "Migrated the MIT realm; its files are kept in {}",
            backup.display()
        );
    } else {
        info!(
            "The realm was already in the database; put the MIT files left beside it in {}",
            backup.display()
        );
    }
    Ok(())
}

fn owner_only_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("while creating {}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("while securing {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot;
    use crate::embedded::tests::TempRealm;
    use krb5_config::KdcPaths;
    use krb5_kdc::host::{HostChange, LoadedRealm};
    use pretty_assertions::assert_eq;
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::sync::Arc;

    type Spoil = fn(&mut TempRealm);

    fn realm_as_mit(temp: &TempRealm) {
        let settings = &temp.settings;
        let dir = &settings.data_dir;
        fs::create_dir_all(dir).unwrap();
        let profile = boot::profile(settings);
        let paths = KdcPaths {
            profile: PathBuf::new(),
            conf: profile.kdc.clone(),
            realm: Some(settings.realm.clone()),
            database_name: dir.join(DB),
            key_stash_file: dir.join(".k5.EXAMPLE.COM"),
            acl_file: None,
            master_key_type: Some("aes256-cts-hmac-sha1-96".to_owned()),
        };
        krb5_kdc::open_or_create(&paths, &profile, None).unwrap();
        fs::copy(dir.join(DB), dir.join(DUMP)).unwrap();
        fs::write(dir.join(DB), "\u{0}\u{6}\u{15}\u{61} db2").unwrap();
        fs::write(dir.join("principal.kadm5"), "").unwrap();
        let _ = fs::remove_file(dir.join("principal.lockout"));
    }

    fn dumped_names(dir: &Path) -> BTreeSet<String> {
        let text = fs::read_to_string(dir.join(DUMP)).unwrap();
        parse_dump(&text)
            .unwrap()
            .princs
            .into_iter()
            .map(|p| p.name.trim_end_matches("@EXAMPLE.COM").to_owned())
            .collect()
    }

    fn held_names(temp: &TempRealm) -> BTreeSet<String> {
        temp.host
            .load()
            .unwrap()
            .principals
            .into_iter()
            .map(|p| p.name)
            .collect()
    }

    fn kept(dir: &Path) -> Vec<String> {
        let mut kept: Vec<_> = fs::read_dir(dir.join(BACKUP))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        kept.sort();
        kept
    }

    #[test]
    fn test_detect() {
        let ours = "kdb5_util load_dump version 7\n";
        let db2 = "\u{0}\u{6}\u{15}\u{61}";
        let rows: [(&[(&str, &str)], Found); 6] = [
            (&[], Found::Empty),
            (&[(DB, ours)], Found::Empty),
            (&[(DB, db2), ("principal.kadm5", "")], Found::MitOnly),
            (&[("principal.kadm5", "")], Found::MitOnly),
            (
                &[(DB, db2), ("principal.kadm5", ""), (DUMP, "x")],
                Found::Dump,
            ),
            (&[(DUMP, "x"), ("mit-db2.bak/principal", db2)], Found::Dump),
        ];
        for (files, expected) in rows {
            let temp = TempRealm::new();
            let dir = &temp.settings.data_dir;
            fs::create_dir_all(dir).unwrap();
            for (name, body) in files {
                let path = dir.join(name);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, body).unwrap();
            }
            assert_eq!(detect(dir).unwrap(), expected, "{files:?}");
        }
    }

    #[test]
    fn test_an_mit_realm_migrates_once() {
        let temp = TempRealm::new();
        realm_as_mit(&temp);
        let settings = &temp.settings;
        let dir = &settings.data_dir;
        let before = dumped_names(dir);
        boot::open_store(settings, &boot::profile(settings), temp.host()).unwrap();
        let held = held_names(&temp);
        let commits = temp.commits();
        let mit = [
            DB,
            DUMP,
            "principal.kadm5",
            "principal.kadm5.lock",
            "principal.ok",
        ];
        assert_eq!(
            (
                detect(dir).unwrap(),
                kept(dir),
                before.is_subset(&held),
                dir.join(boot::LOCKOUT_FILE).exists(),
                fs::metadata(dir.join(BACKUP)).unwrap().permissions().mode() & 0o777,
            ),
            (
                Found::Empty,
                mit.map(String::from).to_vec(),
                true,
                true,
                0o700
            )
        );
        boot::open_store(settings, &boot::profile(settings), temp.host()).unwrap();
        assert_eq!(temp.commits(), commits, "a second boot imports nothing");
    }

    #[test]
    fn test_each_crash_point_of_the_import_recovers() {
        type Crash = fn(&TempRealm, &HostPaths);
        let rows: [(&str, Crash); 4] = [
            ("after the lockout file", |_, paths| {
                create_lockout_file(&paths.lockout).unwrap();
            }),
            ("after the commit", |temp, paths| {
                import(&temp.settings, paths, temp.host.as_ref()).unwrap();
            }),
            ("during the move", |temp, paths| {
                import(&temp.settings, paths, temp.host.as_ref()).unwrap();
                let dir = &temp.settings.data_dir;
                owner_only_dir(&dir.join(BACKUP)).unwrap();
                for name in [DB, "principal.kadm5"] {
                    fs::rename(dir.join(name), dir.join(BACKUP).join(name)).unwrap();
                }
            }),
            ("a dump put back after the move", |temp, paths| {
                import(&temp.settings, paths, temp.host.as_ref()).unwrap();
                let dir = &temp.settings.data_dir;
                finish(dir, true).unwrap();
                fs::copy(dir.join(BACKUP).join(DUMP), dir.join(DUMP)).unwrap();
            }),
        ];
        for (case, crash) in rows {
            let temp = TempRealm::new();
            realm_as_mit(&temp);
            let settings = &temp.settings;
            let dir = &settings.data_dir;
            let before = dumped_names(dir);
            crash(&temp, &boot::host_paths(settings));
            boot::open_store(settings, &boot::profile(settings), temp.host()).unwrap();
            let names = kept(dir);
            assert_eq!(
                (
                    detect(dir).unwrap(),
                    before.is_subset(&held_names(&temp)),
                    names.iter().any(|n| n == DUMP),
                    names.iter().any(|n| n == DB),
                ),
                (Found::Empty, true, true, true),
                "{case}"
            );
        }
    }

    #[test]
    fn test_a_lost_database_after_a_migration_is_refused() {
        let temp = TempRealm::new();
        realm_as_mit(&temp);
        let settings = &temp.settings;
        let profile = boot::profile(settings);
        boot::open_store(settings, &profile, temp.host()).unwrap();
        let stash = boot::host_paths(settings).stash;
        fs::remove_file(&stash).unwrap();
        let empty = Arc::new(crate::embedded::tests::Counting::default());
        let error = format!(
            "{:#}",
            boot::open_store(settings, &profile, empty.clone()).unwrap_err()
        );
        assert!(
            error.contains("holds the MIT files of an earlier migration"),
            "{error}"
        );
        assert!(error.contains("move"), "{error}");
        assert!(!stash.exists(), "no new realm was made");
        assert!(empty.load().unwrap().realm.is_none(), "nothing was written");
    }

    struct Refusing;

    impl KerberosStore for Refusing {
        fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
            Ok(LoadedRealm::default())
        }
        fn commit_change(&self, _: HostChange) -> Result<(), KerberosStoreError> {
            Err(KerberosStoreError::Failed(
                "the database is down".to_owned(),
            ))
        }
    }

    #[test]
    fn test_a_realm_that_cannot_migrate_is_refused_untouched() {
        let rows: [(&str, Spoil, &str); 3] = [
            (
                "bad dump",
                |t| fs::write(t.settings.data_dir.join(DUMP), "not a dump").unwrap(),
                "does not parse",
            ),
            (
                "no stash",
                |t| fs::remove_file(t.settings.data_dir.join(".k5.EXAMPLE.COM")).unwrap(),
                "has a dump but no stash at",
            ),
            (
                "other realm",
                |t| t.settings.realm = "OTHER.TEST".to_owned(),
                "is for realm EXAMPLE.COM, but this server serves OTHER.TEST",
            ),
        ];
        for (case, spoil, cause) in rows {
            let mut temp = TempRealm::new();
            realm_as_mit(&temp);
            spoil(&mut temp);
            let dir = temp.settings.data_dir.clone();
            let paths = boot::host_paths(&temp.settings);
            let error = format!(
                "{:#}",
                migrate(&temp.settings, &paths, temp.host.as_ref()).unwrap_err()
            );
            assert!(error.contains(cause), "{case}: {error}");
            assert_eq!(detect(&dir).unwrap(), Found::Dump, "{case}: nothing moved");
            assert!(held_names(&temp).is_empty(), "{case}: nothing written");
        }
        let temp = TempRealm::new();
        realm_as_mit(&temp);
        let paths = boot::host_paths(&temp.settings);
        let error = format!(
            "{:#}",
            migrate(&temp.settings, &paths, &Refusing).unwrap_err()
        );
        assert!(error.contains("the database is down"), "{error}");
        assert_eq!(detect(&temp.settings.data_dir).unwrap(), Found::Dump);
    }
}
