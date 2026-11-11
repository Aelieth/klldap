use crate::boot::RealmSettings;
use anyhow::{Context, Result, anyhow, bail};
use krb5_kdc::{PrincipalStore, load_dump_with_stash, parse_dump, save_store};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracing::info;

const DB: &str = "principal";
const DUMP: &str = "principal.dump";
const BACKUP: &str = "mit-db2.bak";
const STAGING: &str = ".migrating";
const HEADER: &[u8] = b"kdb5_util load_dump version ";
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
    Ours,
    Staged,
    Lost,
    Dump,
    MitOnly,
    Empty,
}

pub(crate) fn detect(dir: &Path) -> Result<Found> {
    let db = dir.join(DB);
    if db.exists() {
        let mut head = Vec::new();
        File::open(&db)
            .and_then(|f| f.take(HEADER.len() as u64).read_to_end(&mut head))
            .with_context(|| format!("while reading {}", db.display()))?;
        if head == HEADER {
            return Ok(Found::Ours);
        }
    } else if dir.join(BACKUP).is_dir() {
        return Ok(if dir.join(STAGING).join(DB).exists() {
            Found::Staged
        } else {
            Found::Lost
        });
    }
    Ok(if dir.join(DUMP).exists() {
        Found::Dump
    } else if db.exists() || dir.join("principal.kadm5").exists() {
        Found::MitOnly
    } else {
        Found::Empty
    })
}

/// Turns an MIT realm (0.7.x) into ours: loaded from its dump into a staging directory, then the
/// MIT files move to `mit-db2.bak/` and the new database into place, last.
pub(crate) fn migrate(settings: &RealmSettings) -> Result<()> {
    let dir = &settings.data_dir;
    match detect(dir)? {
        Found::Ours | Found::Empty => return Ok(()),
        Found::Lost => bail!(
            "{} has no Kerberos database, but {} holds the MIT files of an earlier migration; \
             restore the database instead of starting a new realm",
            dir.display(),
            dir.join(BACKUP).display()
        ),
        Found::MitOnly => bail!(
            "{} holds the MIT database of KLLDAP 0.7.x, which 0.8.0 cannot open; write its dump to \
             {} with the 0.7.x image you were running (docs/kerberos.md, Upgrading from 0.7.x) and start again",
            dir.display(),
            dir.join(DUMP).display()
        ),
        Found::Dump => stage(settings)?,
        Found::Staged => {}
    }
    finish(dir)
}

pub(crate) fn import(dump: &str, stash: &[u8]) -> Result<PrincipalStore> {
    load_dump_with_stash(dump, stash).map_err(|e| anyhow!("the dump does not load: {e}"))
}

fn stage(settings: &RealmSettings) -> Result<()> {
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
    let stash_path = dir.join(format!(".k5.{}", settings.realm));
    let stash = fs::read(&stash_path).with_context(|| {
        format!(
            "{} has a dump but no stash at {}",
            dir.display(),
            stash_path.display()
        )
    })?;
    let store = import(&text, &stash)?;
    let staging = dir.join(STAGING);
    owner_only_dir(&staging)?;
    save_store(&store, &staging.join(DB), &stash_path)
        .map_err(|e| anyhow!("while writing the migrated database: {e}"))?;
    info!(
        "Loaded {} Kerberos principals from {}",
        dump.princs.len(),
        dir.join(DUMP).display()
    );
    Ok(())
}

fn finish(dir: &Path) -> Result<()> {
    let backup = dir.join(BACKUP);
    owner_only_dir(&backup)?;
    for name in MIT_FILES {
        let (from, to) = (dir.join(name), backup.join(name));
        if from.exists() && !to.exists() {
            fs::rename(&from, &to).with_context(|| format!("while moving {}", from.display()))?;
        }
    }
    let staging = dir.join(STAGING);
    let mut names = fs::read_dir(&staging)
        .with_context(|| format!("while reading {}", staging.display()))?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort_by_key(|name| name.to_str() == Some(DB));
    for name in names {
        fs::rename(staging.join(&name), dir.join(&name))
            .with_context(|| format!("while installing {name:?}"))?;
    }
    fs::remove_dir(&staging).with_context(|| format!("while removing {}", staging.display()))?;
    info!(
        "Migrated the MIT realm; its files are kept in {}",
        backup.display()
    );
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
    use pretty_assertions::assert_eq;

    type Spoil = fn(&mut TempRealm);

    fn realm_as_mit(temp: &TempRealm) {
        let settings = &temp.settings;
        boot::open_store(settings, &boot::profile(settings)).unwrap();
        let dir = &settings.data_dir;
        fs::copy(dir.join(DB), dir.join(DUMP)).unwrap();
        fs::write(dir.join(DB), "\u{0}\u{6}\u{15}\u{61} db2").unwrap();
        fs::write(dir.join("principal.kadm5"), "").unwrap();
        fs::remove_file(dir.join("principal.lockout")).unwrap();
    }

    #[test]
    fn test_detect() {
        let ours = "kdb5_util load_dump version 7\n";
        let db2 = "\u{0}\u{6}\u{15}\u{61}";
        let rows: [(&[(&str, &str)], Found); 8] = [
            (&[], Found::Empty),
            (&[(DB, ours)], Found::Ours),
            (&[(DB, ours), (DUMP, "stale")], Found::Ours),
            (&[(DB, db2), ("principal.kadm5", "")], Found::MitOnly),
            (&[("principal.kadm5", "")], Found::MitOnly),
            (
                &[(DB, db2), ("principal.kadm5", ""), (DUMP, "x")],
                Found::Dump,
            ),
            (
                &[
                    (".migrating/principal", "x"),
                    ("mit-db2.bak/principal", db2),
                ],
                Found::Staged,
            ),
            (&[("mit-db2.bak/principal", db2)], Found::Lost),
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
        let names = |text: &str| {
            let mut names: Vec<_> = (parse_dump(text).unwrap().princs.into_iter())
                .map(|p| p.name)
                .collect();
            names.sort();
            names
        };
        let before = names(&fs::read_to_string(dir.join(DUMP)).unwrap());
        migrate(settings).unwrap();
        let backup = dir.join(BACKUP);
        let mut kept: Vec<_> = fs::read_dir(&backup)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        kept.sort();
        let mit = [
            DB,
            DUMP,
            "principal.kadm5",
            "principal.kadm5.lock",
            "principal.ok",
        ];
        let migrated = fs::read_to_string(dir.join(DB)).unwrap();
        assert_eq!(
            (
                detect(dir).unwrap(),
                kept,
                names(&migrated),
                dir.join(DUMP).exists() || dir.join(STAGING).exists(),
                fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            ),
            (
                Found::Ours,
                mit.map(String::from).to_vec(),
                before,
                false,
                0o700
            )
        );
        migrate(settings).unwrap();
        assert_eq!(fs::read_to_string(dir.join(DB)).unwrap(), migrated);
        boot::open_store(settings, &boot::profile(settings)).unwrap();
    }

    #[test]
    fn test_a_realm_that_cannot_migrate_is_refused_untouched() {
        let rows: [(&str, Spoil, &str); 4] = [
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
            (
                "database lost after a migration",
                |t| {
                    let dir = &t.settings.data_dir;
                    fs::create_dir(dir.join(BACKUP)).unwrap();
                    for name in [DB, DUMP] {
                        fs::rename(dir.join(name), dir.join(BACKUP).join(name)).unwrap();
                    }
                },
                "holds the MIT files of an earlier migration",
            ),
        ];
        for (case, spoil, cause) in rows {
            let mut temp = TempRealm::new();
            realm_as_mit(&temp);
            spoil(&mut temp);
            let dir = temp.settings.data_dir.clone();
            let before = detect(&dir).unwrap();
            let error = format!("{:#}", migrate(&temp.settings).unwrap_err());
            assert!(error.contains(cause), "{case}: {error}");
            assert_eq!(detect(&dir).unwrap(), before, "{case}: nothing moved");
        }
    }
}
