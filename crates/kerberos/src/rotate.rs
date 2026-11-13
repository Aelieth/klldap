use krb5_crypto::{EncryptionType, KeySalt};
use krb5_kdc::{Error as StoreError, PrincipalRead, PrincipalStore, TL_LAST_PWD_CHANGE, TlData};
use krb5_types::PrincipalName;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

fn services(realm: &str) -> [PrincipalName; 3] {
    [
        PrincipalName::krbtgt(realm),
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "admin"]),
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "changepw"]),
    ]
}

/// True when the first listed type is not the type of krbtgt's newest key.
pub(crate) fn roll_due(
    store: &PrincipalStore,
    realm: &str,
    etypes: &[EncryptionType],
) -> Result<bool, StoreError> {
    let newest = store
        .fetch_name(&PrincipalName::krbtgt(realm))?
        .and_then(|p| p.keys_in_order().first().map(|key| key.etype));
    Ok(newest.is_some() && newest != etypes.first().copied())
}

pub(crate) fn roll(
    store: &mut PrincipalStore,
    realm: &str,
    etypes: &[EncryptionType],
    actor: &str,
) -> Result<(), StoreError> {
    let keysalts: Vec<KeySalt> = etypes.iter().map(|&etype| etype.into()).collect();
    store.change(|s| {
        for name in services(realm) {
            if s.fetch_name(&name)?.is_some() {
                s.chrand_etypes_keepold_in(&name, realm, &keysalts, 1, actor)?;
            }
        }
        Ok::<_, StoreError>(())
    })?
}

/// Drops the older key versions of each service whose newest key is at least `grace` seconds
/// old. Returns how many services were purged; with none due, the store is not written.
pub(crate) fn purge_old_keys(
    store: &mut PrincipalStore,
    realm: &str,
    grace: u64,
    now: u64,
    actor: &str,
) -> Result<usize, StoreError> {
    let mut due = Vec::new();
    for name in services(realm) {
        let Some(principal) = store.fetch_name(&name)? else {
            continue;
        };
        let (Some(top), Some(changed)) =
            (principal.top_kvno(), last_pwd_change(&principal.tl_data))
        else {
            continue;
        };
        let older = principal.key_slots().iter().any(|slot| slot.kvno() < top);
        if older && now.saturating_sub(u64::from(changed)) >= grace {
            due.push((name, top));
        }
    }
    if due.is_empty() {
        return Ok(0);
    }
    store.change(|s| {
        for (name, top) in &due {
            s.purgekeys_in(name, realm, i32::try_from(*top).unwrap_or(i32::MAX), actor)?;
        }
        Ok::<_, StoreError>(())
    })??;
    for (name, top) in &due {
        info!(
            "🎟️ Purged the key versions below {top} of {}",
            name.components_joined_lossy()
        );
    }
    Ok(due.len())
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn last_pwd_change(tl_data: &[TlData]) -> Option<u32> {
    let tl = tl_data.iter().find(|tl| tl.ty == TL_LAST_PWD_CHANGE)?;
    Some(u32::from_le_bytes(tl.contents.get(..4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot;
    use crate::embedded::tests::TempRealm;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_last_pwd_change_from_tl_data() {
        let tl = |ty, contents: &[u8]| TlData {
            ty,
            contents: contents.to_vec(),
        };
        let rows = [
            (vec![], None),
            (
                vec![tl(TL_LAST_PWD_CHANGE, &[1, 2, 3, 4])],
                Some(0x0403_0201),
            ),
            (vec![tl(TL_LAST_PWD_CHANGE, &[1, 2, 3])], None),
            (
                vec![
                    tl(2, &[9, 9, 9, 9]),
                    tl(TL_LAST_PWD_CHANGE, &[5, 0, 0, 0, 7]),
                ],
                Some(5),
            ),
        ];
        for (tl_data, expected) in rows {
            assert_eq!(last_pwd_change(&tl_data), expected, "{tl_data:?}");
        }
    }

    fn kvnos(store: &PrincipalStore, name: &PrincipalName) -> Vec<(u32, EncryptionType)> {
        store
            .fetch_name(name)
            .unwrap()
            .unwrap()
            .keys_in_order()
            .iter()
            .map(|key| (key.kvno, key.etype))
            .collect()
    }

    #[test]
    fn test_roll_keeps_the_old_keys_until_the_purge() {
        use EncryptionType::{Aes128CtsHmacSha196 as Aes128, Aes256CtsHmacSha196 as Aes256};
        let temp = TempRealm::new();
        let mut store = boot::open_store(&temp.settings, &boot::profile(&temp.settings)).unwrap();
        let (realm, grace) = ("EXAMPLE.COM", 86_400 + 604_800);
        let tgs = PrincipalName::krbtgt(realm);
        let before = kvnos(&store, &tgs);
        let first = before[0].0;
        assert!(!roll_due(&store, realm, &[Aes256, Aes128]).unwrap());
        assert!(roll_due(&store, realm, &[Aes128, Aes256]).unwrap());

        roll(&mut store, realm, &[Aes128, Aes256], "test").unwrap();
        let mut rolled = vec![(first + 1, Aes128), (first + 1, Aes256)];
        rolled.extend(before.iter().copied());
        assert_eq!(kvnos(&store, &tgs), rolled);
        assert!(!roll_due(&store, realm, &[Aes128, Aes256]).unwrap());

        let now = unix_now();
        for (at, purged) in [
            (now, 0),
            (now + grace - 10, 0),
            (now + grace + 10, 3),
            (now + grace + 10, 0),
        ] {
            let count = purge_old_keys(&mut store, realm, grace, at, "test").unwrap();
            assert_eq!(count, purged, "{at}");
        }
        assert_eq!(kvnos(&store, &tgs), rolled[..2].to_vec());
    }
}
