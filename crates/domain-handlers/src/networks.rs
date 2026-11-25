use crate::enforcement::{
    ALLOWED_NETWORKS, Attempt, Door, ItemCheck, POLICY_UNANSWERED, PolicyCache, UserState,
};
use crate::handler::PolicyBackendHandler;
use crate::logging;
use crate::policies::{
    POLICY_ITEM_CATALOG, POLICY_READ_WAIT, Policy, PolicyLevel, ou_display, resolve_effective_items,
};
use lldap_domain::types::UserId;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use tracing::warn;

pub const ADDRESS_NOT_ALLOWED: &str = "address not allowed";
const EMPTY_ELEMENT: &str = "list elements cannot be empty";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    prefix: u32,
}

impl Net {
    /// The item's grammar for one network; host bits are kept and masked when matching.
    pub fn parse(value: &str) -> Result<Self, String> {
        let (addr, prefix) = value
            .split_once('/')
            .ok_or_else(|| "CIDR must include an explicit prefix".to_owned())?;
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return Err("CIDR prefix must be a number".to_owned());
        }
        let prefix: u32 = prefix
            .parse()
            .map_err(|_| "CIDR prefix must be a number".to_owned())?;
        if let Ok(v4) = addr.parse::<Ipv4Addr>() {
            if prefix > 32 {
                return Err("IPv4 prefix must be 0-32".to_owned());
            }
            Ok(Self {
                addr: IpAddr::V4(v4),
                prefix,
            })
        } else if let Ok(v6) = addr.parse::<Ipv6Addr>() {
            if prefix > 128 {
                return Err("IPv6 prefix must be 0-128".to_owned());
            }
            Ok(Self {
                addr: IpAddr::V6(v6),
                prefix,
            })
        } else {
            Err("CIDR address is not a valid IP".to_owned())
        }
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.addr, address.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix).unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix).unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

fn element(element: &str) -> Result<Net, String> {
    match element.trim() {
        "" => Err(EMPTY_ELEMENT.to_owned()),
        element => Net::parse(element),
    }
}

/// The item's value: comma-separated networks; empty admits any address.
pub fn parse_list(value: &str) -> Result<Vec<Net>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value.split(',').map(element).collect()
}

/// `trusted_proxies`, in the item's grammar; a bad entry is named.
pub fn parse_trusted(value: &str) -> Result<Vec<Net>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let named = |entry: &str| {
        let refused = |e| format!("trusted_proxies \"{}\" is refused: {e}", entry.trim());
        element(entry).map_err(refused)
    };
    value.split(',').map(named).collect()
}

pub fn admits(nets: &[Net], address: Option<IpAddr>) -> bool {
    let inside = |address: IpAddr| nets.iter().any(|net| net.contains(address));
    nets.is_empty() || address.is_some_and(inside)
}

/// From a listed proxy only, `X-Forwarded-For` is read from the right: the first address that
/// is no listed proxy is the client. An entry on the way that is no bare address: unknown.
pub fn resolve_client(
    peer: Option<IpAddr>,
    forwarded_for: &[&str],
    trusted: &[Net],
) -> Option<IpAddr> {
    let peer = peer.map(|peer| peer.to_canonical());
    let listed = |address: IpAddr| trusted.iter().any(|net| net.contains(address));
    let Some(mut client) = peer.filter(|peer| listed(*peer)) else {
        return peer;
    };
    let entries = forwarded_for.iter().rev().flat_map(|line| line.rsplit(','));
    for entry in entries {
        client = entry.trim().parse::<IpAddr>().ok()?.to_canonical();
        if !listed(client) {
            break;
        }
    }
    Some(client)
}

/// The KDC judges its socket peer; the other doors the request's resolved address.
pub fn judged_address(attempt: &Attempt<'_>) -> Option<IpAddr> {
    match attempt.door {
        Door::KerberosAs | Door::KerberosTgs | Door::KerberosS4u => attempt.peer,
        _ => logging::current_request().client_address,
    }
}

pub struct NetworksCheck;

impl ItemCheck for NetworksCheck {
    fn key(&self) -> &'static str {
        ALLOWED_NETWORKS
    }

    fn live(&self, cache: &PolicyCache) -> bool {
        !cache.item_off(ALLOWED_NETWORKS)
    }

    fn reason(&self) -> Option<&'static str> {
        Some(ADDRESS_NOT_ALLOWED)
    }

    fn judges_at_s4u(&self) -> bool {
        false
    }

    fn readable(&self, value: &str, _: &UserState) -> bool {
        parse_list(value).is_ok()
    }

    fn allows(&self, attempt: &Attempt<'_>, value: &str, _: &UserState) -> bool {
        let address = judged_address(attempt);
        parse_list(value).is_ok_and(|nets| admits(&nets, address))
    }
}

#[derive(Default)]
pub(crate) struct NetworksBook {
    trusted: RwLock<Arc<[Net]>>,
    warned: Mutex<BTreeSet<(String, String)>>,
}

impl PolicyCache {
    /// `trusted_proxies`, held once at start; none until then.
    pub fn trusted_proxies(&self) -> Arc<[Net]> {
        let trusted = self.networks.trusted.read();
        trusted.unwrap_or_else(PoisonError::into_inner).clone()
    }

    pub fn set_trusted_proxies(&self, trusted: Vec<Net>) {
        let held = self.networks.trusted.write();
        *held.unwrap_or_else(PoisonError::into_inner) = trusted.into();
    }

    /// One warning for each linked policy whose list does not parse, until that value changes.
    pub fn unreadable_networks(&self, policies: &[Policy]) -> Vec<String> {
        let linked = policies
            .iter()
            .filter(|policy| !policy.linked_ous.is_empty());
        let unread = linked.filter_map(|policy| {
            let value = policy.items.get(ALLOWED_NETWORKS)?;
            parse_list(value)
                .is_err()
                .then(|| (policy.name.clone(), value.clone()))
        });
        let now: BTreeSet<(String, String)> = unread.collect();
        let warned = self.networks.warned.lock();
        let mut warned = warned.unwrap_or_else(PoisonError::into_inner);
        let new = now.difference(&warned).map(|(name, _)| {
            format!(
                "The policy \"{name}\" sets {ALLOWED_NETWORKS} to a value that does not parse: \
                 the users it applies to are refused as unreadable until it is set again"
            )
        });
        let new = new.collect();
        *warned = now;
        new
    }
}

/// Beside inactivity-days' warnings, in the follow of the policies.
pub fn warn_unreadable(cache: &PolicyCache, policies: &[Policy]) {
    for warning in cache.unreadable_networks(policies) {
        warn!("{warning}");
    }
}

/// What a policy save tells its author whose own list, as it now stands, refuses them.
pub fn own_list_warning(levels: &[PolicyLevel], address: Option<IpAddr>) -> Option<String> {
    let items = resolve_effective_items(POLICY_ITEM_CATALOG, levels);
    let item = items.iter().find(|item| item.key == ALLOWED_NETWORKS)?;
    let admitted = parse_list(&item.value).is_ok_and(|nets| admits(&nets, address));
    (!admitted).then(|| {
        let seen = address.map_or_else(|| "unknown".to_owned(), |address| address.to_string());
        let source = item.source.as_ref();
        let ou = source.map_or("<ou>", |source| ou_display(&source.ou_key));
        format!(
            "{ALLOWED_NETWORKS}: the list that now applies to you does not contain the address \
             the server sees you as ({seen}). The way back, on the host: lldap policy-unlink \
             --config-file <config> '{ou}'"
        )
    })
}

/// After a policy save; never an error. While no OU sets the item nothing is read.
pub async fn author_warnings<H>(
    handler: &H,
    cache: &PolicyCache,
    author: &UserId,
    address: Option<IpAddr>,
) -> Vec<String>
where
    H: PolicyBackendHandler + ?Sized,
{
    if cache.item_off(ALLOWED_NETWORKS) {
        return Vec::new();
    }
    let read = tokio::time::timeout(POLICY_READ_WAIT, handler.bounded_policy_entry(author));
    let levels = match read.await {
        Ok(Ok((_, levels))) => levels,
        Ok(Err(e)) => {
            warn!("The list that applies to {author} was not read after a policy save: {e}");
            return Vec::new();
        }
        Err(_) => {
            warn!("The list that applies to {author} was not read: {POLICY_UNANSWERED}");
            return Vec::new();
        }
    };
    own_list_warning(&levels, address).into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::{
        INACTIVITY_DAYS, ItemFlags, Refusal, UNREADABLE, decide, default_item_checks,
    };
    use crate::instant::{Timestamp, days};
    use crate::logging::{RequestMeta, with_request_sync};
    use crate::policies::{
        AttachedPolicy, EffectiveItem, PolicyId, PolicyScope, catalog_item, validate_items,
    };
    use pretty_assertions::assert_eq;
    use std::collections::BTreeMap;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn nets(value: &str) -> Vec<Net> {
        parse_list(value).unwrap()
    }

    fn item(key: &str, value: &str) -> EffectiveItem {
        EffectiveItem {
            key: key.to_owned(),
            scope: PolicyScope::User,
            value: value.to_owned(),
            enforced: true,
            source: None,
        }
    }

    fn attempt<'a>(user: &'a UserId, door: Door, peer: Option<&str>) -> Attempt<'a> {
        Attempt {
            user,
            door,
            peer: peer.map(ip),
            now: Timestamp::from_second(1_700_000_000).unwrap(),
            second_factor: false,
        }
    }

    fn refused(door: Door) -> Result<(), Refusal> {
        Err(Refusal {
            item: ALLOWED_NETWORKS,
            door,
            reason: Some(ADDRESS_NOT_ALLOWED),
        })
    }

    fn linked(name: &str, value: &str, ous: &[&str]) -> Policy {
        Policy {
            id: PolicyId(5),
            name: name.to_owned(),
            description: String::new(),
            items: BTreeMap::from([(ALLOWED_NETWORKS.to_owned(), value.to_owned())]),
            linked_ous: ous.iter().map(|ou| ou.to_string()).collect(),
        }
    }

    fn level(ou: &str, blocked: bool, list: Option<&str>) -> PolicyLevel {
        let policy = list.map(|value| AttachedPolicy {
            id: PolicyId(5),
            name: "nets".to_owned(),
            items: BTreeMap::from([(ALLOWED_NETWORKS.to_owned(), value.to_owned())]),
        });
        PolicyLevel {
            ou_key: ou.to_owned(),
            blocked,
            policy,
        }
    }

    #[test]
    fn test_the_matcher_masks_host_bits_and_never_mixes_families() {
        let rows = [
            ("10.0.0.0/8", "10.255.0.1", true),
            ("10.0.0.0/8", "11.0.0.1", false),
            ("10.0.0.1/8", "10.9.9.9", true),
            ("10.1.2.3/31", "10.1.2.2", true),
            ("192.0.2.7/32", "192.0.2.7", true),
            ("192.0.2.7/32", "192.0.2.8", false),
            ("0.0.0.0/0", "203.0.113.9", true),
            ("0.0.0.0/0", "2001:db8::1", false),
            ("2001:db8::/32", "2001:db8:ffff::1", true),
            ("2001:db8::/32", "2001:db9::1", false),
            ("2001:db8::1/64", "2001:db8::ffff", true),
            ("2001:db8::1/128", "2001:db8::1", true),
            ("2001:db8::1/128", "2001:db8::2", false),
            ("::/0", "2001:db8::1", true),
            ("::/0", "10.0.0.1", false),
            ("10.0.0.0/8", "::ffff:10.1.2.3", true),
            ("10.0.0.0/8", "::ffff:11.1.2.3", false),
            ("::/0", "::ffff:10.1.2.3", false),
            ("::ffff:10.0.0.0/104", "::ffff:10.1.2.3", false),
            ("10.0.0.0/8", "::10.1.2.3", false),
        ];
        for (net, address, inside) in rows {
            let parsed = Net::parse(net).unwrap();
            assert_eq!(parsed.contains(ip(address)), inside, "{net} {address}");
        }
    }

    #[test]
    fn test_the_list_parser_accepts_exactly_what_the_validator_accepts() {
        let rows: [(&str, Result<usize, &str>); 19] = [
            ("", Ok(0)),
            ("10.0.0.0/8,2001:db8::/32", Ok(2)),
            ("192.168.1.0/24, 2001:db8::/32", Ok(2)),
            (" 10.0.0.1/8 ", Ok(1)),
            ("10.0.0.0/024", Ok(1)),
            ("0.0.0.0/0,::/0", Ok(2)),
            ("10.0.0.0", Err("CIDR must include an explicit prefix")),
            ("10.0.0.0/+24", Err("CIDR prefix must be a number")),
            ("10.0.0.0/", Err("CIDR prefix must be a number")),
            ("10.0.0.0/99999999999", Err("CIDR prefix must be a number")),
            ("10.0.0.0/8/8", Err("CIDR prefix must be a number")),
            ("10.0.0.0/33", Err("IPv4 prefix must be 0-32")),
            ("2001:db8::/129", Err("IPv6 prefix must be 0-128")),
            ("not-an-ip/24", Err("CIDR address is not a valid IP")),
            ("[2001:db8::]/32", Err("CIDR address is not a valid IP")),
            ("010.0.0.0/8", Err("CIDR address is not a valid IP")),
            ("10.0.0.0/8,,", Err("list elements cannot be empty")),
            (" ", Err("list elements cannot be empty")),
            ("10.0.0.0/8 ,", Err("list elements cannot be empty")),
        ];
        for (value, expected) in rows {
            let expected = expected.map_err(str::to_owned);
            let parsed = parse_list(value).map(|nets| nets.len());
            let stored = BTreeMap::from([(ALLOWED_NETWORKS.to_owned(), value.to_owned())]);
            let validated = validate_items(&stored);
            let said = expected.clone().map(drop);
            let said = said.map_err(|e| format!("{ALLOWED_NETWORKS}: {e}"));
            assert_eq!((parsed, validated), (expected, said), "{value:?}");
        }
    }

    #[test]
    fn test_the_forwarded_address_is_believed_only_from_a_listed_proxy() {
        let listed = nets("10.9.0.1/32, 10.9.0.2/32");
        let proxies: &[Net] = &listed;
        let none: &[Net] = &[];
        type Row<'a> = (
            &'a str,
            Option<&'a str>,
            &'a [&'a str],
            &'a [Net],
            Option<&'a str>,
        );
        let rows: [Row; 22] = [
            (
                "no list: the header is ignored",
                Some("10.9.0.1"),
                &["203.0.113.9"],
                none,
                Some("10.9.0.1"),
            ),
            (
                "a listed proxy with one entry",
                Some("10.9.0.1"),
                &["203.0.113.9"],
                proxies,
                Some("203.0.113.9"),
            ),
            (
                "a chain through two listed proxies: the right-most entry that is no proxy",
                Some("10.9.0.1"),
                &["198.51.100.4, 203.0.113.9, 10.9.0.2"],
                proxies,
                Some("203.0.113.9"),
            ),
            (
                "a name on the way: unknown",
                Some("10.9.0.1"),
                &["203.0.113.9, bogus, 10.9.0.2"],
                proxies,
                None,
            ),
            (
                "an entry that is no address left of the client is not on the way",
                Some("10.9.0.1"),
                &["bogus, 203.0.113.9"],
                proxies,
                Some("203.0.113.9"),
            ),
            (
                "an unlisted peer with a forged header",
                Some("192.0.2.50"),
                &["203.0.113.9"],
                proxies,
                Some("192.0.2.50"),
            ),
            (
                "two header lines are one list, read from the last",
                Some("10.9.0.1"),
                &["198.51.100.4", "203.0.113.9, 10.9.0.2"],
                proxies,
                Some("203.0.113.9"),
            ),
            (
                "two header lines, the last only a proxy",
                Some("10.9.0.1"),
                &["203.0.113.9", "10.9.0.2"],
                proxies,
                Some("203.0.113.9"),
            ),
            (
                "an unreadable line on the way: unknown",
                Some("10.9.0.1"),
                &["10.9.9.9", ""],
                proxies,
                None,
            ),
            (
                "a port: unknown",
                Some("10.9.0.1"),
                &["203.0.113.9:443"],
                proxies,
                None,
            ),
            (
                "brackets: unknown",
                Some("10.9.0.1"),
                &["[2001:db8::9]"],
                proxies,
                None,
            ),
            (
                "brackets with a port: unknown",
                Some("10.9.0.1"),
                &["[2001:db8::9]:443"],
                proxies,
                None,
            ),
            (
                "the text unknown: unknown",
                Some("10.9.0.1"),
                &["unknown"],
                proxies,
                None,
            ),
            (
                "an empty element on the way: unknown",
                Some("10.9.0.1"),
                &["203.0.113.9, , 10.9.0.2"],
                proxies,
                None,
            ),
            (
                "an empty header line: unknown",
                Some("10.9.0.1"),
                &[""],
                proxies,
                None,
            ),
            (
                "a bare IPv6 entry",
                Some("10.9.0.1"),
                &["2001:db8::9"],
                proxies,
                Some("2001:db8::9"),
            ),
            (
                "a mapped entry counts as IPv4",
                Some("10.9.0.1"),
                &["::ffff:203.0.113.9"],
                proxies,
                Some("203.0.113.9"),
            ),
            (
                "a mapped peer is the listed proxy",
                Some("::ffff:10.9.0.1"),
                &["203.0.113.9"],
                proxies,
                Some("203.0.113.9"),
            ),
            (
                "a listed proxy with no header is itself the client",
                Some("10.9.0.1"),
                &[],
                proxies,
                Some("10.9.0.1"),
            ),
            (
                "every entry a listed proxy: the left-most",
                Some("10.9.0.1"),
                &["10.9.0.2, 10.9.0.1"],
                proxies,
                Some("10.9.0.2"),
            ),
            ("no peer", None, &["203.0.113.9"], proxies, None),
            (
                "a mapped peer is given as IPv4",
                Some("::ffff:192.0.2.50"),
                &[],
                none,
                Some("192.0.2.50"),
            ),
        ];
        for (label, peer, lines, trusted, expected) in rows {
            let got = resolve_client(peer.map(ip), lines, trusted);
            assert_eq!(got, expected.map(ip), "{label}");
        }
    }

    #[test]
    fn test_the_check_is_live_with_its_flag_names_the_address_and_does_not_judge_at_s4u() {
        let cache = PolicyCache::new();
        let off = (NetworksCheck.live(&cache), cache.reads());
        let flags = ItemFlags {
            networks: true,
            ..ItemFlags::default()
        };
        cache.set_item_flags(flags);
        let on = (NetworksCheck.live(&cache), cache.reads());
        assert_eq!(
            (off, on),
            ((false, 0), (true, 0)),
            "one atomic read, and no read of the entries"
        );
        let said = (
            NetworksCheck.key(),
            NetworksCheck.reason(),
            NetworksCheck.judges_at_s4u(),
        );
        assert_eq!(said, (ALLOWED_NETWORKS, Some("address not allowed"), false));
        let state = UserState::default();
        let readable = ["", "10.0.0.0/8", "10.0.0.0", "10.0.0.0/8,,"]
            .map(|value| NetworksCheck.readable(value, &state));
        assert_eq!(readable, [true, true, false, false]);
        let spec = catalog_item(ALLOWED_NETWORKS).unwrap();
        assert_eq!(
            (spec.enforced, spec.description),
            (true, "Source CIDRs that may authenticate; empty means any.")
        );
    }

    #[test]
    fn test_inside_is_admitted_outside_and_no_address_refused_and_s4u_is_not_judged() {
        let bob = UserId::new("e5bob");
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(NetworksCheck)];
        let list = "192.0.2.0/24, 2001:db8::/32";
        let unreadable = Err(Refusal {
            item: UNREADABLE,
            door: Door::KerberosAs,
            reason: None,
        });
        let kdc = [
            (
                "v4 inside",
                Door::KerberosAs,
                Some("192.0.2.7"),
                list,
                Ok(()),
            ),
            (
                "v4 outside",
                Door::KerberosAs,
                Some("198.51.100.7"),
                list,
                refused(Door::KerberosAs),
            ),
            (
                "v6 inside",
                Door::KerberosTgs,
                Some("2001:db8::7"),
                list,
                Ok(()),
            ),
            (
                "v6 outside",
                Door::KerberosTgs,
                Some("2001:db9::7"),
                list,
                refused(Door::KerberosTgs),
            ),
            (
                "a mapped address inside",
                Door::KerberosAs,
                Some("::ffff:192.0.2.7"),
                list,
                Ok(()),
            ),
            (
                "no address",
                Door::KerberosAs,
                None,
                list,
                refused(Door::KerberosAs),
            ),
            (
                "no address, an empty list",
                Door::KerberosAs,
                None,
                "",
                Ok(()),
            ),
            (
                "a service asking for the user is not judged",
                Door::KerberosS4u,
                Some("198.51.100.7"),
                list,
                Ok(()),
            ),
            (
                "a list that does not parse",
                Door::KerberosAs,
                Some("192.0.2.7"),
                "192.0.2.0",
                unreadable,
            ),
        ];
        let state = UserState::default();
        for (label, door, peer, value, expected) in kdc {
            let items = [item(ALLOWED_NETWORKS, value)];
            let got = decide(&attempt(&bob, door, peer), &items, &state, &checks);
            assert_eq!(got, expected, "{label}");
        }
        let behind = |peer: &str, client: Option<&str>| RequestMeta {
            client_address: client.map(ip),
            ..RequestMeta::http(Some(ip(peer)), Some("203.0.113.1".to_owned()))
        };
        let doors = [
            (
                "the resolved address inside, the socket peer outside",
                Door::SimpleLogin,
                behind("10.9.0.1", Some("192.0.2.7")),
                Ok(()),
            ),
            (
                "the resolved address outside, the socket peer inside",
                Door::WebLogin,
                behind("192.0.2.8", Some("198.51.100.7")),
                refused(Door::WebLogin),
            ),
            (
                "a refresh with no resolved address",
                Door::Refresh,
                behind("192.0.2.8", None),
                refused(Door::Refresh),
            ),
            (
                "a token's use from inside",
                Door::TokenUse,
                behind("10.9.0.1", Some("2001:db8::9")),
                Ok(()),
            ),
            (
                "LDAP: the socket peer",
                Door::LdapBind,
                RequestMeta::ldap(None, Some(ip("198.51.100.9"))),
                refused(Door::LdapBind),
            ),
        ];
        for (label, door, meta, expected) in doors {
            let items = [item(ALLOWED_NETWORKS, list)];
            let got = with_request_sync(meta, || {
                decide(&Attempt::new(&bob, door), &items, &state, &checks)
            });
            assert_eq!(got, expected, "{label}");
        }
        let detail = refused(Door::LdapBind).map_err(|refusal| refusal.detail());
        assert_eq!(
            detail,
            Err("policy: allowed-networks (address not allowed)".to_owned())
        );
    }

    #[test]
    fn test_the_check_is_registered_after_inactivity_and_named_only_when_it_alone_refuses() {
        let checks = default_item_checks();
        let keys: Vec<&str> = checks.iter().map(|check| check.key()).collect();
        let at = |key| keys.iter().position(|registered| *registered == key);
        assert!(
            at(INACTIVITY_DAYS).is_some() && at(ALLOWED_NETWORKS) > at(INACTIVITY_DAYS),
            "{keys:?}"
        );
        let bob = UserId::new("e5both");
        let outside = attempt(&bob, Door::KerberosAs, Some("198.51.100.7"));
        let items = [
            item(INACTIVITY_DAYS, "1"),
            item(ALLOWED_NETWORKS, "192.0.2.0/24"),
        ];
        let named = |since| {
            let state = UserState {
                active_since: Some(since),
                ..UserState::default()
            };
            decide(&outside, &items, &state, &checks).map_err(|refusal| refusal.item)
        };
        assert_eq!(
            (named(outside.now - days(2)), named(outside.now)),
            (Err(INACTIVITY_DAYS), Err(ALLOWED_NETWORKS)),
            "an inactive user outside the list is named inactive"
        );
    }

    #[test]
    fn test_one_warning_for_a_list_that_does_not_parse_until_it_changes() {
        let cache = PolicyCache::new();
        let bad = linked("nets", "10.0.0.0", &["people"]);
        let unlinked = linked("spare", "x", &[]);
        let good = linked("nets", "10.0.0.0/8", &["people"]);
        let said = [
            cache.unreadable_networks(&[bad.clone(), unlinked]),
            cache.unreadable_networks(std::slice::from_ref(&bad)),
            cache.unreadable_networks(&[good]),
            cache.unreadable_networks(&[bad]),
        ];
        let text = "The policy \"nets\" sets allowed-networks to a value that does not parse: the \
                    users it applies to are refused as unreadable until it is set again"
            .to_owned();
        assert_eq!(said, [vec![text.clone()], vec![], vec![], vec![text]]);
    }

    #[test]
    fn test_the_warning_follows_the_authors_own_effective_list() {
        let text = |seen: &str, ou: &str| {
            Some(format!(
                "allowed-networks: the list that now applies to you does not contain the address \
                 the server sees you as ({seen}). The way back, on the host: lldap policy-unlink \
                 --config-file <config> '{ou}'"
            ))
        };
        let list = Some("10.73.0.0/16");
        let own = || vec![level("", false, None), level("e5team", false, list)];
        let rows = [
            (
                "linked to the author's OU",
                own(),
                Some("192.0.2.5"),
                text("192.0.2.5", "e5team"),
            ),
            ("linked, the author inside", own(), Some("10.73.0.9"), None),
            ("linked, no address", own(), None, text("unknown", "e5team")),
            (
                "unlinked: no level carries it",
                vec![level("", false, None), level("e5team", false, None)],
                Some("192.0.2.5"),
                None,
            ),
            (
                "inherited from the root",
                vec![level("", false, list), level("e5team", false, None)],
                Some("192.0.2.5"),
                text("192.0.2.5", "(root)"),
            ),
            (
                "blocked below the root",
                vec![level("", false, list), level("e5team", true, None)],
                Some("192.0.2.5"),
                None,
            ),
            (
                "a closer empty list",
                vec![level("", false, list), level("e5team", false, Some(""))],
                Some("192.0.2.5"),
                None,
            ),
            (
                "a closer list that does not parse",
                vec![
                    level("", false, None),
                    level("e5team", false, Some("10.73.0.0")),
                ],
                Some("10.73.0.9"),
                text("10.73.0.9", "e5team"),
            ),
        ];
        for (label, levels, address, expected) in rows {
            let got = own_list_warning(&levels, address.map(ip));
            assert_eq!(got, expected, "{label}");
        }
    }

    #[test]
    fn test_trusted_proxies_take_the_items_grammar_and_a_bad_entry_is_named() {
        let count = |value| parse_trusted(value).map(|nets| nets.len());
        assert_eq!(
            (count(""), count("10.9.0.1/32, 2001:db8::/64")),
            (Ok(0), Ok(2))
        );
        let rows = [
            (
                "10.9.0.1",
                "trusted_proxies \"10.9.0.1\" is refused: CIDR must include an explicit prefix",
            ),
            (
                "10.9.0.1/32,10.9.0.2/33",
                "trusted_proxies \"10.9.0.2/33\" is refused: IPv4 prefix must be 0-32",
            ),
            (
                "10.9.0.1/32,",
                "trusted_proxies \"\" is refused: list elements cannot be empty",
            ),
            (
                "proxy.example/32",
                "trusted_proxies \"proxy.example/32\" is refused: CIDR address is not a valid IP",
            ),
        ];
        for (value, said) in rows {
            assert_eq!(count(value), Err(said.to_owned()), "{value}");
        }
        let cache = PolicyCache::new();
        let before = cache.trusted_proxies().len();
        cache.set_trusted_proxies(nets("10.9.0.1/32"));
        let held = cache.trusted_proxies().to_vec();
        assert_eq!((before, held), (0, nets("10.9.0.1/32")));
    }
}
