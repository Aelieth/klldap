use super::*;
use lldap_domain_handlers::enforcement::ALLOWED_NETWORKS;
use pretty_assertions::assert_eq;
use serial_test::serial;

const NOT_ALLOWED: &str = "policy: allowed-networks (address not allowed)";

type Said = Result<(), (i32, Option<String>)>;

fn from(text: &str) -> HostAddress {
    HostAddress::from_socket(text.parse().unwrap())
}

fn asked_as(
    verdict: &KdcVerdict,
    store: &SharedDump,
    user: &str,
    peer: Option<&HostAddress>,
    s4u2self: bool,
) -> Said {
    let guard = store.read().unwrap();
    let client = guard.get_name(&name(user)).unwrap();
    let krbtgt = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", REALM]);
    let server = guard.fetch_name(&krbtgt).unwrap().unwrap();
    let mut request = tgs_body(&ticket(REALM, user));
    let service = PrincipalName::new(PrincipalName::NT_SRV_HST, SERVICE.split('/'));
    request.sname = Some(service);
    let requested = name(user);
    let q = AsQuestion {
        client,
        requested: &requested,
        server: &server,
        peer,
        now: 1_700_000_000,
        request: &request,
        s4u2self,
    };
    verdict.check_as(&q).map_err(|r| (r.code, r.e_text))
}

fn asked_tgs(
    verdict: &KdcVerdict,
    store: &SharedDump,
    user: &str,
    peer: Option<&HostAddress>,
    kind: TgsKind,
) -> Said {
    let guard = store.read().unwrap();
    let client = guard.get_name(&name(user)).unwrap();
    let krbtgt = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", REALM]);
    let server = guard.fetch_name(&krbtgt).unwrap().unwrap();
    let ticket = ticket(REALM, user);
    let request = tgs_body(&ticket);
    let subject = name(user);
    let q = TgsQuestion {
        client: TgsClient::Found(client),
        subject: &subject,
        server: &server,
        ticket: &ticket,
        request: &request,
        peer,
        now: 1_700_000_000,
        kind,
    };
    verdict.check_tgs(&q).map_err(|r| (r.code, r.e_text))
}

#[tokio::test]
#[serial]
async fn test_the_kdc_judges_its_socket_peer_with_v4_v6_and_none_and_never_at_s4u() {
    let user = "e5kdc";
    let (_temp, _embedded, store) = realm(&[user]).await;
    let _guard = EnforcementGuard::default_checks();
    let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
    let counter: &'static Lockout = Box::leak(Box::default());
    let list = EffectiveItem {
        key: ALLOWED_NETWORKS.to_owned(),
        scope: PolicyScope::User,
        value: "192.0.2.0/24, 2001:db8::/32".to_owned(),
        enforced: true,
        source: None,
    };
    cache.replace(Entries {
        ous_of_users: HashMap::from([(UserId::new(user), "e5ou".to_owned())]),
        items_of_ous: HashMap::from([("e5ou".to_owned(), vec![list].into())]),
        facts: HashMap::new(),
        windows: HashMap::new(),
        built_at: Timestamp::now(),
    });
    let flags = ItemFlags {
        networks: true,
        ..ItemFlags::default()
    };
    cache.set_item_flags(flags);
    let verdict = Arc::new(KdcVerdict::on(REALM, cache, counter));
    store
        .write()
        .unwrap()
        .policy
        .plugins
        .set_host_admission(verdict.clone());
    let log = LogGuard::install_on_this_thread();
    let (v4_in, v4_out) = (from("192.0.2.7:88"), from("198.51.100.7:88"));
    let (v6_in, v6_out) = (from("[2001:db8::7]:88"), from("[2001:db9::7]:88"));
    let mapped = from("[::ffff:192.0.2.7]:88");
    let as_from = |peer, s4u2self| asked_as(&verdict, &store, user, peer, s4u2self);
    let refused: Said = Err((err::CLIENT_REVOKED, None));
    assert_eq!(
        [
            as_from(Some(&v4_in), false),
            as_from(Some(&v4_out), false),
            as_from(Some(&v6_in), false),
            as_from(Some(&v6_out), false),
            as_from(Some(&mapped), false),
            as_from(None, false),
            as_from(Some(&v4_out), true),
        ],
        [
            Ok(()),
            refused.clone(),
            Ok(()),
            refused.clone(),
            Ok(()),
            refused.clone(),
            Ok(())
        ],
        "AS: v4 and v6 inside and outside, a mapped address inside, no address; an S4U2Self \
         from outside is not judged"
    );
    let tgs_from = |peer, kind| asked_tgs(&verdict, &store, user, peer, kind);
    assert_eq!(
        [
            tgs_from(Some(&v4_in), TgsKind::Renew),
            tgs_from(Some(&v4_out), TgsKind::Renew),
            tgs_from(Some(&v6_in), TgsKind::Normal),
            tgs_from(Some(&v6_out), TgsKind::Normal),
            tgs_from(None, TgsKind::Normal),
            tgs_from(Some(&v4_out), TgsKind::S4u2Self),
            tgs_from(Some(&v4_out), TgsKind::S4u2Proxy),
        ],
        [
            Ok(()),
            refused.clone(),
            Ok(()),
            refused.clone(),
            refused.clone(),
            Ok(()),
            Ok(())
        ],
        "TGS: a renewal and a service ticket inside and outside, with no address; the S4U kinds \
         are not judged"
    );
    let signed_in = kinit(&store, user, Some(PASSWORD));
    let denied = |peer: Option<&str>| {
        let peer = peer.map(str::to_owned);
        let target = Some(user.to_owned());
        let detail = Some(NOT_ALLOWED.to_owned());
        (LogKind::AccessDenied, false, target, peer, detail)
    };
    assert_eq!(
        (signed_in, kdc_rows(&log)),
        (
            (err::CLIENT_REVOKED, None),
            vec![
                denied(Some("198.51.100.7")),
                denied(Some("2001:db9::7")),
                denied(None),
                row(LogKind::Login, false, user, NOT_ALLOWED),
            ]
        ),
        "18 with no text; the reason and the socket peer in the row only; a kinit whose request \
         carries no address is refused"
    );
}
