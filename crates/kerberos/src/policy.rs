use krb5_kdc::{
    Error, KDB_DISALLOW_ALL_TIX, KdcPolicy, PolicyAdjustment, Principal, PrincipalRead,
};
use krb5_types::{EncTicketPart, KdcReqBody, PrincipalName, err};
use tracing::info;

const LOCKED_OUT: &str = "CLIENT LOCKED OUT";
const NOT_FOUND: &str = "CLIENT_NOT_FOUND";

// Neither MIT nor kerber-rust looks at the client again once it holds a TGT, so a disabled or
// deleted user would keep getting service tickets and renewals until the TGT expired.
pub(crate) struct LiveClients;

impl KdcPolicy for LiveClients {
    fn name(&self) -> &'static str {
        "lldap_live_clients"
    }

    fn check_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Ok(PolicyAdjustment::default())
    }

    fn check_tgs(
        &self,
        _store: &dyn PrincipalRead,
        _sname: &PrincipalName,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Ok(PolicyAdjustment::default())
    }

    fn check_tgs_req(
        &self,
        _request: &KdcReqBody,
        store: &dyn PrincipalRead,
        _server: &Principal,
        ticket: &EncTicketPart,
        _indicators: &[String],
        status: &mut Option<&'static str>,
    ) -> Result<PolicyAdjustment, Error> {
        if ticket.crealm.as_bytes() != store.realm().as_bytes() {
            return Ok(PolicyAdjustment::default());
        }
        let (word, reason) = match store.fetch_name(&ticket.cname)? {
            Some(client) if client.attributes & KDB_DISALLOW_ALL_TIX == 0 => {
                return Ok(PolicyAdjustment::default());
            }
            Some(_) => (LOCKED_OUT, "is disabled"),
            None => (NOT_FOUND, "no longer exists"),
        };
        let principal = ticket.cname.unparse_with_realm_lossy(store.realm());
        info!("Refused a Kerberos ticket request from {principal}: the principal {reason}");
        *status = Some(word);
        Err(Error::Protocol {
            code: err::CLIENT_REVOKED,
            text: Some(word.to_owned()),
            e_data: None,
            detail: Some(format!("{principal}: {word}")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded::tests::TempRealm;
    use krb5_types::{
        EncryptionKey, KdcOptions, KerberosTime, TicketFlags, TransitedEncoding, try_ascii,
    };
    use lldap_domain::types::UserId;
    use lldap_domain_handlers::kerberos::KerberosSync;
    use pretty_assertions::assert_eq;

    fn ticket(realm: &str, user: &str) -> EncTicketPart {
        let now = KerberosTime::from_unix_seconds(1_700_000_000);
        EncTicketPart {
            flags: TicketFlags::initial_preauth(),
            key: EncryptionKey {
                keytype: 18,
                keyvalue: vec![0u8; 32].into(),
            },
            crealm: try_ascii(realm).unwrap(),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user]),
            transited: TransitedEncoding::empty(),
            authtime: now.clone(),
            starttime: Some(now),
            endtime: KerberosTime::from_unix_seconds(2_000_000_000),
            renew_till: None,
            caddr: None,
            authorization_data: None,
        }
    }

    fn check(store: &dyn PrincipalRead, ticket: &EncTicketPart) -> Result<(), (i32, String)> {
        let request = KdcReqBody {
            kdc_options: KdcOptions::none(),
            cname: None,
            realm: ticket.crealm.clone(),
            sname: None,
            from: None,
            till: KerberosTime::from_unix_seconds(2_000_000_000),
            rtime: None,
            nonce: 1,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };
        let krbtgt = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "EXAMPLE.COM"]);
        let server = store.fetch_name(&krbtgt).unwrap().unwrap();
        let mut status = None;
        match LiveClients.check_tgs_from(&request, store, &server, ticket, &[], None, &mut status) {
            Ok(_) => Ok(()),
            Err(Error::Protocol {
                code,
                text: Some(text),
                ..
            }) if status == Some(text.as_str()) => Err((code, text)),
            Err(e) => panic!("unexpected {e:?}, status {status:?}"),
        }
    }

    #[tokio::test]
    async fn test_a_ticket_outlives_its_user_only_until_the_next_request() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let bob = UserId::new("bob");
        embedded
            .sync_principal(&bob, "Bob-Password-1")
            .await
            .unwrap();
        let revoked = |word: &str| Err((err::CLIENT_REVOKED, word.to_owned()));
        let steps = [
            ("enabled", Ok(())),
            ("disabled", revoked(LOCKED_OUT)),
            ("enabled again", Ok(())),
            ("deleted", revoked(NOT_FOUND)),
        ];
        for (step, expected) in steps {
            match step {
                "disabled" => embedded.set_principal_enabled(&bob, false).await.unwrap(),
                "enabled again" => embedded.set_principal_enabled(&bob, true).await.unwrap(),
                "deleted" => embedded.delete_principal(&bob).await.unwrap(),
                _ => {}
            }
            let guard = store.read().unwrap();
            let got = (
                check(&*guard, &ticket("EXAMPLE.COM", "bob")),
                check(&*guard, &ticket("OTHER.ORG", "bob")),
            );
            assert_eq!(got, (expected, Ok(())), "{step}");
        }
    }
}
