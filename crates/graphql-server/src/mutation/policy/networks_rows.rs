use super::*;
use crate::mutation::Mutation;
use crate::query::Query;
use juniper::{EmptySubscription, RootNode, Value, Variables, execute, graphql_value};
use lldap_auth::access_control::{Permission, ValidationResults};
use lldap_domain::types::UserId;
use lldap_domain_handlers::enforcement::{ALLOWED_NETWORKS, ItemFlags};
use lldap_domain_handlers::logging::{RequestMeta, with_request};
use lldap_domain_handlers::networks::{parse_list, resolve_client};
use lldap_domain_handlers::policies::{AttachedPolicy, PolicyLevel};
use lldap_domain_model::error::DomainError;
use lldap_test_utils::enforcement::EnforcementGuard;
use lldap_test_utils::{MockTestBackendHandler, user_named};
use mockall::predicate::eq;
use pretty_assertions::assert_eq;
use serial_test::serial;

type Schema = RootNode<
    Query<MockTestBackendHandler>,
    Mutation<MockTestBackendHandler>,
    EmptySubscription<Context<MockTestBackendHandler>>,
>;

fn schema() -> Schema {
    RootNode::new(Query::new(), Mutation::default(), EmptySubscription::new())
}

fn signed_in(
    mock: MockTestBackendHandler,
    user: &str,
    permission: Permission,
) -> Context<MockTestBackendHandler> {
    let user = UserId::new(user);
    Context::new_for_tests(mock, ValidationResults { user, permission })
}

fn seen_as(address: &str) -> RequestMeta {
    RequestMeta {
        client_address: address.parse().ok(),
        ..RequestMeta::http("10.9.0.1".parse().ok(), None)
    }
}

fn levels(list: &str) -> Vec<PolicyLevel> {
    let items = [(ALLOWED_NETWORKS.to_owned(), list.to_owned())].into();
    let policy = AttachedPolicy {
        id: PolicyId(9),
        name: "nets".to_owned(),
        items,
    };
    vec![PolicyLevel {
        ou_key: String::new(),
        blocked: false,
        policy: Some(policy),
    }]
}

#[tokio::test]
async fn test_client_address_shows_the_judged_address_and_null_without_one() {
    let behind = |trusted: &str, forwarded: &str| {
        let peer = "10.9.0.1".parse().ok();
        let client = resolve_client(peer, &[forwarded], &parse_list(trusted).unwrap());
        RequestMeta {
            client_address: client,
            ..RequestMeta::http(peer, Some(forwarded.to_owned()))
        }
    };
    let rows = [
        (
            "behind a listed proxy: the forwarded address",
            behind("10.9.0.1/32", "203.0.113.9"),
            graphql_value!({"clientAddress": "203.0.113.9"}),
        ),
        (
            "without the list: the socket peer",
            behind("", "203.0.113.9"),
            graphql_value!({"clientAddress": "10.9.0.1"}),
        ),
        (
            "behind a listed proxy, an entry with a port: unknown",
            behind("10.9.0.1/32", "203.0.113.9:443"),
            graphql_value!({"clientAddress": null}),
        ),
        (
            "an IPv6 peer",
            RequestMeta::http("2001:db8::5".parse().ok(), None),
            graphql_value!({"clientAddress": "2001:db8::5"}),
        ),
        (
            "no address",
            RequestMeta::default(),
            graphql_value!({"clientAddress": null}),
        ),
    ];
    for (label, meta, expected) in rows {
        let context = signed_in(MockTestBackendHandler::new(), "bob", Permission::Regular);
        let schema = schema();
        let variables = Variables::new();
        let asked = execute("{ clientAddress }", None, &schema, &variables, &context);
        let (value, errors) = with_request(meta, asked).await.unwrap();
        assert_eq!((errors.len(), value), (0, expected), "{label}");
    }
}

#[tokio::test]
#[serial]
async fn test_a_policy_save_warns_when_the_authors_own_list_refuses_them() {
    let _guard = EnforcementGuard::none();
    let saves = [
        (
            "updatePolicy",
            r#"mutation { updatePolicy(policyId: 9, items: [{key: "allowed-networks", value: "10.73.0.0/16"}]) { ok warnings } }"#,
        ),
        (
            "setOuPolicy",
            r#"mutation { setOuPolicy(ou: "", policyId: 9) { ok warnings } }"#,
        ),
        (
            "clearOuPolicy",
            r#"mutation { clearOuPolicy(ou: "") { ok warnings } }"#,
        ),
        (
            "setOuPolicyInheritance",
            r#"mutation { setOuPolicyInheritance(ou: "people", blocked: false) { ok warnings } }"#,
        ),
        (
            "deletePolicy",
            r#"mutation { deletePolicy(policyId: 9) { ok warnings } }"#,
        ),
    ];
    let warned = "allowed-networks: the list that now applies to you does not contain the address \
                  the server sees you as (192.0.2.5). The way back, on the host: lldap \
                  policy-unlink --config-file <config> '(root)'";
    type Row<'a> = (&'a str, bool, Option<bool>, &'a str, &'a [&'a str]);
    let rows: [Row; 4] = [
        (
            "no OU sets the item: nothing is read",
            false,
            None,
            "192.0.2.5",
            &[],
        ),
        (
            "the author's list refuses the author",
            true,
            Some(true),
            "192.0.2.5",
            &[warned],
        ),
        (
            "the author inside the list",
            true,
            Some(true),
            "10.73.0.9",
            &[],
        ),
        (
            "the read fails: the save stands",
            true,
            Some(false),
            "192.0.2.5",
            &[],
        ),
    ];
    for (label, live, read, address, said) in rows {
        let flags = ItemFlags {
            networks: live,
            ..ItemFlags::default()
        };
        policy_cache().set_item_flags(flags);
        for (save, query) in saves {
            let mut mock = MockTestBackendHandler::new();
            mock.expect_update_policy().returning(|_| Ok(()));
            mock.expect_set_ou_policy().returning(|_, _| Ok(()));
            mock.expect_clear_ou_policy().returning(|_| Ok(()));
            mock.expect_set_ou_policy_inheritance()
                .returning(|_, _| Ok(()));
            mock.expect_delete_policy().returning(|_| Ok(()));
            mock.expect_get_allowed_ous()
                .returning(|| Ok(vec!["people".to_owned()]));
            mock.expect_bounded_policy_entry()
                .with(eq(UserId::new("admin")))
                .times(usize::from(read.is_some()))
                .returning(move |_| match read {
                    Some(true) => Ok((user_named(&UserId::new("admin")), levels("10.73.0.0/16"))),
                    _ => Err(DomainError::InternalError("down".to_owned())),
                });
            let context = signed_in(mock, "admin", Permission::Admin);
            let schema = schema();
            let variables = Variables::new();
            let asked = execute(query, None, &schema, &variables, &context);
            let (value, errors) = with_request(seen_as(address), asked).await.unwrap();
            let list = Value::list(said.iter().map(|w| graphql_value!(*w)).collect());
            let expected = match save {
                "updatePolicy" => graphql_value!({"updatePolicy": {"ok": true, "warnings": list}}),
                "setOuPolicy" => graphql_value!({"setOuPolicy": {"ok": true, "warnings": list}}),
                "clearOuPolicy" => {
                    graphql_value!({"clearOuPolicy": {"ok": true, "warnings": list}})
                }
                "setOuPolicyInheritance" => {
                    graphql_value!({"setOuPolicyInheritance": {"ok": true, "warnings": list}})
                }
                _ => graphql_value!({"deletePolicy": {"ok": true, "warnings": list}}),
            };
            assert_eq!((errors.len(), value), (0, expected), "{save}: {label}");
        }
    }
    let mut mock = MockTestBackendHandler::new();
    mock.expect_unlock_user().times(1).returning(|_| Ok(()));
    mock.expect_bounded_policy_entry().times(0);
    let context = signed_in(mock, "admin", Permission::Admin);
    let schema = schema();
    let query = r#"mutation { unlockUser(userId: "bob") { ok warnings } }"#;
    let variables = Variables::new();
    let asked = execute(query, None, &schema, &variables, &context);
    let (value, errors) = with_request(seen_as("192.0.2.5"), asked).await.unwrap();
    assert_eq!(
        (errors.len(), value),
        (
            0,
            graphql_value!({"unlockUser": {"ok": true, "warnings": []}})
        ),
        "a write that is no policy save reads nothing and warns of nothing"
    );
}
