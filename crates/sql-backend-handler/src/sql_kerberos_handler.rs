use crate::sql_migrations::{KerberosPolicies, KerberosPrincipals, KerberosRealm, Users};
use lldap_domain_handlers::kerberos::{
    LoadedPrincipal, LoadedRealm, PolicyRow, PrincipalRow, RealmBatch, RealmState,
    user_id_for_principal_name,
};
use sea_orm::sea_query::{Alias, Expr, OnConflict, Order, Query, Value};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbErr, FromQueryResult};

#[derive(Debug)]
pub(crate) enum KerberosSqlError {
    Failed(String),
    Refused(String),
    GenerationMoved { expected: i64 },
}

impl std::fmt::Display for KerberosSqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(reason) => write!(f, "Kerberos store failed: {reason}"),
            Self::Refused(reason) => write!(f, "Kerberos store refused the change: {reason}"),
            Self::GenerationMoved { expected } => {
                write!(f, "the generation was not {expected}")
            }
        }
    }
}

impl std::error::Error for KerberosSqlError {}

fn failed(err: DbErr) -> KerberosSqlError {
    KerberosSqlError::Failed(err.to_string())
}

#[derive(Debug, FromQueryResult)]
struct StoredRealm {
    realm: String,
    generation: i64,
    state: Vec<u8>,
}

#[derive(Debug, FromQueryResult)]
struct StoredPrincipal {
    name: String,
    record: Vec<u8>,
}

#[derive(Debug, FromQueryResult)]
struct StoredPolicy {
    name: String,
    record: Vec<u8>,
}

pub async fn load_realm(db: &impl ConnectionTrait) -> Result<(LoadedRealm, i64), KerberosSqlError> {
    let backend = db.get_database_backend();
    let principals = StoredPrincipal::find_by_statement(
        backend.build(
            Query::select()
                .columns([KerberosPrincipals::Name, KerberosPrincipals::Record])
                .from(KerberosPrincipals::Table)
                .order_by(KerberosPrincipals::Name, Order::Asc),
        ),
    )
    .all(db)
    .await
    .map_err(failed)?;
    let policies = StoredPolicy::find_by_statement(
        backend.build(
            Query::select()
                .columns([KerberosPolicies::Name, KerberosPolicies::Record])
                .from(KerberosPolicies::Table)
                .order_by(KerberosPolicies::Name, Order::Asc),
        ),
    )
    .all(db)
    .await
    .map_err(failed)?;
    let realm = StoredRealm::find_by_statement(
        backend.build(
            Query::select()
                .columns([
                    KerberosRealm::Realm,
                    KerberosRealm::Generation,
                    KerberosRealm::State,
                ])
                .from(KerberosRealm::Table)
                .and_where(Expr::col(KerberosRealm::Id).eq(1)),
        ),
    )
    .one(db)
    .await
    .map_err(failed)?;
    let generation = realm.as_ref().map(|row| row.generation).unwrap_or(0);
    Ok((
        LoadedRealm {
            principals: principals
                .into_iter()
                .map(|row| LoadedPrincipal {
                    name: row.name,
                    record: row.record,
                })
                .collect(),
            policies: policies
                .into_iter()
                .map(|row| PolicyRow {
                    name: row.name,
                    record: row.record,
                })
                .collect(),
            realm: realm.map(|row| RealmState {
                realm: row.realm,
                state: row.state,
            }),
        },
        generation,
    ))
}

pub async fn commit_batch_with_transaction(
    transaction: &DatabaseTransaction,
    batch: &RealmBatch,
    generation: i64,
) -> Result<(), KerberosSqlError> {
    let realm_name = prepare_realm(transaction, batch, generation).await?;
    for name in &batch.delete_principals {
        delete_principal(transaction, name).await?;
    }
    for name in &batch.delete_policies {
        delete_policy(transaction, name).await?;
    }
    for policy in &batch.put_policies {
        upsert_policy(transaction, policy).await?;
    }
    for principal in &batch.upsert_principals {
        upsert_principal(transaction, principal, &realm_name).await?;
    }
    advance_generation(transaction, generation).await
}

async fn prepare_realm(
    transaction: &DatabaseTransaction,
    batch: &RealmBatch,
    generation: i64,
) -> Result<String, KerberosSqlError> {
    let backend = transaction.get_database_backend();
    let stored = StoredRealm::find_by_statement(
        backend.build(
            Query::select()
                .columns([
                    KerberosRealm::Realm,
                    KerberosRealm::Generation,
                    KerberosRealm::State,
                ])
                .from(KerberosRealm::Table)
                .and_where(Expr::col(KerberosRealm::Id).eq(1)),
        ),
    )
    .one(transaction)
    .await
    .map_err(failed)?;
    let Some(stored) = stored else {
        let Some(incoming) = &batch.realm else {
            return Err(KerberosSqlError::Refused(
                "a first commit needs the realm".to_owned(),
            ));
        };
        transaction
            .execute(
                backend.build(
                    Query::insert()
                        .into_table(KerberosRealm::Table)
                        .columns([
                            KerberosRealm::Id,
                            KerberosRealm::Realm,
                            KerberosRealm::Generation,
                            KerberosRealm::Open,
                            KerberosRealm::State,
                        ])
                        .values_panic([
                            Expr::value(1i32),
                            Expr::value(incoming.realm.clone()),
                            Expr::value(generation),
                            Expr::value(true),
                            Expr::value(bytes_value(incoming.state.clone())),
                        ]),
                ),
            )
            .await
            .map_err(failed)?;
        return Ok(incoming.realm.clone());
    };
    if let Some(incoming) = &batch.realm {
        if incoming.realm != stored.realm {
            return Err(KerberosSqlError::Refused(format!(
                "realm name is {}, batch says {}",
                stored.realm, incoming.realm
            )));
        }
        transaction
            .execute(
                backend.build(
                    Query::update()
                        .table(KerberosRealm::Table)
                        .value(KerberosRealm::State, bytes_value(incoming.state.clone()))
                        .and_where(Expr::col(KerberosRealm::Id).eq(1)),
                ),
            )
            .await
            .map_err(failed)?;
    }
    Ok(stored.realm)
}

async fn delete_principal(
    transaction: &DatabaseTransaction,
    name: &str,
) -> Result<(), KerberosSqlError> {
    let backend = transaction.get_database_backend();
    transaction
        .execute(
            backend.build(
                Query::delete()
                    .from_table(KerberosPrincipals::Table)
                    .and_where(Expr::col(KerberosPrincipals::Name).eq(name)),
            ),
        )
        .await
        .map_err(failed)?;
    if let Some(user_id) = user_id_for_principal_name(name) {
        set_principal_attribute(transaction, user_id, None).await?;
    }
    Ok(())
}

async fn delete_policy(
    transaction: &DatabaseTransaction,
    name: &str,
) -> Result<(), KerberosSqlError> {
    transaction
        .execute(
            transaction.get_database_backend().build(
                Query::delete()
                    .from_table(KerberosPolicies::Table)
                    .and_where(Expr::col(KerberosPolicies::Name).eq(name)),
            ),
        )
        .await
        .map_err(failed)?;
    Ok(())
}

async fn upsert_policy(
    transaction: &DatabaseTransaction,
    policy: &PolicyRow,
) -> Result<(), KerberosSqlError> {
    transaction
        .execute(
            transaction.get_database_backend().build(
                Query::insert()
                    .into_table(KerberosPolicies::Table)
                    .columns([KerberosPolicies::Name, KerberosPolicies::Record])
                    .values_panic([
                        Expr::value(policy.name.clone()),
                        Expr::value(bytes_value(policy.record.clone())),
                    ])
                    .on_conflict(
                        OnConflict::column(KerberosPolicies::Name)
                            .update_columns([KerberosPolicies::Record])
                            .to_owned(),
                    ),
            ),
        )
        .await
        .map_err(failed)?;
    Ok(())
}

async fn upsert_principal(
    transaction: &DatabaseTransaction,
    principal: &PrincipalRow,
    realm_name: &str,
) -> Result<(), KerberosSqlError> {
    let user_id = user_id_for_principal_name(&principal.name).map(str::to_owned);
    if let Some(user_id) = &user_id
        && !user_exists(transaction, user_id).await?
    {
        return Err(KerberosSqlError::Refused(format!(
            "principal {} names user {user_id}, and there is no such user",
            principal.name
        )));
    }
    transaction
        .execute(
            transaction.get_database_backend().build(
                Query::insert()
                    .into_table(KerberosPrincipals::Table)
                    .columns([
                        KerberosPrincipals::Name,
                        KerberosPrincipals::UserId,
                        KerberosPrincipals::Record,
                        KerberosPrincipals::HasKeys,
                        KerberosPrincipals::Disabled,
                        KerberosPrincipals::Kvno,
                        KerberosPrincipals::Expiration,
                        KerberosPrincipals::PasswordExpiration,
                        KerberosPrincipals::Policy,
                        KerberosPrincipals::ModifiedDate,
                    ])
                    .values_panic([
                        Expr::value(principal.name.clone()),
                        Expr::value(string_value(user_id.clone())),
                        Expr::value(bytes_value(principal.record.clone())),
                        Expr::value(principal.has_keys),
                        Expr::value(principal.disabled),
                        Expr::value(principal.kvno),
                        Expr::value(time_value(principal.expiration)),
                        Expr::value(time_value(principal.password_expiration)),
                        Expr::value(string_value(principal.policy.clone())),
                        Expr::value(principal.modified_date),
                    ])
                    .on_conflict(
                        OnConflict::column(KerberosPrincipals::Name)
                            .update_columns([
                                KerberosPrincipals::UserId,
                                KerberosPrincipals::Record,
                                KerberosPrincipals::HasKeys,
                                KerberosPrincipals::Disabled,
                                KerberosPrincipals::Kvno,
                                KerberosPrincipals::Expiration,
                                KerberosPrincipals::PasswordExpiration,
                                KerberosPrincipals::Policy,
                                KerberosPrincipals::ModifiedDate,
                            ])
                            .to_owned(),
                    ),
            ),
        )
        .await
        .map_err(failed)?;
    if let Some(user_id) = user_id {
        let attribute = format!("{}@{realm_name}", principal.name);
        set_principal_attribute(transaction, &user_id, Some(attribute)).await?;
    }
    Ok(())
}

async fn user_exists(
    transaction: &DatabaseTransaction,
    user_id: &str,
) -> Result<bool, KerberosSqlError> {
    let found = transaction
        .query_one(
            transaction.get_database_backend().build(
                Query::select()
                    .expr(Expr::value(1))
                    .from(Users::Table)
                    .and_where(Expr::col(Users::UserId).eq(user_id)),
            ),
        )
        .await
        .map_err(failed)?;
    Ok(found.is_some())
}

async fn set_principal_attribute(
    transaction: &DatabaseTransaction,
    user_id: &str,
    attribute: Option<String>,
) -> Result<(), KerberosSqlError> {
    transaction
        .execute(
            transaction.get_database_backend().build(
                Query::update()
                    .table(Users::Table)
                    .value(Alias::new("krb_principal_name"), string_value(attribute))
                    .and_where(Expr::col(Users::UserId).eq(user_id)),
            ),
        )
        .await
        .map_err(failed)?;
    Ok(())
}

async fn advance_generation(
    transaction: &DatabaseTransaction,
    generation: i64,
) -> Result<(), KerberosSqlError> {
    let updated = transaction
        .execute(
            transaction.get_database_backend().build(
                Query::update()
                    .table(KerberosRealm::Table)
                    .value(KerberosRealm::Generation, generation + 1)
                    .and_where(Expr::col(KerberosRealm::Id).eq(1))
                    .and_where(Expr::col(KerberosRealm::Generation).eq(generation)),
            ),
        )
        .await
        .map_err(failed)?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(KerberosSqlError::GenerationMoved {
            expected: generation,
        })
    }
}

pub(crate) struct RealmHold {
    pub generation: i64,
    pub open: bool,
}

#[derive(Debug, FromQueryResult)]
struct HoldRow {
    generation: i64,
    open: bool,
}

pub(crate) async fn read_hold(
    db: &impl ConnectionTrait,
) -> Result<Option<RealmHold>, KerberosSqlError> {
    let row = HoldRow::find_by_statement(
        db.get_database_backend().build(
            Query::select()
                .columns([KerberosRealm::Generation, KerberosRealm::Open])
                .from(KerberosRealm::Table)
                .and_where(Expr::col(KerberosRealm::Id).eq(1)),
        ),
    )
    .one(db)
    .await
    .map_err(failed)?;
    Ok(row.map(|row| RealmHold {
        generation: row.generation,
        open: row.open,
    }))
}

pub(crate) async fn take_realm(
    transaction: &DatabaseTransaction,
    generation: i64,
) -> Result<i64, KerberosSqlError> {
    let updated = transaction
        .execute(
            transaction.get_database_backend().build(
                Query::update()
                    .table(KerberosRealm::Table)
                    .value(KerberosRealm::Open, Expr::value(true))
                    .value(KerberosRealm::Generation, generation + 1)
                    .and_where(Expr::col(KerberosRealm::Id).eq(1))
                    .and_where(Expr::col(KerberosRealm::Generation).eq(generation)),
            ),
        )
        .await
        .map_err(failed)?;
    if updated.rows_affected() == 1 {
        Ok(generation + 1)
    } else {
        Err(KerberosSqlError::GenerationMoved {
            expected: generation,
        })
    }
}

pub(crate) async fn heartbeat(
    transaction: &DatabaseTransaction,
    generation: i64,
) -> Result<i64, KerberosSqlError> {
    let updated = transaction
        .execute(
            transaction.get_database_backend().build(
                Query::update()
                    .table(KerberosRealm::Table)
                    .value(KerberosRealm::Generation, generation + 1)
                    .and_where(Expr::col(KerberosRealm::Id).eq(1))
                    .and_where(Expr::col(KerberosRealm::Generation).eq(generation))
                    .and_where(Expr::col(KerberosRealm::Open).eq(true)),
            ),
        )
        .await
        .map_err(failed)?;
    if updated.rows_affected() == 1 {
        Ok(generation + 1)
    } else {
        Err(KerberosSqlError::GenerationMoved {
            expected: generation,
        })
    }
}

pub(crate) async fn clear_open(
    transaction: &DatabaseTransaction,
    generation: i64,
) -> Result<(), KerberosSqlError> {
    let updated = transaction
        .execute(
            transaction.get_database_backend().build(
                Query::update()
                    .table(KerberosRealm::Table)
                    .value(KerberosRealm::Open, Expr::value(false))
                    .and_where(Expr::col(KerberosRealm::Id).eq(1))
                    .and_where(Expr::col(KerberosRealm::Generation).eq(generation))
                    .and_where(Expr::col(KerberosRealm::Open).eq(true)),
            ),
        )
        .await
        .map_err(failed)?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(KerberosSqlError::GenerationMoved {
            expected: generation,
        })
    }
}

fn bytes_value(value: Vec<u8>) -> Value {
    Value::Bytes(Some(Box::new(value)))
}

fn string_value(value: Option<String>) -> Value {
    Value::String(value.map(Box::new))
}

fn time_value(value: Option<chrono::NaiveDateTime>) -> Value {
    Value::ChronoDateTime(value.map(Box::new))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sql_tables::{DbConnection, init_table};
    use lldap_domain_handlers::kerberos::RealmState;
    use pretty_assertions::assert_eq;
    use sea_orm::{Database, TransactionTrait};

    fn stamp() -> chrono::NaiveDateTime {
        chrono::NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap()
    }

    fn principal(name: &str, record: Vec<u8>) -> PrincipalRow {
        PrincipalRow {
            name: name.to_owned(),
            record,
            has_keys: true,
            disabled: false,
            kvno: 1,
            expiration: None,
            password_expiration: None,
            policy: None,
            modified_date: stamp(),
        }
    }

    fn realm_batch(state: Vec<u8>, principals: Vec<PrincipalRow>) -> RealmBatch {
        RealmBatch {
            upsert_principals: principals,
            delete_principals: Vec::new(),
            put_policies: vec![PolicyRow {
                name: "default".to_owned(),
                record: vec![3],
            }],
            delete_policies: Vec::new(),
            realm: Some(RealmState {
                realm: "EXAMPLE.COM".to_owned(),
                state,
            }),
        }
    }

    async fn memory() -> DbConnection {
        let mut opts = sea_orm::ConnectOptions::new("sqlite::memory:".to_owned());
        opts.max_connections(1).sqlx_logging(false);
        Database::connect(opts).await.unwrap()
    }

    async fn insert_user(pool: &DbConnection, user_id: &str, uuid: &str) {
        let when = stamp();
        pool.execute(
            pool.get_database_backend().build(
                Query::insert()
                    .into_table(Users::Table)
                    .columns([
                        Users::UserId,
                        Users::Email,
                        Users::LowercaseEmail,
                        Users::CreationDate,
                        Users::Uuid,
                        Users::ModifiedDate,
                        Users::PasswordModifiedDate,
                    ])
                    .values_panic([
                        user_id.into(),
                        format!("{user_id}@ex.com").into(),
                        format!("{user_id}@ex.com").into(),
                        when.into(),
                        uuid.into(),
                        when.into(),
                        when.into(),
                    ]),
            ),
        )
        .await
        .unwrap();
    }

    async fn krb_name(pool: &DbConnection, user_id: &str) -> Option<String> {
        #[derive(FromQueryResult)]
        struct Row {
            krb_principal_name: Option<String>,
        }
        Row::find_by_statement(
            pool.get_database_backend().build(
                Query::select()
                    .column(Alias::new("krb_principal_name"))
                    .from(Users::Table)
                    .and_where(Expr::col(Users::UserId).eq(user_id)),
            ),
        )
        .one(pool)
        .await
        .unwrap()
        .unwrap()
        .krb_principal_name
    }

    async fn principal_user(pool: &DbConnection, name: &str) -> Option<String> {
        #[derive(FromQueryResult)]
        struct Row {
            user_id: Option<String>,
        }
        Row::find_by_statement(
            pool.get_database_backend().build(
                Query::select()
                    .column(KerberosPrincipals::UserId)
                    .from(KerberosPrincipals::Table)
                    .and_where(Expr::col(KerberosPrincipals::Name).eq(name)),
            ),
        )
        .one(pool)
        .await
        .unwrap()
        .unwrap()
        .user_id
    }

    async fn realm_is_open(pool: &DbConnection) -> bool {
        #[derive(FromQueryResult)]
        struct Row {
            open: bool,
        }
        Row::find_by_statement(
            pool.get_database_backend().build(
                Query::select()
                    .column(KerberosRealm::Open)
                    .from(KerberosRealm::Table)
                    .and_where(Expr::col(KerberosRealm::Id).eq(1)),
            ),
        )
        .one(pool)
        .await
        .unwrap()
        .unwrap()
        .open
    }

    async fn commit(
        pool: &DbConnection,
        batch: &RealmBatch,
        generation: i64,
    ) -> Result<(), KerberosSqlError> {
        let txn = pool.begin().await.map_err(failed)?;
        match commit_batch_with_transaction(&txn, batch, generation).await {
            Ok(()) => txn.commit().await.map_err(failed),
            Err(err) => {
                txn.rollback().await.map_err(failed)?;
                Err(err)
            }
        }
    }

    pub(crate) async fn scenario_batch_round_trip(pool: &DbConnection) {
        init_table(pool).await.unwrap();
        insert_user(pool, "alice", "11111111-1111-1111-1111-111111111111").await;
        commit(
            pool,
            &realm_batch(
                vec![9],
                vec![
                    principal("alice", vec![1]),
                    principal("HTTP/kc.example.com", vec![2]),
                ],
            ),
            0,
        )
        .await
        .unwrap();
        let (loaded, generation) = load_realm(pool).await.unwrap();
        assert_eq!(generation, 1);
        assert_eq!(
            loaded.realm,
            Some(RealmState {
                realm: "EXAMPLE.COM".to_owned(),
                state: vec![9],
            })
        );
        assert_eq!(
            loaded.principals,
            vec![
                LoadedPrincipal {
                    name: "HTTP/kc.example.com".to_owned(),
                    record: vec![2],
                },
                LoadedPrincipal {
                    name: "alice".to_owned(),
                    record: vec![1],
                },
            ]
        );
        assert_eq!(
            loaded.policies,
            vec![PolicyRow {
                name: "default".to_owned(),
                record: vec![3],
            }]
        );
        assert_eq!(
            krb_name(pool, "alice").await,
            Some("alice@EXAMPLE.COM".to_owned())
        );
        assert_eq!(
            principal_user(pool, "alice").await,
            Some("alice".to_owned())
        );
        assert_eq!(principal_user(pool, "HTTP/kc.example.com").await, None);
        assert!(realm_is_open(pool).await);
    }

    pub(crate) async fn scenario_stale_generation(pool: &DbConnection) {
        scenario_batch_round_trip(pool).await;
        let err = commit(
            pool,
            &RealmBatch {
                upsert_principals: Vec::new(),
                delete_principals: Vec::new(),
                put_policies: vec![PolicyRow {
                    name: "sneak".to_owned(),
                    record: vec![4],
                }],
                delete_policies: Vec::new(),
                realm: None,
            },
            0,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            KerberosSqlError::GenerationMoved { expected: 0 }
        ));
        let (loaded, generation) = load_realm(pool).await.unwrap();
        assert_eq!(generation, 1);
        assert_eq!(loaded.policies.len(), 1);
        assert_eq!(loaded.policies[0].name, "default");
    }

    pub(crate) async fn scenario_failure_rolls_back(pool: &DbConnection) {
        init_table(pool).await.unwrap();
        insert_user(pool, "alice", "11111111-1111-1111-1111-111111111111").await;
        insert_user(pool, "carol", "33333333-3333-3333-3333-333333333333").await;
        pool.execute(
            pool.get_database_backend().build(
                Query::update()
                    .table(Users::Table)
                    .value(
                        Alias::new("krb_principal_name"),
                        string_value(Some("carol@EXAMPLE.COM".to_owned())),
                    )
                    .and_where(Expr::col(Users::UserId).eq("carol")),
            ),
        )
        .await
        .unwrap();
        let batch = realm_batch(
            vec![9],
            vec![principal("alice", vec![1]), principal("ghost", vec![5])],
        );
        let err = commit(pool, &batch, 0).await.unwrap_err();
        let KerberosSqlError::Refused(reason) = err else {
            panic!("expected a refusal, got {err}");
        };
        assert!(reason.contains("ghost"), "{reason}");
        assert!(reason.contains("no such user"), "{reason}");
        let (loaded, generation) = load_realm(pool).await.unwrap();
        assert_eq!(generation, 0);
        assert_eq!(loaded.realm, None);
        assert!(loaded.policies.is_empty());
        assert!(loaded.principals.is_empty());
        assert_eq!(krb_name(pool, "alice").await, None);
        assert_eq!(
            krb_name(pool, "carol").await,
            Some("carol@EXAMPLE.COM".to_owned())
        );
    }

    #[tokio::test]
    async fn test_batch_round_trip() {
        scenario_batch_round_trip(&memory().await).await;
    }

    #[tokio::test]
    async fn test_stale_generation_writes_nothing() {
        scenario_stale_generation(&memory().await).await;
    }

    #[tokio::test]
    async fn test_failure_rolls_back() {
        scenario_failure_rolls_back(&memory().await).await;
    }

    #[tokio::test]
    async fn test_deleting_user_removes_principal() {
        let pool = memory().await;
        scenario_batch_round_trip(&pool).await;
        pool.execute(
            pool.get_database_backend().build(
                Query::delete()
                    .from_table(Users::Table)
                    .and_where(Expr::col(Users::UserId).eq("alice")),
            ),
        )
        .await
        .unwrap();
        let (loaded, _) = load_realm(&pool).await.unwrap();
        assert!(loaded.principals.iter().all(|row| row.name != "alice"));
    }

    #[tokio::test]
    async fn test_principal_name_follows() {
        let pool = memory().await;
        scenario_batch_round_trip(&pool).await;
        assert_eq!(
            krb_name(&pool, "alice").await,
            Some("alice@EXAMPLE.COM".to_owned())
        );
        commit(
            &pool,
            &RealmBatch {
                upsert_principals: Vec::new(),
                delete_principals: vec!["alice".to_owned()],
                put_policies: Vec::new(),
                delete_policies: Vec::new(),
                realm: None,
            },
            1,
        )
        .await
        .unwrap();
        assert_eq!(krb_name(&pool, "alice").await, None);
        let (loaded, generation) = load_realm(&pool).await.unwrap();
        assert_eq!(generation, 2);
        assert!(loaded.principals.iter().all(|row| row.name != "alice"));
    }

    #[tokio::test]
    async fn test_realm_name_change_is_refused() {
        let pool = memory().await;
        scenario_batch_round_trip(&pool).await;
        let err = commit(
            &pool,
            &RealmBatch {
                upsert_principals: Vec::new(),
                delete_principals: Vec::new(),
                put_policies: Vec::new(),
                delete_policies: Vec::new(),
                realm: Some(RealmState {
                    realm: "OTHER.COM".to_owned(),
                    state: vec![8],
                }),
            },
            1,
        )
        .await
        .unwrap_err();
        let KerberosSqlError::Refused(reason) = err else {
            panic!("expected a refusal");
        };
        assert!(reason.contains("EXAMPLE.COM"), "{reason}");
        assert!(reason.contains("OTHER.COM"), "{reason}");
        let (loaded, generation) = load_realm(&pool).await.unwrap();
        assert_eq!(generation, 1);
        assert_eq!(loaded.realm.unwrap().state, vec![9]);
    }

    async fn insert_realm(pool: &DbConnection, generation: i64, open: bool) {
        pool.execute(
            pool.get_database_backend().build(
                Query::insert()
                    .into_table(KerberosRealm::Table)
                    .columns([
                        KerberosRealm::Id,
                        KerberosRealm::Realm,
                        KerberosRealm::Generation,
                        KerberosRealm::Open,
                        KerberosRealm::State,
                    ])
                    .values_panic([
                        Expr::value(1i32),
                        Expr::value("EXAMPLE.COM"),
                        Expr::value(generation),
                        Expr::value(open),
                        Expr::value(bytes_value(vec![1])),
                    ]),
            ),
        )
        .await
        .unwrap();
    }

    struct TwoConnections {
        a: DbConnection,
        b: DbConnection,
        path: std::path::PathBuf,
    }

    impl Drop for TwoConnections {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    async fn two_connections() -> TwoConnections {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("klldap-sql-b3-{}-{n}.db", std::process::id()));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let open = |url: String| async move {
            let mut opts = sea_orm::ConnectOptions::new(url);
            opts.max_connections(1).sqlx_logging(false);
            Database::connect(opts).await.unwrap()
        };
        let a = open(url.clone()).await;
        init_table(&a).await.unwrap();
        let b = open(url).await;
        TwoConnections { a, b, path }
    }

    async fn commit_take(pool: &DbConnection, generation: i64) -> Result<i64, KerberosSqlError> {
        let txn = pool.begin().await.map_err(failed)?;
        match take_realm(&txn, generation).await {
            Ok(next) => {
                txn.commit().await.map_err(failed)?;
                Ok(next)
            }
            Err(err) => {
                txn.rollback().await.map_err(failed)?;
                Err(err)
            }
        }
    }

    async fn commit_heartbeat(
        pool: &DbConnection,
        generation: i64,
    ) -> Result<i64, KerberosSqlError> {
        let txn = pool.begin().await.map_err(failed)?;
        match heartbeat(&txn, generation).await {
            Ok(next) => {
                txn.commit().await.map_err(failed)?;
                Ok(next)
            }
            Err(err) => {
                txn.rollback().await.map_err(failed)?;
                Err(err)
            }
        }
    }

    pub(crate) async fn scenario_take_one_wins(pool: &DbConnection) {
        init_table(pool).await.unwrap();
        insert_realm(pool, 5, false).await;
        let winner = pool.begin().await.unwrap();
        assert_eq!(take_realm(&winner, 5).await.unwrap(), 6);
        let loser = tokio::spawn({
            let pool = pool.clone();
            async move {
                let txn = pool.begin().await.unwrap();
                let result = take_realm(&txn, 5).await;
                txn.rollback().await.unwrap();
                result
            }
        });
        winner.commit().await.unwrap();
        let err = loser.await.unwrap().unwrap_err();
        assert!(matches!(
            err,
            KerberosSqlError::GenerationMoved { expected: 5 }
        ));
        let hold = read_hold(pool).await.unwrap().unwrap();
        assert_eq!(hold.generation, 6);
        assert!(hold.open);
    }

    #[tokio::test]
    async fn test_one_take_wins() {
        let db = two_connections().await;
        insert_realm(&db.a, 5, false).await;
        assert_eq!(commit_take(&db.a, 5).await.unwrap(), 6);
        let err = commit_take(&db.b, 5).await.unwrap_err();
        assert!(matches!(
            err,
            KerberosSqlError::GenerationMoved { expected: 5 }
        ));
        let hold = read_hold(&db.a).await.unwrap().unwrap();
        assert_eq!(hold.generation, 6);
        assert!(hold.open);
    }

    #[tokio::test]
    async fn test_closed_realm_is_taken_at_once() {
        let pool = memory().await;
        init_table(&pool).await.unwrap();
        insert_realm(&pool, 5, false).await;
        assert_eq!(commit_take(&pool, 5).await.unwrap(), 6);
        let hold = read_hold(&pool).await.unwrap().unwrap();
        assert!(hold.open);
        assert_eq!(hold.generation, 6);
    }

    #[tokio::test]
    async fn test_heartbeat_is_seen() {
        let db = two_connections().await;
        insert_realm(&db.a, 5, true).await;
        assert_eq!(commit_heartbeat(&db.b, 5).await.unwrap(), 6);
        let hold = read_hold(&db.a).await.unwrap().unwrap();
        assert_eq!(hold.generation, 6);
    }

    #[tokio::test]
    async fn test_dead_owner_is_taken() {
        let pool = memory().await;
        init_table(&pool).await.unwrap();
        insert_realm(&pool, 5, true).await;
        assert_eq!(commit_take(&pool, 5).await.unwrap(), 6);
        let hold = read_hold(&pool).await.unwrap().unwrap();
        assert_eq!(hold.generation, 6);
        assert!(hold.open);
    }

    #[tokio::test]
    async fn test_live_owner_blocks_take() {
        let db = two_connections().await;
        insert_realm(&db.a, 5, true).await;
        assert_eq!(commit_heartbeat(&db.b, 5).await.unwrap(), 6);
        let err = commit_take(&db.a, 5).await.unwrap_err();
        assert!(matches!(
            err,
            KerberosSqlError::GenerationMoved { expected: 5 }
        ));
        assert_eq!(read_hold(&db.a).await.unwrap().unwrap().generation, 6);
    }

    #[tokio::test]
    async fn test_replaced_heartbeat() {
        let db = two_connections().await;
        insert_realm(&db.a, 5, true).await;
        assert_eq!(commit_heartbeat(&db.a, 5).await.unwrap(), 6);
        let err = commit_heartbeat(&db.b, 5).await.unwrap_err();
        assert!(matches!(
            err,
            KerberosSqlError::GenerationMoved { expected: 5 }
        ));
    }

    #[tokio::test]
    async fn test_replaced_clear_leaves_open() {
        let db = two_connections().await;
        insert_realm(&db.a, 5, true).await;
        assert_eq!(commit_heartbeat(&db.a, 5).await.unwrap(), 6);
        let txn = db.b.begin().await.unwrap();
        let err = clear_open(&txn, 5).await.unwrap_err();
        txn.rollback().await.unwrap();
        assert!(matches!(
            err,
            KerberosSqlError::GenerationMoved { expected: 5 }
        ));
        let hold = read_hold(&db.a).await.unwrap().unwrap();
        assert!(hold.open);
        assert_eq!(hold.generation, 6);
    }
}
