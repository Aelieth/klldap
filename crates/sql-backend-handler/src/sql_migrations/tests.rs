use super::*;
use crate::sql_backend_handler::SqlBackendHandler;
use crate::sql_tables::{LAST_SCHEMA_VERSION, SchemaVersion, init_table};
use chrono::prelude::*;
use lldap_auth::opaque::server::generate_random_private_key;
use lldap_domain::requests::UpdateUserRequest;
use lldap_domain::types::{Attribute, AttributeValue, Cardinality, Serialized, UserId};
use lldap_domain_handlers::handler::{
    GroupListerBackendHandler, UserBackendHandler, UserListerBackendHandler,
};
use pretty_assertions::assert_eq;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, FromQueryResult};

fn raw_statement(sql: &str) -> sea_orm::Statement {
    sea_orm::Statement::from_string(DbBackend::Sqlite, sql.to_owned())
}

async fn get_in_memory_db() -> DbConnection {
    let mut sql_opt = sea_orm::ConnectOptions::new("sqlite::memory:".to_owned());
    sql_opt.max_connections(1).sqlx_logging(false);
    Database::connect(sql_opt).await.unwrap()
}

async fn populate_rich_data_for_version(
    pool: &DbConnection,
    up_to_version: SchemaVersion,
) -> anyhow::Result<()> {
    let builder = pool.get_database_backend();
    let now = Utc::now().naive_utc();

    // Rows are inserted directly: the handler cannot speak every historical schema shape.
    if up_to_version.0 < 5 {
        // Parameterized so the v5 migration and later asserts see the exact test JPEG bytes.
        pool.execute(sea_orm::Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"INSERT INTO users (user_id, email, display_name, first_name, last_name, avatar, creation_date, uuid)
               VALUES ("bob", "bob@bob.com", "Bob Display", "first bob", "last bob", $1, "1970-01-01 00:00:00", "a02eaf13-48a7-30f6-a3d4-040ff7c52b04")"#,
            [lldap_domain::images::make_test_jpeg_bytes().into()],
        ))
        .await?;

        pool.execute(raw_statement(
            r#"INSERT INTO users (user_id, email, display_name, first_name, last_name, creation_date, uuid)
               VALUES ("pat", "pat@pat.com", "Patrícia", "first pat", NULL, "1971-01-01 00:00:00", "986765a5-3f03-389e-b47b-536b2d6e1bec")"#,
        ))
        .await?;

        pool.execute(raw_statement(
            r#"INSERT INTO users (user_id, email, display_name, creation_date, uuid)
               VALUES ("unicode-ü", "u@u.com", "Üsér", "1972-01-01 00:00:00", "11111111-1111-1111-1111-111111111111")"#,
        ))
        .await?;

        pool.execute(raw_statement(
            r#"INSERT INTO groups (display_name, creation_date, uuid)
               VALUES ("lldap_admin", "1970-01-01 00:00:00", "g1")"#,
        ))
        .await?;
        pool.execute(raw_statement(
            r#"INSERT INTO groups (display_name, creation_date, uuid)
               VALUES ("lldap_password_manager", "1970-01-01 00:00:00", "g2")"#,
        ))
        .await?;
        pool.execute(raw_statement(
            r#"INSERT INTO groups (display_name, creation_date, uuid)
               VALUES ("testgroup", "1970-01-01 00:00:00", "g3")"#,
        ))
        .await?;
    } else {
        // Legacy attribute names, so the rename paths get exercised.
        let legacy_first = if up_to_version.0 < 12 {
            "first_name"
        } else {
            "firstname"
        };
        let legacy_last = if up_to_version.0 < 12 {
            "last_name"
        } else {
            "lastname"
        };
        let legacy_avatar = "avatar"; // always canonicalized early

        let _ = pool
            .execute(
                builder.build(
                    Query::insert()
                        .into_table(UserAttributeSchema::Table)
                        .columns([
                            UserAttributeSchema::UserAttributeSchemaName,
                            UserAttributeSchema::UserAttributeSchemaType,
                            UserAttributeSchema::UserAttributeSchemaIsList,
                            UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                            UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                            UserAttributeSchema::UserAttributeSchemaIsHardcoded,
                        ])
                        .values_panic([
                            legacy_first.into(),
                            AttributeType::String.into(),
                            false.into(),
                            true.into(),
                            true.into(),
                            true.into(),
                        ])
                        .values_panic([
                            legacy_last.into(),
                            AttributeType::String.into(),
                            false.into(),
                            true.into(),
                            true.into(),
                            true.into(),
                        ])
                        .values_panic([
                            legacy_avatar.into(),
                            AttributeType::Avatar.into(),
                            false.into(),
                            true.into(),
                            true.into(),
                            true.into(),
                        ]),
                ),
            )
            .await;

        pool.execute(raw_statement(
            r#"INSERT INTO users (user_id, email, lowercase_email, display_name, creation_date, uuid, modified_date, password_modified_date)
               VALUES ("bob", "bob@bob.com", "bob@bob.com", "Bob Display", "1970-01-01 00:00:00", "a02eaf13-48a7-30f6-a3d4-040ff7c52b04", "1970-01-01 00:00:00", "1970-01-01 00:00:00")"#,
        )).await?;
        pool.execute(raw_statement(
            r#"INSERT INTO users (user_id, email, lowercase_email, display_name, creation_date, uuid, modified_date, password_modified_date)
               VALUES ("pat", "pat@pat.com", "pat@pat.com", "Patrícia", "1971-01-01 00:00:00", "986765a5-3f03-389e-b47b-536b2d6e1bec", "1971-01-01 00:00:00", "1971-01-01 00:00:00")"#,
        )).await?;
        pool.execute(raw_statement(
            r#"INSERT INTO users (user_id, email, lowercase_email, display_name, creation_date, uuid, modified_date, password_modified_date)
               VALUES ("unicode-ü", "u@u.com", "u@u.com", "Üsér", "1972-01-01 00:00:00", "11111111-1111-1111-1111-111111111111", "1972-01-01 00:00:00", "1972-01-01 00:00:00")"#,
        )).await?;
        pool.execute(raw_statement(
            r#"INSERT INTO users (user_id, email, lowercase_email, display_name, creation_date, uuid, modified_date, password_modified_date)
               VALUES ("emptyattrs", "e@e.com", "e@e.com", NULL, "1973-01-01 00:00:00", "22222222-2222-2222-2222-222222222222", "1973-01-01 00:00:00", "1973-01-01 00:00:00")"#,
        )).await?;

        pool.execute(raw_statement(
            r#"INSERT INTO groups (group_id, display_name, lowercase_display_name, creation_date, uuid, modified_date)
               VALUES (1, "lldap_admin", "lldap_admin", "1970-01-01 00:00:00", "g1", "1970-01-01 00:00:00")"#,
        ))
        .await?;
        pool.execute(raw_statement(
            r#"INSERT INTO groups (group_id, display_name, lowercase_display_name, creation_date, uuid, modified_date)
               VALUES (2, "lldap_password_manager", "lldap_password_manager", "1970-01-01 00:00:00", "g2", "1970-01-01 00:00:00")"#,
        ))
        .await?;
        pool.execute(raw_statement(
            r#"INSERT INTO groups (group_id, display_name, lowercase_display_name, creation_date, uuid, modified_date)
               VALUES (3, "testgroup", "testgroup", "1970-01-01 00:00:00", "g3", "1970-01-01 00:00:00")"#,
        ))
        .await?;

        // Memberships, with a duplicate pair for the v8 cleanup path.
        pool.execute(raw_statement(
            r#"INSERT INTO memberships (user_id, group_id) VALUES ("bob", 1), ("bob", 3), ("pat", 1), ("pat", 2), ("unicode-ü", 3)"#,
        ))
        .await?;
        if up_to_version.0 < 8 {
            pool.execute(raw_statement(
                r#"INSERT INTO memberships (user_id, group_id) VALUES ("bob", 1)"#,
            ))
            .await?;
        }

        // Legacy first_name/last_name rows for the v5 move and the v12 rename.
        let bob_first_val = Serialized(b"first bob".to_vec());
        let bob_last_val = Serialized(b"last bob".to_vec());
        pool.execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic(["bob".into(), legacy_first.into(), bob_first_val.into()])
                    .values_panic(["bob".into(), legacy_last.into(), bob_last_val.into()]),
            ),
        )
        .await?;

        let jpeg = lldap_domain::images::make_test_jpeg_bytes();
        pool.execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic([
                        "bob".into(),
                        legacy_avatar.into(),
                        Serialized(jpeg.clone()).into(),
                    ]),
            ),
        )
        .await?;

        // Lists are stored as JSON.
        let ssh_list: Vec<String> = vec![
            "ssh-rsa AAAAB3... bob@laptop".into(),
            "ssh-ed25519 AAAAC3... bob@phone".into(),
        ];
        let ssh_json = serde_json::to_vec(&ssh_list).unwrap();
        pool.execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic([
                        "bob".into(),
                        "sshpublickey".into(),
                        Serialized(ssh_json).into(),
                    ]),
            ),
        )
        .await?;

        let tags: Vec<String> = vec!["admin".into(), "dev".into()];
        let tags_json = serde_json::to_vec(&tags).unwrap();
        let _ = pool
            .execute(
                builder.build(
                    Query::insert()
                        .into_table(UserAttributeSchema::Table)
                        .columns([
                            UserAttributeSchema::UserAttributeSchemaName,
                            UserAttributeSchema::UserAttributeSchemaType,
                            UserAttributeSchema::UserAttributeSchemaIsList,
                            UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                            UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                            UserAttributeSchema::UserAttributeSchemaIsHardcoded,
                        ])
                        .values_panic([
                            "tags".into(),
                            AttributeType::String.into(),
                            true.into(),
                            true.into(),
                            true.into(),
                            false.into(),
                        ]),
                ),
            )
            .await;
        pool.execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic(["bob".into(), "tags".into(), Serialized(tags_json).into()]),
            ),
        )
        .await?;

        let _ = pool
            .execute(
                builder.build(
                    Query::insert()
                        .into_table(UserAttributeSchema::Table)
                        .columns([
                            UserAttributeSchema::UserAttributeSchemaName,
                            UserAttributeSchema::UserAttributeSchemaType,
                            UserAttributeSchema::UserAttributeSchemaIsList,
                            UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                            UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                            UserAttributeSchema::UserAttributeSchemaIsHardcoded,
                        ])
                        .values_panic([
                            "score".into(),
                            AttributeType::Integer.into(),
                            false.into(),
                            true.into(),
                            true.into(),
                            false.into(),
                        ]),
                ),
            )
            .await;
        pool.execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic([
                        "pat".into(),
                        "uidnumber".into(),
                        Serialized(b"10042".to_vec()).into(),
                    ])
                    .values_panic([
                        "pat".into(),
                        "score".into(),
                        Serialized(b"42".to_vec()).into(),
                    ]),
            ),
        )
        .await?;

        let _ = pool
            .execute(
                builder.build(
                    Query::insert()
                        .into_table(UserAttributeSchema::Table)
                        .columns([
                            UserAttributeSchema::UserAttributeSchemaName,
                            UserAttributeSchema::UserAttributeSchemaType,
                            UserAttributeSchema::UserAttributeSchemaIsList,
                            UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                            UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                            UserAttributeSchema::UserAttributeSchemaIsHardcoded,
                        ])
                        .values_panic([
                            "lastlogin".into(),
                            AttributeType::DateTime.into(),
                            false.into(),
                            true.into(),
                            true.into(),
                            false.into(),
                        ]),
                ),
            )
            .await;
        let dt_bytes = Serialized(format!("{}", now.and_utc().timestamp()).into_bytes());
        pool.execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic(["unicode-ü".into(), "lastlogin".into(), dt_bytes.into()]),
            ),
        )
        .await?;

        let _ = pool
            .execute(
                builder.build(
                    Query::insert()
                        .into_table(UserAttributeSchema::Table)
                        .columns([
                            UserAttributeSchema::UserAttributeSchemaName,
                            UserAttributeSchema::UserAttributeSchemaType,
                            UserAttributeSchema::UserAttributeSchemaIsList,
                            UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                            UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                            UserAttributeSchema::UserAttributeSchemaIsHardcoded,
                        ])
                        .values_panic([
                            "profilepic".into(),
                            AttributeType::Avatar.into(),
                            false.into(),
                            true.into(),
                            true.into(),
                            false.into(),
                        ]),
                ),
            )
            .await;
        pool.execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic([
                        "pat".into(),
                        "profilepic".into(),
                        Serialized(jpeg.clone()).into(),
                    ]),
            ),
        )
        .await?;

        let _ = pool
            .execute(
                builder.build(
                    Query::insert()
                        .into_table(GroupAttributeSchema::Table)
                        .columns([
                            GroupAttributeSchema::GroupAttributeSchemaName,
                            GroupAttributeSchema::GroupAttributeSchemaType,
                            GroupAttributeSchema::GroupAttributeSchemaIsList,
                            GroupAttributeSchema::GroupAttributeSchemaIsGroupVisible,
                            GroupAttributeSchema::GroupAttributeSchemaIsGroupEditable,
                            GroupAttributeSchema::GroupAttributeSchemaIsHardcoded,
                        ])
                        .values_panic([
                            "gidnumber".into(),
                            AttributeType::Integer.into(),
                            false.into(),
                            true.into(),
                            false.into(),
                            true.into(),
                        ]),
                ),
            )
            .await;
        pool.execute(
            builder.build(
                Query::insert()
                    .into_table(GroupAttributes::Table)
                    .columns([
                        GroupAttributes::GroupAttributeGroupId,
                        GroupAttributes::GroupAttributeName,
                        GroupAttributes::GroupAttributeValue,
                    ])
                    .values_panic([
                        3i64.into(),
                        "gidnumber".into(),
                        Serialized(b"3001".to_vec()).into(),
                    ]),
            ),
        )
        .await?;

        if up_to_version.0 >= 9 {
            pool.execute(raw_statement(
                r#"INSERT INTO user_object_classes (lower_object_class, object_class)
                   VALUES ("inetorgperson", "inetOrgPerson"), ("posixaccount", "posixAccount")"#,
            ))
            .await?;
            pool.execute(raw_statement(
                r#"INSERT INTO group_object_classes (lower_object_class, object_class)
                   VALUES ("posixgroup", "posixGroup")"#,
            ))
            .await?;
        }

        // A pre-v12 database still holds alias-named rows; the v12 step must fold them.
        if up_to_version.0 < 12 {
            let _ = pool
                .execute(
                    builder.build(
                        Query::insert()
                            .into_table(UserAttributeSchema::Table)
                            .columns([
                                UserAttributeSchema::UserAttributeSchemaName,
                                UserAttributeSchema::UserAttributeSchemaType,
                                UserAttributeSchema::UserAttributeSchemaIsList,
                                UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                                UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                                UserAttributeSchema::UserAttributeSchemaIsHardcoded,
                            ])
                            .values_panic([
                                "jpegPhoto".into(),
                                AttributeType::Avatar.into(),
                                false.into(),
                                true.into(),
                                true.into(),
                                true.into(),
                            ]),
                    ),
                )
                .await;

            pool.execute(
                builder.build(
                    Query::insert()
                        .into_table(UserAttributes::Table)
                        .columns([
                            UserAttributes::UserAttributeUserId,
                            UserAttributes::UserAttributeName,
                            UserAttributes::UserAttributeValue,
                        ])
                        .values_panic([
                            "bob".into(),
                            "jpegPhoto".into(),
                            Serialized(jpeg.clone()).into(),
                        ]),
                ),
            )
            .await?;
        }

        add_full_eav_richness(pool).await?;
    }

    if up_to_version.0 < 5 {
        // Pre-v5 starts get their memberships here; v8 dedups them later.
        pool.execute(raw_statement(
            r#"INSERT INTO memberships (user_id, group_id) VALUES ("bob", 1), ("bob", 3), ("pat", 1), ("pat", 2), ("unicode-ü", 3)"#,
        ))
        .await?;
        if up_to_version.0 < 8 {
            pool.execute(raw_statement(
                r#"INSERT INTO memberships (user_id, group_id) VALUES ("bob", 1)"#,
            ))
            .await?;
        }
    }

    Ok(())
}

async fn add_full_eav_richness(pool: &DbConnection) -> anyhow::Result<()> {
    let builder = pool.get_database_backend();
    let now = Utc::now().naive_utc();
    let expected_jpeg = lldap_domain::images::make_test_jpeg_bytes();

    let _ = pool
        .execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributeSchema::Table)
                    .columns([
                        UserAttributeSchema::UserAttributeSchemaName,
                        UserAttributeSchema::UserAttributeSchemaType,
                        UserAttributeSchema::UserAttributeSchemaIsList,
                        UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                        UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                        UserAttributeSchema::UserAttributeSchemaIsHardcoded,
                    ])
                    .values_panic([
                        "sshpublickey".into(),
                        AttributeType::String.into(),
                        true.into(),
                        true.into(),
                        true.into(),
                        true.into(),
                    ])
                    .values_panic([
                        "uidnumber".into(),
                        AttributeType::Integer.into(),
                        false.into(),
                        true.into(),
                        false.into(),
                        true.into(),
                    ]),
            ),
        )
        .await;

    let _ = pool
        .execute(
            builder.build(
                Query::insert()
                    .into_table(GroupAttributeSchema::Table)
                    .columns([
                        GroupAttributeSchema::GroupAttributeSchemaName,
                        GroupAttributeSchema::GroupAttributeSchemaType,
                        GroupAttributeSchema::GroupAttributeSchemaIsList,
                        GroupAttributeSchema::GroupAttributeSchemaIsGroupVisible,
                        GroupAttributeSchema::GroupAttributeSchemaIsGroupEditable,
                        GroupAttributeSchema::GroupAttributeSchemaIsHardcoded,
                    ])
                    .values_panic([
                        "gidnumber".into(),
                        AttributeType::Integer.into(),
                        false.into(),
                        true.into(),
                        false.into(),
                        true.into(),
                    ]),
            ),
        )
        .await;

    for (name, typ, is_list) in [
        ("tags", AttributeType::String, true),
        ("score", AttributeType::Integer, false),
        ("lastlogin", AttributeType::DateTime, false),
        ("profilepic", AttributeType::Avatar, false),
    ] {
        let _ = pool
            .execute(
                builder.build(
                    Query::insert()
                        .into_table(UserAttributeSchema::Table)
                        .columns([
                            UserAttributeSchema::UserAttributeSchemaName,
                            UserAttributeSchema::UserAttributeSchemaType,
                            UserAttributeSchema::UserAttributeSchemaIsList,
                            UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                            UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                            UserAttributeSchema::UserAttributeSchemaIsHardcoded,
                        ])
                        .values_panic([
                            name.into(),
                            typ.into(),
                            is_list.into(),
                            true.into(),
                            true.into(),
                            false.into(),
                        ]),
                ),
            )
            .await;
    }

    let ssh_list: Vec<String> = vec![
        "ssh-rsa AAAAB3... bob@laptop".into(),
        "ssh-ed25519 AAAAC3... bob@phone".into(),
    ];
    let _ = pool
        .execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic([
                        "bob".into(),
                        "sshpublickey".into(),
                        Serialized(serde_json::to_vec(&ssh_list).unwrap()).into(),
                    ]),
            ),
        )
        .await;

    let tags_json = serde_json::to_vec(&vec!["admin".to_string(), "dev".to_string()]).unwrap();
    let _ = pool
        .execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic(["bob".into(), "tags".into(), Serialized(tags_json).into()]),
            ),
        )
        .await;

    let _ = pool
        .execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic([
                        "pat".into(),
                        "uidnumber".into(),
                        Serialized(b"10042".to_vec()).into(),
                    ])
                    .values_panic([
                        "pat".into(),
                        "score".into(),
                        Serialized(b"42".to_vec()).into(),
                    ]),
            ),
        )
        .await;

    let dt_bytes = Serialized(format!("{}", now.and_utc().timestamp()).into_bytes());
    let _ = pool
        .execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic(["unicode-ü".into(), "lastlogin".into(), dt_bytes.into()]),
            ),
        )
        .await;

    let _ = pool
        .execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic([
                        "pat".into(),
                        "profilepic".into(),
                        Serialized(expected_jpeg.clone()).into(),
                    ]),
            ),
        )
        .await;

    let _ = pool
        .execute(
            builder.build(
                Query::insert()
                    .into_table(GroupAttributes::Table)
                    .columns([
                        GroupAttributes::GroupAttributeGroupId,
                        GroupAttributes::GroupAttributeName,
                        GroupAttributes::GroupAttributeValue,
                    ])
                    .values_panic([
                        3i64.into(),
                        "gidnumber".into(),
                        Serialized(b"3001".to_vec()).into(),
                    ]),
            ),
        )
        .await;

    // A pre-v12 alias row for the v12 step to fold.
    let _ = pool
        .execute(
            builder.build(
                Query::insert()
                    .into_table(UserAttributes::Table)
                    .columns([
                        UserAttributes::UserAttributeUserId,
                        UserAttributes::UserAttributeName,
                        UserAttributes::UserAttributeValue,
                    ])
                    .values_panic([
                        "bob".into(),
                        "jpegPhoto".into(),
                        Serialized(expected_jpeg).into(),
                    ]),
            ),
        )
        .await;

    let _ = pool
        .execute(raw_statement(
            r#"INSERT OR IGNORE INTO user_object_classes (lower_object_class, object_class)
               VALUES ("inetorgperson", "inetOrgPerson"), ("posixaccount", "posixAccount")"#,
        ))
        .await;
    let _ = pool
        .execute(raw_statement(
            r#"INSERT OR IGNORE INTO group_object_classes (lower_object_class, object_class)
               VALUES ("posixgroup", "posixGroup")"#,
        ))
        .await;

    Ok(())
}

async fn setup_legacy_rich_db(up_to_version: SchemaVersion) -> anyhow::Result<DatabaseConnection> {
    let pool = get_in_memory_db().await;

    upgrade_to_v1(&pool).await?;
    if up_to_version.0 > 1 {
        migrate_from_version(&pool, SchemaVersion(1), up_to_version).await?;
    }

    populate_rich_data_for_version(&pool, up_to_version).await?;

    Ok(pool)
}

#[derive(FromQueryResult)]
struct CountRow {
    c: i64,
}
#[derive(FromQueryResult)]
struct BytesRow {
    v: Vec<u8>,
}
#[derive(FromQueryResult)]
struct TextRow {
    t: String,
}

async fn count(pool: &DbConnection, sql: &str) -> i64 {
    CountRow::find_by_statement(raw_statement(sql))
        .one(pool)
        .await
        .unwrap()
        .unwrap()
        .c
}

async fn bytes(pool: &DbConnection, sql: &str) -> Vec<u8> {
    BytesRow::find_by_statement(raw_statement(sql))
        .one(pool)
        .await
        .unwrap()
        .unwrap()
        .v
}

async fn text(pool: &DbConnection, sql: &str) -> String {
    TextRow::find_by_statement(raw_statement(sql))
        .one(pool)
        .await
        .unwrap()
        .unwrap()
        .t
}

async fn insert_user_attr(pool: &DbConnection, user: &str, name: &str, value: &[u8]) {
    pool.execute(
        pool.get_database_backend().build(
            Query::insert()
                .into_table(UserAttributes::Table)
                .columns([
                    UserAttributes::UserAttributeUserId,
                    UserAttributes::UserAttributeName,
                    UserAttributes::UserAttributeValue,
                ])
                .values_panic([user.into(), name.into(), Serialized(value.to_vec()).into()]),
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_v12_via_version_gate_is_idempotent_and_repairs() {
    let pool = get_in_memory_db().await;
    upgrade_to_v1(&pool).await.unwrap();
    migrate_from_version(&pool, SchemaVersion(1), SchemaVersion(11))
        .await
        .unwrap();

    // v11 state: v5 already seeded the first_name/last_name/avatar schema ghosts.
    pool.execute(raw_statement(
        r#"INSERT INTO users (user_id, email, lowercase_email, creation_date, uuid, modified_date, password_modified_date)
           VALUES ("bob", "bob@ex.com", "bob@ex.com", "1970-01-01 00:00:00", "a02eaf13-48a7-30f6-a3d4-040ff7c52b04", "1970-01-01 00:00:00", "1970-01-01 00:00:00")"#,
    ))
    .await
    .unwrap();
    pool.execute(raw_statement(
        r#"INSERT INTO groups (group_id, display_name, lowercase_display_name, creation_date, uuid, modified_date)
           VALUES (7, "devs", "devs", "1970-01-01 00:00:00", "33333333-3333-3333-3333-333333333333", "1970-01-01 00:00:00")"#,
    ))
    .await
    .unwrap();
    // A real v11 schema only knows the alias spellings, so the canonical twin and the
    // kerberossync row are inserted with FK checks off; they model rows a partially
    // upgraded DB could hold, exercising the duplicate guard and the normalization.
    pool.execute(raw_statement("PRAGMA foreign_keys = OFF"))
        .await
        .unwrap();
    insert_user_attr(&pool, "bob", "firstname", b"Bob").await;
    insert_user_attr(&pool, "bob", "first_name", b"ALIAS").await;
    insert_user_attr(&pool, "bob", "kerberossync", b"true").await;
    pool.execute(raw_statement("PRAGMA foreign_keys = ON"))
        .await
        .unwrap();
    // Pre-existing config row must survive the seed untouched.
    pool.execute(raw_statement(
        r#"CREATE TABLE system_config ("key" varchar NOT NULL PRIMARY KEY, "value" text NOT NULL)"#,
    ))
    .await
    .unwrap();
    pool.execute(raw_statement(
        r#"INSERT INTO system_config ("key", "value") VALUES ('allowedous', '["custom"]')"#,
    ))
    .await
    .unwrap();
    // Custom attr whose name collides with a hardcoded alias must survive ghost cleanup.
    pool.execute(raw_statement(
        r#"INSERT INTO user_attribute_schema
           (user_attribute_schema_name, user_attribute_schema_type,
            user_attribute_schema_is_list, user_attribute_schema_is_user_visible,
            user_attribute_schema_is_user_editable, user_attribute_schema_is_hardcoded)
           VALUES ("email", "String", false, true, true, false)"#,
    ))
    .await
    .unwrap();

    migrate_from_version(&pool, SchemaVersion(11), SchemaVersion(12))
        .await
        .unwrap();

    let assert_v12_state = |pool: DbConnection, expected_version: SchemaVersion| async move {
        let ver =
            JustSchemaVersion::find_by_statement(raw_statement(r#"SELECT version FROM metadata"#))
                .one(&pool)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(ver.version, expected_version);

        count(
            &pool,
            r#"SELECT COUNT(aliases) as c FROM user_attribute_schema"#,
        )
        .await;
        count(
            &pool,
            r#"SELECT COUNT(user_attribute_schema_is_readonly) as c FROM user_attribute_schema"#,
        )
        .await;
        count(&pool, r#"SELECT COUNT(krb_principal_name) as c FROM users"#).await;

        assert_eq!(
            text(
                &pool,
                r#"SELECT user_attribute_schema_type as t FROM user_attribute_schema
                   WHERE user_attribute_schema_name = "avatar""#
            )
            .await,
            "Avatar"
        );
        let avatar_aliases = text(
            &pool,
            r#"SELECT aliases as t FROM user_attribute_schema
               WHERE user_attribute_schema_name = "avatar""#,
        )
        .await;
        assert_ne!(avatar_aliases, "[]");

        assert_eq!(
            count(
                &pool,
                r#"SELECT COUNT(*) as c FROM user_attribute_schema
                   WHERE user_attribute_schema_name IN ("first_name", "last_name")"#
            )
            .await,
            0
        );

        // Alias data folded: exactly one canonical row, the canonical value won.
        assert_eq!(
            count(
                &pool,
                r#"SELECT COUNT(*) as c FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "firstname""#
            )
            .await,
            1
        );
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT user_attribute_value as v FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "firstname""#
            )
            .await,
            b"Bob"
        );
        assert_eq!(
            count(
                &pool,
                r#"SELECT COUNT(*) as c FROM user_attributes
                   WHERE user_attribute_name = "first_name""#
            )
            .await,
            0
        );

        // Defaults are byte-bound blobs; kerberossync "true" canonicalized to "1".
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT user_attribute_value as v FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "ou""#
            )
            .await,
            b"people"
        );
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT group_attribute_value as v FROM group_attributes
                   WHERE group_attribute_group_id = 7 AND group_attribute_name = "ou""#
            )
            .await,
            b"groups"
        );
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT user_attribute_value as v FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "kerberossync""#
            )
            .await,
            b"1"
        );
        assert_eq!(
            PublicSchema::get()
                .user_attributes()
                .get_by_name_or_alias("kerberossync")
                .unwrap()
                .attribute_type,
            AttributeType::Integer,
            "the canonical bytes are the integer the schema declares"
        );

        assert_eq!(
            text(
                &pool,
                r#"SELECT "value" as t FROM system_config WHERE "key" = "allowedous""#
            )
            .await,
            r#"["custom"]"#
        );
        assert_eq!(
            count(
                &pool,
                r#"SELECT COUNT(*) as c FROM user_attribute_schema
                   WHERE user_attribute_schema_name = "email"
                     AND user_attribute_schema_is_hardcoded = 0"#
            )
            .await,
            1
        );
        pool
    };

    let pool = assert_v12_state(pool, SchemaVersion(12)).await;

    // Idempotency runs through the version gate: re-init carries the DB to LAST
    // without re-running the v12 body (plain add_column would fail); the v12 state
    // must survive v13's detector untouched.
    init_table(&pool).await.unwrap();
    assert_v12_state(pool, LAST_SCHEMA_VERSION).await;
}

async fn insert_group_attr(pool: &DbConnection, group_id: i32, name: &str, value: &[u8]) {
    pool.execute(
        pool.get_database_backend().build(
            Query::insert()
                .into_table(GroupAttributes::Table)
                .columns([
                    GroupAttributes::GroupAttributeGroupId,
                    GroupAttributes::GroupAttributeName,
                    GroupAttributes::GroupAttributeValue,
                ])
                .values_panic([
                    group_id.into(),
                    name.into(),
                    Serialized(value.to_vec()).into(),
                ]),
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_v13_reencodes_lldap_bincode_values() {
    use lldap_domain::types::{AttributeValue, Cardinality};
    use lldap_domain_model::model::codec;

    let pool = get_in_memory_db().await;
    upgrade_to_v1(&pool).await.unwrap();
    migrate_from_version(&pool, SchemaVersion(1), SchemaVersion(11))
        .await
        .unwrap();

    pool.execute(raw_statement(
        r#"INSERT INTO users (user_id, email, lowercase_email, creation_date, uuid, modified_date, password_modified_date)
           VALUES ("bob", "bob@ex.com", "bob@ex.com", "1970-01-01 00:00:00", "a02eaf13-48a7-30f6-a3d4-040ff7c52b04", "1970-01-01 00:00:00", "1970-01-01 00:00:00")"#,
    ))
    .await
    .unwrap();
    pool.execute(raw_statement(
        r#"INSERT INTO groups (group_id, display_name, lowercase_display_name, creation_date, uuid, modified_date)
           VALUES (7, "devs", "devs", "1970-01-01 00:00:00", "33333333-3333-3333-3333-333333333333", "1970-01-01 00:00:00")"#,
    ))
    .await
    .unwrap();
    // Custom schema rows in v11 shape; these are user-owned attributes and
    // stay after v13 (the migration never creates scratch schema).
    // Upstream stores JpegPhoto as its own type.
    for (name, typ, is_list) in [
        ("mylist", "String", 1),
        ("myints", "Integer", 1),
        ("myint", "Integer", 0),
        ("mydate", "DateTime", 0),
        ("mydates", "DateTime", 1),
        ("baddates", "DateTime", 1),
        ("myphoto", "JpegPhoto", 0),
        ("myphotos", "JpegPhoto", 1),
        ("rawstr", "String", 0),
    ] {
        pool.execute(raw_statement(&format!(
            r#"INSERT INTO user_attribute_schema
               (user_attribute_schema_name, user_attribute_schema_type,
                user_attribute_schema_is_list, user_attribute_schema_is_user_visible,
                user_attribute_schema_is_user_editable, user_attribute_schema_is_hardcoded)
               VALUES ("{name}", "{typ}", {is_list}, true, true, false)"#,
        )))
        .await
        .unwrap();
    }
    pool.execute(raw_statement(
        r#"INSERT INTO group_attribute_schema
           (group_attribute_schema_name, group_attribute_schema_type,
            group_attribute_schema_is_list, group_attribute_schema_is_group_visible,
            group_attribute_schema_is_group_editable, group_attribute_schema_is_hardcoded)
           VALUES ("gnote", "String", false, true, true, false)"#,
    ))
    .await
    .unwrap();

    let jpeg = lldap_domain::images::make_test_jpeg_bytes();
    insert_user_attr(
        &pool,
        "bob",
        "first_name",
        &bincode::serialize("Bincode Bob").unwrap(),
    )
    .await;
    insert_user_attr(
        &pool,
        "bob",
        "mylist",
        &bincode::serialize(&vec!["a".to_string(), "b".to_string()]).unwrap(),
    )
    .await;
    insert_user_attr(
        &pool,
        "bob",
        "myints",
        &bincode::serialize(&vec![1i64, 2]).unwrap(),
    )
    .await;
    insert_user_attr(
        &pool,
        "bob",
        "myint",
        &bincode::serialize(&4242i64).unwrap(),
    )
    .await;
    insert_user_attr(
        &pool,
        "bob",
        "mydate",
        &bincode::serialize("2024-05-01T12:00:00").unwrap(),
    )
    .await;
    insert_user_attr(
        &pool,
        "bob",
        "mydates",
        &bincode::serialize(&vec![
            "2024-05-01T12:00:00".to_string(),
            "2024-05-02T12:00:00".to_string(),
        ])
        .unwrap(),
    )
    .await;
    let baddates = bincode::serialize(&vec![
        "2024-05-01T12:00:00".to_string(),
        "not-a-date".to_string(),
    ])
    .unwrap();
    insert_user_attr(&pool, "bob", "baddates", &baddates).await;
    insert_user_attr(&pool, "bob", "myphoto", &bincode::serialize(&jpeg).unwrap()).await;
    insert_user_attr(
        &pool,
        "bob",
        "myphotos",
        &bincode::serialize(&vec![jpeg.clone()]).unwrap(),
    )
    .await;
    insert_user_attr(&pool, "bob", "rawstr", b"native").await;
    insert_group_attr(
        &pool,
        7,
        "gnote",
        &bincode::serialize("Group note").unwrap(),
    )
    .await;

    migrate_from_version(&pool, SchemaVersion(11), SchemaVersion(13))
        .await
        .unwrap();

    let assert_v13_state = |pool: DbConnection, jpeg: Vec<u8>, baddates: Vec<u8>| async move {
        let ver =
            JustSchemaVersion::find_by_statement(raw_statement(r#"SELECT version FROM metadata"#))
                .one(&pool)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(ver.version, SchemaVersion(13));

        assert_eq!(
            bytes(
                &pool,
                r#"SELECT user_attribute_value as v FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "firstname""#
            )
            .await,
            b"Bincode Bob"
        );
        assert_eq!(
            count(
                &pool,
                r#"SELECT COUNT(*) as c FROM user_attributes
                   WHERE user_attribute_name = "first_name""#
            )
            .await,
            0
        );
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT user_attribute_value as v FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "mylist""#
            )
            .await,
            br#"["a","b"]"#
        );
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT user_attribute_value as v FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "myints""#
            )
            .await,
            b"[1,2]"
        );
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT user_attribute_value as v FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "myint""#
            )
            .await,
            b"4242"
        );
        let mydate = bytes(
            &pool,
            r#"SELECT user_attribute_value as v FROM user_attributes
               WHERE user_attribute_user_id = "bob" AND user_attribute_name = "mydate""#,
        )
        .await;
        assert_eq!(mydate, b"1714564800");
        assert_eq!(
            codec::decode_attribute_value(&Serialized(mydate), AttributeType::DateTime, false),
            AttributeValue::DateTime(Cardinality::Singleton(
                "2024-05-01T12:00:00".parse().unwrap()
            ))
        );
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT user_attribute_value as v FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "mydates""#
            )
            .await,
            b"[1714564800,1714651200]"
        );
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT user_attribute_value as v FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "baddates""#
            )
            .await,
            baddates
        );
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT user_attribute_value as v FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "myphoto""#
            )
            .await,
            jpeg
        );
        let myphotos = bytes(
            &pool,
            r#"SELECT user_attribute_value as v FROM user_attributes
               WHERE user_attribute_user_id = "bob" AND user_attribute_name = "myphotos""#,
        )
        .await;
        assert_eq!(
            myphotos,
            serde_json::to_vec(&[general_purpose::STANDARD.encode(&jpeg)]).unwrap()
        );
        assert_eq!(
            text(
                &pool,
                r#"SELECT user_attribute_schema_type as t FROM user_attribute_schema
                   WHERE user_attribute_schema_name = "myphoto""#
            )
            .await,
            "Avatar"
        );
        assert_eq!(
            text(
                &pool,
                r#"SELECT user_attribute_schema_type as t FROM user_attribute_schema
                   WHERE user_attribute_schema_name = "myphotos""#
            )
            .await,
            "Avatar"
        );
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT user_attribute_value as v FROM user_attributes
                   WHERE user_attribute_user_id = "bob" AND user_attribute_name = "rawstr""#
            )
            .await,
            b"native"
        );
        assert_eq!(
            bytes(
                &pool,
                r#"SELECT group_attribute_value as v FROM group_attributes
                   WHERE group_attribute_group_id = 7 AND group_attribute_name = "gnote""#
            )
            .await,
            b"Group note"
        );
        pool
    };

    let pool = assert_v13_state(pool, jpeg.clone(), baddates.clone()).await;

    // Idempotent: a second init at LAST leaves every re-encoded byte untouched.
    init_table(&pool).await.unwrap();
    assert_v13_state(pool, jpeg, baddates).await;
}

async fn assert_full_rich_data_integrity(pool: &DbConnection, at_version: SchemaVersion) {
    let ver =
        JustSchemaVersion::find_by_statement(raw_statement(r#"SELECT version FROM metadata"#))
            .one(pool)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(ver.version, at_version, "schema version mismatch");

    #[derive(FromQueryResult, Debug)]
    struct CountRow {
        c: i64,
    }
    let user_count: CountRow =
        CountRow::find_by_statement(raw_statement(r#"SELECT COUNT(*) as c FROM users"#))
            .one(pool)
            .await
            .unwrap()
            .unwrap();
    assert!(
        user_count.c >= 3,
        "expected at least 3 users, got {}",
        user_count.c
    );

    let group_count: CountRow =
        CountRow::find_by_statement(raw_statement(r#"SELECT COUNT(*) as c FROM groups"#))
            .one(pool)
            .await
            .unwrap()
            .unwrap();
    assert!(group_count.c >= 3, "expected at least 3 groups");

    #[derive(FromQueryResult, PartialEq, Eq, Debug)]
    struct AttrRow {
        user_attribute_user_id: String,
        user_attribute_name: String,
        user_attribute_value: Vec<u8>,
    }

    if at_version.0 >= 5 {
        let attr_count: CountRow = CountRow::find_by_statement(raw_statement(
            r#"SELECT COUNT(*) as c FROM user_attributes"#,
        ))
        .one(pool)
        .await
        .unwrap()
        .unwrap();
        assert!(
            attr_count.c >= 3,
            "expected several user_attributes after v5, got {}",
            attr_count.c
        );

        let attrs: Vec<AttrRow> = AttrRow::find_by_statement(raw_statement(
            r#"SELECT user_attribute_user_id, user_attribute_name, user_attribute_value
               FROM user_attributes
               WHERE user_attribute_user_id IN ('bob', 'pat')
               ORDER BY user_attribute_user_id, user_attribute_name"#,
        ))
        .all(pool)
        .await
        .unwrap();

        let expected_jpeg = lldap_domain::images::make_test_jpeg_bytes();
        assert!(
            attrs
                .iter()
                .any(|a| a.user_attribute_name == "avatar"
                    && a.user_attribute_value == expected_jpeg),
            "avatar bytes (make_test_jpeg_bytes) must be present under canonical name after v5"
        );

        // The legacy "first_name" row survives only until the v12 normalization.
        let has_legacy_first = attrs.iter().any(|a| a.user_attribute_name == "first_name");
        if at_version.0 < 12 {
        } else {
            assert!(
                !has_legacy_first,
                "after v12, legacy 'first_name' alias rows must have been migrated/deleted"
            );
            assert!(
                attrs.iter().any(|a| a.user_attribute_name == "firstname"
                    && a.user_attribute_value == b"first bob"),
                "firstname (canonical) + original bytes must be present post v12 normalization"
            );
        }

        assert!(
            attrs.iter().any(|a| a.user_attribute_name == "sshpublickey"
                && a.user_attribute_value.starts_with(b"[")),
            "sshpublickey list should be stored as json bytes"
        );

        assert!(
            attrs.iter().any(|a| a.user_attribute_name == "tags"),
            "custom list attr 'tags' should be present"
        );

        let gattr_count: CountRow = CountRow::find_by_statement(raw_statement(
            r#"SELECT COUNT(*) as c FROM group_attributes"#,
        ))
        .one(pool)
        .await
        .unwrap()
        .unwrap();
        assert!(gattr_count.c >= 1, "expected group_attributes");

        if at_version.0 >= 9 {
            let uoc: CountRow = CountRow::find_by_statement(raw_statement(
                r#"SELECT COUNT(*) as c FROM user_object_classes"#,
            ))
            .one(pool)
            .await
            .unwrap()
            .unwrap();
            assert!(
                uoc.c >= 1,
                "user_object_classes should be populated for v9+"
            );
        }
    }

    if at_version.0 >= 6 {
        let _ = pool
            .query_one(raw_statement(
                r#"SELECT lowercase_email FROM users LIMIT 1"#,
            ))
            .await
            .expect("lowercase_email column must exist >=v6");
    }

    if at_version.0 >= 11 {
        let _ = pool
            .query_one(raw_statement(
                r#"SELECT modified_date, password_modified_date FROM users LIMIT 1"#,
            ))
            .await
            .expect("date columns must exist >=v11");
        let _ = pool
            .query_one(raw_statement(r#"SELECT modified_date FROM groups LIMIT 1"#))
            .await
            .expect("group modified_date >=v11");
    }

    if at_version.0 >= 12 {
        #[derive(FromQueryResult, Debug)]
        struct SysRow {
            _key: String,
            value: String,
        }
        let sys = SysRow::find_by_statement(raw_statement(
            r#"SELECT key as _key, value FROM system_config WHERE key='allowedous'"#,
        ))
        .one(pool)
        .await
        .unwrap()
        .expect("system_config allowedous row must exist after v12");
        assert!(sys.value.contains("people") && sys.value.contains("groups"));

        let kerb_attrs: Vec<AttrRow> = AttrRow::find_by_statement(raw_statement(
            r#"SELECT user_attribute_user_id, user_attribute_name, user_attribute_value
               FROM user_attributes WHERE user_attribute_name IN ('kerberossync','ou')"#,
        ))
        .all(pool)
        .await
        .unwrap();
        assert!(
            kerb_attrs
                .iter()
                .any(|a| a.user_attribute_name == "kerberossync" && a.user_attribute_value == b"0"),
            "kerberossync default '0' (bytes) must be injected by v12 for users"
        );
        assert!(
            kerb_attrs
                .iter()
                .any(|a| a.user_attribute_name == "ou" && a.user_attribute_value == b"people"),
            "ou='people' default must be injected by v12"
        );

        #[derive(FromQueryResult, PartialEq, Eq, Debug)]
        struct GroupAttrRow {
            group_attribute_group_id: i64,
            group_attribute_name: String,
            group_attribute_value: Vec<u8>,
        }
        let gou: Vec<GroupAttrRow> = GroupAttrRow::find_by_statement(raw_statement(
            r#"SELECT group_attribute_group_id, group_attribute_name, group_attribute_value
               FROM group_attributes WHERE group_attribute_name = 'ou'"#,
        ))
        .all(pool)
        .await
        .unwrap();
        assert!(
            gou.iter().any(|a| a.group_attribute_value == b"groups"),
            "ou='groups' default must exist for groups after v12"
        );

        // The authoritative cleanup: no alias names survive as attribute names.
        let alias_names_left: CountRow = CountRow::find_by_statement(raw_statement(
            r#"SELECT COUNT(*) as c FROM user_attributes
               WHERE user_attribute_name IN ('first_name','last_name','jpegPhoto','jpegphoto','email','givenName','sn')"#,
        ))
        .one(pool)
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            alias_names_left.c, 0,
            "v12 must have removed all alias-named attribute rows"
        );

        let schema_names: Vec<String> = {
            #[derive(FromQueryResult)]
            struct NameRow {
                name: String,
            }
            NameRow::find_by_statement(raw_statement(
                r#"SELECT user_attribute_schema_name as name FROM user_attribute_schema"#,
            ))
            .all(pool)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect()
        };
        assert!(
            schema_names.iter().any(|n| n == "firstname"),
            "PublicSchema seeding in v12 must have created firstname (among others)"
        );
        assert!(
            schema_names.iter().any(|n| n == "sshpublickey"),
            "sshpublickey (list attr) must be in schema after v12"
        );
    }

    if at_version.0 >= 13 {
        assert_eq!(
            count(pool, r#"SELECT COUNT(*) as c FROM logs"#).await,
            0,
            "logs must exist and be empty after v13"
        );
    }
}

const LOG_INDEXES: [&str; 5] = [
    "logs-timestamp",
    "logs-actor",
    "logs-kind",
    "logs-target",
    "logs-peer",
];

#[tokio::test]
async fn test_init_repairs_the_logs_table_and_its_indexes() {
    let pool = get_in_memory_db().await;
    init_table(&pool).await.unwrap();
    for name in LOG_INDEXES {
        pool.execute(raw_statement(&format!(r#"DROP INDEX "{name}""#)))
            .await
            .unwrap();
    }
    init_table(&pool).await.unwrap();
    #[derive(FromQueryResult)]
    struct NameRow {
        name: String,
    }
    let names: Vec<String> = NameRow::find_by_statement(raw_statement(
        r#"SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'logs'"#,
    ))
    .all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|r| r.name)
    .collect();
    for index in LOG_INDEXES {
        assert!(
            names.iter().any(|n| n == index),
            "{index} restored: {names:?}"
        );
    }

    pool.execute(raw_statement(
        r#"INSERT INTO logs (timestamp, kind, success, protocol)
           VALUES ('2026-01-01 00:00:00', 'server_start', 1, 'system')"#,
    ))
    .await
    .unwrap();
    init_table(&pool).await.unwrap();
    assert_eq!(
        count(&pool, r#"SELECT COUNT(*) as c FROM logs"#).await,
        1,
        "re-init keeps the logs table and its rows"
    );

    pool.execute(raw_statement(r#"DROP TABLE logs"#))
        .await
        .unwrap();
    init_table(&pool).await.unwrap();
    assert_eq!(
        count(&pool, r#"SELECT COUNT(*) as c FROM logs"#).await,
        0,
        "a missing logs table is recreated"
    );
}

#[tokio::test]
async fn test_init_repairs_the_policy_tables_and_indexes() {
    let pool = get_in_memory_db().await;
    init_table(&pool).await.unwrap();
    for name in ["unique-policy-lower-name", "ou-policies-policy-id"] {
        pool.execute(raw_statement(&format!(r#"DROP INDEX "{name}""#)))
            .await
            .unwrap();
    }
    init_table(&pool).await.unwrap();
    #[derive(FromQueryResult)]
    struct NameRow {
        name: String,
    }
    let names: Vec<String> = NameRow::find_by_statement(raw_statement(
        r#"SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name IN ('policies', 'ou_policies')"#,
    ))
    .all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|r| r.name)
    .collect();
    for index in ["unique-policy-lower-name", "ou-policies-policy-id"] {
        assert!(
            names.iter().any(|n| n == index),
            "{index} restored: {names:?}"
        );
    }

    pool.execute(raw_statement(
        r#"INSERT INTO policies (name, lowercase_name, description, items)
           VALUES ('Hours', 'hours', '', '{}')"#,
    ))
    .await
    .unwrap();
    init_table(&pool).await.unwrap();
    assert_eq!(
        count(&pool, r#"SELECT COUNT(*) as c FROM policies"#).await,
        1,
        "re-init keeps policy rows"
    );

    pool.execute(raw_statement(r#"DROP TABLE ou_policies"#))
        .await
        .unwrap();
    pool.execute(raw_statement(r#"DROP TABLE policies"#))
        .await
        .unwrap();
    init_table(&pool).await.unwrap();
    assert_eq!(
        count(&pool, r#"SELECT COUNT(*) as c FROM policies"#).await,
        0,
        "missing policy tables are recreated"
    );
}

async fn run_stepwise_migration_test(start_ver: SchemaVersion) {
    crate::logging::init_for_tests();

    let pool = setup_legacy_rich_db(start_ver)
        .await
        .expect("failed to setup rich legacy DB");

    assert_full_rich_data_integrity(&pool, start_ver).await;

    for target in (start_ver.0 + 1)..=LAST_SCHEMA_VERSION.0 {
        let target_ver = SchemaVersion(target);
        migrate_from_version(&pool, SchemaVersion(target - 1), target_ver)
            .await
            .unwrap_or_else(|e| panic!("migration from {} to {} failed: {e}", target - 1, target));

        // Object-class inserts only succeed once v9 has created their tables.
        if target_ver.0 >= 5 {
            let _ = add_full_eav_richness(&pool).await;
        }

        assert_full_rich_data_integrity(&pool, target_ver).await;
    }

    init_table(&pool)
        .await
        .expect("re-init after full migration must succeed");
    assert_full_rich_data_integrity(&pool, LAST_SCHEMA_VERSION).await;

    let private_key = generate_random_private_key();
    let handler = SqlBackendHandler::new(private_key, pool);

    let users = handler
        .list_users(None, false)
        .await
        .expect("list_users must succeed on rich migrated DB");
    assert!(users.len() >= 3, "handler must see the rich users");

    let bob = handler
        .get_user_details(&UserId::new("bob"))
        .await
        .expect("get_user_details(bob) must work");
    let has_avatar = bob.attributes.iter().any(|a| a.name.as_str() == "avatar");
    assert!(has_avatar, "bob must have avatar attribute after migration");

    let ssh_attr = bob
        .attributes
        .iter()
        .find(|a| a.name.as_str() == "sshpublickey")
        .expect("sshpublickey must be queryable");
    if let AttributeValue::String(Cardinality::Unbounded(list)) = &ssh_attr.value {
        assert!(
            list.len() >= 2,
            "sshpublickey list must have preserved 2 entries"
        );
    } else {
        panic!("sshpublickey should be a string list");
    }

    handler
        .update_user(UpdateUserRequest {
            user_id: UserId::new("bob"),
            insert_attributes: vec![
                Attribute {
                    name: "tags".into(),
                    value: AttributeValue::String(Cardinality::Unbounded(vec![
                        "extra".to_string(),
                        "tag2".to_string(),
                    ])),
                },
                Attribute {
                    name: "score".into(),
                    value: AttributeValue::Integer(Cardinality::Singleton(99)),
                },
                Attribute {
                    name: "lastlogin".into(),
                    value: AttributeValue::DateTime(Cardinality::Singleton(Utc::now().naive_utc())),
                },
            ],
            ..Default::default()
        })
        .await
        .expect("update_user with mixed attr types must succeed after migration");

    let bob2 = handler.get_user_details(&UserId::new("bob")).await.unwrap();
    assert!(
        bob2.attributes.iter().any(|a| a.name.as_str() == "score"),
        "new integer attr must be readable"
    );

    let groups = handler.list_groups(None).await.expect("list_groups");
    assert!(groups.len() >= 3);
}

#[tokio::test]
async fn test_full_migration_from_v1_with_rich_attributes() {
    run_stepwise_migration_test(SchemaVersion(1)).await;
}

#[tokio::test]
async fn test_migration_from_v5_eav_with_legacy_names() {
    run_stepwise_migration_test(SchemaVersion(4)).await; // reach v5 state via the runner start
}

// The #[ignore] lane tests reset one scratch database; the lock stops parallel clobber.
static PG_LANE_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
static MYSQL_LANE_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

async fn connect_scratch_postgres() -> Option<DbConnection> {
    connect_scratch_postgres_sized(2).await
}

async fn connect_scratch_postgres_sized(connections: u32) -> Option<DbConnection> {
    let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
        eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
        return None;
    };
    if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
        eprintln!("KLLDAP_TEST_DATABASE_URL is not a postgres URL; skipping");
        return None;
    }
    let mut opts = sea_orm::ConnectOptions::new(url);
    opts.max_connections(connections).sqlx_logging(false);
    let pool = Database::connect(opts)
        .await
        .expect("connect test postgres");
    for reset in ["DROP SCHEMA public CASCADE", "CREATE SCHEMA public"] {
        pool.execute(sea_orm::Statement::from_string(
            DbBackend::Postgres,
            reset.to_owned(),
        ))
        .await
        .expect("reset scratch schema");
    }
    Some(pool)
}

fn mysql_database_name(url: &str) -> String {
    let path = url.split('?').next().unwrap_or(url);
    let name = path.rsplit('/').next().unwrap_or("klldap");
    assert!(
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "mysql database name {name}"
    );
    name.to_owned()
}

async fn connect_scratch_mysql() -> Option<DbConnection> {
    connect_scratch_mysql_sized(2).await
}

async fn connect_scratch_mysql_sized(connections: u32) -> Option<DbConnection> {
    let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
        eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
        return None;
    };
    if !url.starts_with("mysql://") {
        eprintln!("KLLDAP_TEST_DATABASE_URL is not a mysql URL; skipping");
        return None;
    }
    let db = mysql_database_name(&url);
    let admin = format!(
        "{}/mysql",
        url.split('?')
            .next()
            .unwrap_or(&url)
            .rsplit_once('/')
            .unwrap()
            .0
    );
    let mut opts = sea_orm::ConnectOptions::new(admin);
    opts.max_connections(1).sqlx_logging(false);
    let admin_pool = Database::connect(opts).await.expect("connect mysql admin");
    for sql in [
        format!("DROP DATABASE IF EXISTS `{db}`"),
        format!("CREATE DATABASE `{db}`"),
    ] {
        admin_pool
            .execute(sea_orm::Statement::from_string(DbBackend::MySql, sql))
            .await
            .expect("reset scratch database");
    }
    let mut opts = sea_orm::ConnectOptions::new(url);
    opts.max_connections(connections).sqlx_logging(false);
    Some(
        Database::connect(opts)
            .await
            .expect("connect scratch mysql"),
    )
}

async fn lane_user_attribute(pool: &DbConnection, user: &str, name: &str) -> Vec<u8> {
    pool.query_one(sea_orm::Statement::from_string(
        pool.get_database_backend(),
        format!(
            "SELECT user_attribute_value FROM user_attributes \
             WHERE user_attribute_user_id = '{user}' AND user_attribute_name = '{name}'"
        ),
    ))
    .await
    .expect("query")
    .unwrap_or_else(|| panic!("attribute {name} missing for {user}"))
    .try_get_by_index::<Vec<u8>>(0)
    .expect("value column")
}

async fn stepwise_lane(pool: &DbConnection) {
    upgrade_to_v1(pool).await.unwrap();
    migrate_from_version(pool, SchemaVersion(1), SchemaVersion(11))
        .await
        .expect("chain to v11");

    let now = chrono::Utc::now().naive_utc();
    let builder = pool.get_database_backend();
    let mut insert_user = Query::insert();
    insert_user
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
            "pguser".into(),
            "pg@ex.com".into(),
            "pg@ex.com".into(),
            now.into(),
            "11111111-1111-1111-1111-111111111111".into(),
            now.into(),
            now.into(),
        ]);
    pool.execute(builder.build(&insert_user)).await.unwrap();

    for (name, typ) in [("pgcustom", "String"), ("kerberossync", "String")] {
        let mut insert_schema = Query::insert();
        insert_schema
            .into_table(UserAttributeSchema::Table)
            .columns([
                UserAttributeSchema::UserAttributeSchemaName,
                UserAttributeSchema::UserAttributeSchemaType,
                UserAttributeSchema::UserAttributeSchemaIsList,
                UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                UserAttributeSchema::UserAttributeSchemaIsHardcoded,
            ])
            .values_panic([
                name.into(),
                typ.into(),
                false.into(),
                true.into(),
                true.into(),
                false.into(),
            ]);
        pool.execute(builder.build(&insert_schema)).await.unwrap();
    }

    let jpeg: &[u8] = b"\xff\xd8\xff\xe0raw-jpeg-bytes";
    let bincoded = bincode::serialize("PG Bob").unwrap();
    for (name, value) in [
        ("avatar", jpeg.to_vec()),
        ("kerberossync", b"1".to_vec()),
        ("pgcustom", bincoded),
    ] {
        let mut insert_value = Query::insert();
        insert_value
            .into_table(UserAttributes::Table)
            .columns([
                UserAttributes::UserAttributeUserId,
                UserAttributes::UserAttributeName,
                UserAttributes::UserAttributeValue,
            ])
            .values_panic(["pguser".into(), name.into(), value.into()]);
        pool.execute(builder.build(&insert_value)).await.unwrap();
    }

    migrate_from_version(pool, SchemaVersion(11), LAST_SCHEMA_VERSION)
        .await
        .expect("v12+v13");
    assert_eq!(get_schema_version(pool).await, Some(LAST_SCHEMA_VERSION));

    assert_eq!(
        lane_user_attribute(pool, "pguser", "pgcustom").await,
        b"PG Bob",
        "v13 must re-encode bincode"
    );
    assert_eq!(
        lane_user_attribute(pool, "pguser", "kerberossync").await,
        b"1",
        "v12 normalize must preserve truthy kerberossync"
    );
    assert_eq!(
        lane_user_attribute(pool, "pguser", "ou").await,
        b"people",
        "v12 OU default must be stored as bytes"
    );
    assert_eq!(
        lane_user_attribute(pool, "pguser", "avatar").await,
        jpeg,
        "raw JPEG must pass through untouched"
    );
    let aliases_row = pool
        .query_one(sea_orm::Statement::from_string(
            pool.get_database_backend(),
            "SELECT aliases FROM user_attribute_schema \
             WHERE user_attribute_schema_name = 'avatar'"
                .to_owned(),
        ))
        .await
        .expect("query")
        .expect("avatar schema row");
    let aliases: Option<String> = aliases_row.try_get_by_index(0).expect("aliases column");
    assert!(
        aliases
            .unwrap_or_default()
            .to_lowercase()
            .contains("jpegphoto"),
        "v12 upsert must reach the hardcoded avatar aliases"
    );

    init_table(pool).await.expect("re-init must be idempotent");
    assert_eq!(
        lane_user_attribute(pool, "pguser", "pgcustom").await,
        b"PG Bob"
    );
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_stepwise_migration() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    stepwise_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_stepwise_migration() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    stepwise_lane(&pool).await;
}

async fn lane_insert_user(pool: &DbConnection, user_id: &str, uuid: &str) {
    let now = chrono::Utc::now().naive_utc();
    let mut insert_user = Query::insert();
    insert_user
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
            now.into(),
            uuid.into(),
            now.into(),
            now.into(),
        ]);
    pool.execute(pool.get_database_backend().build(&insert_user))
        .await
        .unwrap();
}

async fn lane_insert_group(pool: &DbConnection, group_id: i32, name: &str, uuid: &str) {
    let now = chrono::Utc::now().naive_utc();
    let mut insert_group = Query::insert();
    insert_group
        .into_table(Groups::Table)
        .columns([
            Groups::GroupId,
            Groups::DisplayName,
            Groups::LowercaseDisplayName,
            Groups::CreationDate,
            Groups::Uuid,
            Groups::ModifiedDate,
        ])
        .values_panic([
            group_id.into(),
            name.into(),
            name.into(),
            now.into(),
            uuid.into(),
            now.into(),
        ]);
    pool.execute(pool.get_database_backend().build(&insert_group))
        .await
        .unwrap();
}

async fn lane_user_schema(pool: &DbConnection, name: &str, hardcoded: bool) {
    let mut insert_schema = Query::insert();
    insert_schema
        .into_table(UserAttributeSchema::Table)
        .columns([
            UserAttributeSchema::UserAttributeSchemaName,
            UserAttributeSchema::UserAttributeSchemaType,
            UserAttributeSchema::UserAttributeSchemaIsList,
            UserAttributeSchema::UserAttributeSchemaIsUserVisible,
            UserAttributeSchema::UserAttributeSchemaIsUserEditable,
            UserAttributeSchema::UserAttributeSchemaIsHardcoded,
        ])
        .values_panic([
            name.into(),
            "Integer".into(),
            false.into(),
            true.into(),
            false.into(),
            hardcoded.into(),
        ]);
    pool.execute(pool.get_database_backend().build(&insert_schema))
        .await
        .unwrap();
}

async fn lane_group_schema(pool: &DbConnection, name: &str, hardcoded: bool) {
    let mut insert_schema = Query::insert();
    insert_schema
        .into_table(GroupAttributeSchema::Table)
        .columns([
            GroupAttributeSchema::GroupAttributeSchemaName,
            GroupAttributeSchema::GroupAttributeSchemaType,
            GroupAttributeSchema::GroupAttributeSchemaIsList,
            GroupAttributeSchema::GroupAttributeSchemaIsGroupVisible,
            GroupAttributeSchema::GroupAttributeSchemaIsGroupEditable,
            GroupAttributeSchema::GroupAttributeSchemaIsHardcoded,
        ])
        .values_panic([
            name.into(),
            "Integer".into(),
            false.into(),
            true.into(),
            false.into(),
            hardcoded.into(),
        ]);
    pool.execute(pool.get_database_backend().build(&insert_schema))
        .await
        .unwrap();
}

async fn lane_user_value(pool: &DbConnection, user_id: &str, name: &str, value: &[u8]) {
    let mut insert_value = Query::insert();
    insert_value
        .into_table(UserAttributes::Table)
        .columns([
            UserAttributes::UserAttributeUserId,
            UserAttributes::UserAttributeName,
            UserAttributes::UserAttributeValue,
        ])
        .values_panic([user_id.into(), name.into(), value.to_vec().into()]);
    pool.execute(pool.get_database_backend().build(&insert_value))
        .await
        .unwrap();
}

async fn lane_group_value(pool: &DbConnection, group_id: i32, name: &str, value: &[u8]) {
    let mut insert_value = Query::insert();
    insert_value
        .into_table(GroupAttributes::Table)
        .columns([
            GroupAttributes::GroupAttributeGroupId,
            GroupAttributes::GroupAttributeName,
            GroupAttributes::GroupAttributeValue,
        ])
        .values_panic([group_id.into(), name.into(), value.to_vec().into()]);
    pool.execute(pool.get_database_backend().build(&insert_value))
        .await
        .unwrap();
}

async fn lane_one_spelling(pool: &DbConnection, sql: String, canonical: &str, value: &[u8]) {
    #[derive(Debug, FromQueryResult)]
    struct NameValue {
        name: String,
        value: Vec<u8>,
    }
    let rows = NameValue::find_by_statement(sea_orm::Statement::from_string(
        pool.get_database_backend(),
        sql,
    ))
    .all(pool)
    .await
    .expect("attribute names");
    let matched: Vec<_> = rows
        .iter()
        .filter(|row| row.name.eq_ignore_ascii_case(canonical))
        .collect();
    assert_eq!(matched.len(), 1, "{canonical} rows: {rows:?}");
    assert_eq!(matched[0].name, canonical, "stored spelling");
    assert_eq!(matched[0].value, value);
}

async fn lane_hardcoded_schema(pool: &DbConnection, sql: &str, canonical: &str) {
    #[derive(Debug, FromQueryResult)]
    struct NameFlag {
        name: String,
        flag: bool,
    }
    let rows = NameFlag::find_by_statement(sea_orm::Statement::from_string(
        pool.get_database_backend(),
        sql.to_owned(),
    ))
    .all(pool)
    .await
    .expect("schema names");
    let matched: Vec<_> = rows
        .iter()
        .filter(|row| row.name.eq_ignore_ascii_case(canonical))
        .collect();
    assert_eq!(matched.len(), 1, "{canonical} schema rows: {rows:?}");
    assert_eq!(matched[0].name, canonical, "schema spelling");
    assert!(matched[0].flag, "{canonical} schema row must be hardcoded");
}

// Seeds the case-only alias before v12. PostgreSQL can hold both spellings for one
// entity; MySQL cannot, so that third entity is Postgres-only.
async fn alias_case_lane(pool: &DbConnection) {
    upgrade_to_v1(pool).await.unwrap();
    migrate_from_version(pool, SchemaVersion(1), SchemaVersion(11))
        .await
        .expect("chain to v11");

    lane_insert_user(pool, "aliasonly", "11111111-1111-1111-1111-111111111101").await;
    lane_insert_user(pool, "canononly", "11111111-1111-1111-1111-111111111102").await;
    lane_insert_group(pool, 41, "aliasg", "22222222-2222-2222-2222-222222222201").await;
    lane_insert_group(pool, 42, "canong", "22222222-2222-2222-2222-222222222202").await;
    lane_user_schema(pool, "uidnumber", false).await;
    lane_group_schema(pool, "gidnumber", false).await;
    let postgres = pool.get_database_backend() == DbBackend::Postgres;
    if postgres {
        lane_insert_user(pool, "bothspell", "11111111-1111-1111-1111-111111111103").await;
        lane_insert_group(pool, 43, "bothg", "22222222-2222-2222-2222-222222222203").await;
        lane_user_schema(pool, "uidNumber", true).await;
        lane_group_schema(pool, "gidNumber", true).await;
    }
    lane_user_value(pool, "aliasonly", "uidNumber", b"3001").await;
    lane_user_value(pool, "canononly", "uidnumber", b"3002").await;
    lane_group_value(pool, 41, "gidNumber", b"4001").await;
    lane_group_value(pool, 42, "gidnumber", b"4002").await;
    if postgres {
        lane_user_value(pool, "bothspell", "uidnumber", b"3002").await;
        lane_user_value(pool, "bothspell", "uidNumber", b"3001").await;
        lane_group_value(pool, 43, "gidnumber", b"4002").await;
        lane_group_value(pool, 43, "gidNumber", b"4001").await;
    }

    migrate_from_version(pool, SchemaVersion(11), LAST_SCHEMA_VERSION)
        .await
        .expect("v12+v13");

    lane_one_spelling(
        pool,
        "SELECT user_attribute_name AS name, user_attribute_value AS value \
         FROM user_attributes WHERE user_attribute_user_id = 'aliasonly'"
            .to_owned(),
        "uidnumber",
        b"3001",
    )
    .await;
    lane_one_spelling(
        pool,
        "SELECT user_attribute_name AS name, user_attribute_value AS value \
         FROM user_attributes WHERE user_attribute_user_id = 'canononly'"
            .to_owned(),
        "uidnumber",
        b"3002",
    )
    .await;
    lane_one_spelling(
        pool,
        "SELECT group_attribute_name AS name, group_attribute_value AS value \
         FROM group_attributes WHERE group_attribute_group_id = 41"
            .to_owned(),
        "gidnumber",
        b"4001",
    )
    .await;
    lane_one_spelling(
        pool,
        "SELECT group_attribute_name AS name, group_attribute_value AS value \
         FROM group_attributes WHERE group_attribute_group_id = 42"
            .to_owned(),
        "gidnumber",
        b"4002",
    )
    .await;
    if postgres {
        lane_one_spelling(
            pool,
            "SELECT user_attribute_name AS name, user_attribute_value AS value \
             FROM user_attributes WHERE user_attribute_user_id = 'bothspell'"
                .to_owned(),
            "uidnumber",
            b"3002",
        )
        .await;
        lane_one_spelling(
            pool,
            "SELECT group_attribute_name AS name, group_attribute_value AS value \
             FROM group_attributes WHERE group_attribute_group_id = 43"
                .to_owned(),
            "gidnumber",
            b"4002",
        )
        .await;
    }
    lane_hardcoded_schema(
        pool,
        "SELECT user_attribute_schema_name AS name, \
         user_attribute_schema_is_hardcoded AS flag FROM user_attribute_schema",
        "uidnumber",
    )
    .await;
    lane_hardcoded_schema(
        pool,
        "SELECT group_attribute_schema_name AS name, \
         group_attribute_schema_is_hardcoded AS flag FROM group_attribute_schema",
        "gidnumber",
    )
    .await;
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_alias_case() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    alias_case_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_alias_case() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    alias_case_lane(&pool).await;
}

fn drop_policy_index_sql(backend: DbBackend) -> &'static str {
    match backend {
        DbBackend::MySql => "DROP INDEX `unique-policy-lower-name` ON `policies`",
        DbBackend::Postgres => "DROP INDEX \"unique-policy-lower-name\"",
        other => panic!("repair lane has no drop-index for {other:?}"),
    }
}

async fn drop_logs_and_policy_index(pool: &DbConnection) {
    let backend = pool.get_database_backend();
    pool.execute(sea_orm::Statement::from_string(
        backend,
        "DROP TABLE logs".to_owned(),
    ))
    .await
    .expect("drop logs");
    pool.execute(sea_orm::Statement::from_string(
        backend,
        drop_policy_index_sql(backend).to_owned(),
    ))
    .await
    .expect("drop index");
}

async fn expect_logs_and_policy_index(pool: &DbConnection) {
    let backend = pool.get_database_backend();
    pool.execute(sea_orm::Statement::from_string(
        backend,
        "SELECT 1 FROM logs LIMIT 1".to_owned(),
    ))
    .await
    .expect("logs restored");

    #[derive(FromQueryResult)]
    struct IndexRow {
        indexname: String,
    }
    let index_sql = match backend {
        DbBackend::Postgres => {
            "SELECT indexname FROM pg_indexes WHERE indexname = 'unique-policy-lower-name'"
        }
        DbBackend::MySql => {
            "SELECT index_name AS indexname FROM information_schema.statistics \
             WHERE table_schema = DATABASE() AND index_name = 'unique-policy-lower-name'"
        }
        other => panic!("repair lane has no index query for {other:?}"),
    };
    let indexes: Vec<String> = IndexRow::find_by_statement(sea_orm::Statement::from_string(
        backend,
        index_sql.to_owned(),
    ))
    .all(pool)
    .await
    .expect("index lookup")
    .into_iter()
    .map(|row| row.indexname)
    .collect();
    assert!(
        indexes
            .iter()
            .any(|name| name == "unique-policy-lower-name"),
        "unique-policy-lower-name restored: {indexes:?}"
    );
}

fn period_key_sql(backend: DbBackend, statement: &str) -> String {
    let key = match backend {
        DbBackend::MySql => "`key`",
        DbBackend::Postgres => "\"key\"",
        other => panic!("repair lane has no key quoting for {other:?}"),
    };
    format!("{statement} FROM system_config WHERE {key} = 'lockout_period'")
}

async fn drop_lockout_tables(pool: &DbConnection) {
    let backend = pool.get_database_backend();
    for table in [
        "login_lockouts",
        "user_activity",
        "totp_steps",
        "mfa_used_proofs",
        "mfa_windows",
    ] {
        pool.execute(sea_orm::Statement::from_string(
            backend,
            format!("DROP TABLE {table}"),
        ))
        .await
        .expect("drop a lockout table");
    }
    pool.execute(sea_orm::Statement::from_string(
        backend,
        period_key_sql(backend, "DELETE"),
    ))
    .await
    .expect("delete the period row");
    pool.execute(sea_orm::Statement::from_string(
        backend,
        recording_key_sql(backend, "DELETE"),
    ))
    .await
    .expect("delete the recording row");
}

fn recording_key_sql(backend: DbBackend, statement: &str) -> String {
    let period = period_key_sql(backend, statement);
    period.replace("'lockout_period'", "'inactivity_recording_since'")
}

async fn expect_lockout_tables(pool: &DbConnection) {
    let backend = pool.get_database_backend();
    pool.execute(sea_orm::Statement::from_string(
        backend,
        "SELECT fail_count, lock_logged, split_start FROM login_lockouts LIMIT 1".to_owned(),
    ))
    .await
    .expect("login_lockouts restored");
    pool.execute(sea_orm::Statement::from_string(
        backend,
        "SELECT user_id, last_success, reenabled_at FROM user_activity LIMIT 1".to_owned(),
    ))
    .await
    .expect("user_activity restored");
    pool.execute(sea_orm::Statement::from_string(
        backend,
        "SELECT user_id, step, failures, used FROM totp_steps LIMIT 1".to_owned(),
    ))
    .await
    .expect("totp_steps restored");
    pool.execute(sea_orm::Statement::from_string(
        backend,
        "SELECT proof_id, expires_at FROM mfa_used_proofs LIMIT 1".to_owned(),
    ))
    .await
    .expect("mfa_used_proofs restored");
    pool.execute(sea_orm::Statement::from_string(
        backend,
        "SELECT user_id, peer, opened_at, until_at FROM mfa_windows LIMIT 1".to_owned(),
    ))
    .await
    .expect("mfa_windows restored");
    let period = pool
        .query_one(sea_orm::Statement::from_string(
            backend,
            period_key_sql(backend, "SELECT value"),
        ))
        .await
        .expect("period query")
        .expect("the period row restored");
    let value: String = period.try_get_by_index(0).expect("value");
    assert_eq!(value, "0");
    let recording = pool
        .query_one(sea_orm::Statement::from_string(
            backend,
            recording_key_sql(backend, "SELECT value"),
        ))
        .await
        .expect("recording query")
        .expect("the recording row restored");
    let value: String = recording.try_get_by_index(0).expect("value");
    assert_eq!(value, "off");
}

async fn expect_kept_user(pool: &DbConnection) {
    let backend = pool.get_database_backend();
    let kept = pool
        .query_one(sea_orm::Statement::from_string(
            backend,
            "SELECT email FROM users WHERE user_id = 'kept'".to_owned(),
        ))
        .await
        .expect("kept user query")
        .expect("kept user row");
    let email: String = kept.try_get_by_index(0).expect("email");
    assert_eq!(email, "kept@ex.com");
}

async fn repair_lane(pool: &DbConnection) {
    init_table(pool).await.expect("init");
    insert_directory_user(pool, "kept", "22222222-2222-2222-2222-222222222222").await;
    let backend = pool.get_database_backend();

    pool.execute(sea_orm::Statement::from_string(
        backend,
        "UPDATE metadata SET version = 12".to_owned(),
    ))
    .await
    .expect("stamp version 12");
    pool.execute(sea_orm::Statement::from_string(
        backend,
        "ALTER TABLE users DROP COLUMN krb_principal_name".to_owned(),
    ))
    .await
    .expect("drop v13 column");
    drop_logs_and_policy_index(pool).await;
    drop_lockout_tables(pool).await;
    migrate_from_version(pool, SchemaVersion(12), LAST_SCHEMA_VERSION)
        .await
        .expect("v13 from version 12");
    pool.execute(sea_orm::Statement::from_string(
        backend,
        "SELECT krb_principal_name FROM users LIMIT 1".to_owned(),
    ))
    .await
    .expect("krb_principal_name restored");
    expect_logs_and_policy_index(pool).await;
    assert_eq!(get_schema_version(pool).await, Some(LAST_SCHEMA_VERSION));
    expect_kept_user(pool).await;
    // The lockout's tables come from the additions, the boot's next step (init_table).
    ensure_v13_additions(pool)
        .await
        .expect("v13 additions after the step");
    expect_lockout_tables(pool).await;

    drop_logs_and_policy_index(pool).await;
    drop_lockout_tables(pool).await;
    ensure_v13_additions(pool).await.expect("v13 additions");
    expect_logs_and_policy_index(pool).await;
    expect_lockout_tables(pool).await;
    expect_kept_user(pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_repair_v13_additions() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    repair_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_repair_v13_additions() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    repair_lane(&pool).await;
}

async fn fresh_install_lane(pool: &DbConnection) {
    use crate::sql_backend_handler::tests::{
        insert_group, insert_membership, insert_user_no_password,
    };
    use crate::sql_log_handler::{LogRetention, enforce_log_retention};
    use lldap_domain_handlers::handler::LogBackendHandler;
    use lldap_domain_handlers::logging::{
        LOGIN_KINDS, LogCursor, LogDimension, LogFilter, LogKind,
    };
    use lldap_domain_model::model::{Logs, LogsColumn, logs};
    use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

    init_table(pool).await.expect("fresh init");
    assert_eq!(get_schema_version(pool).await, Some(LAST_SCHEMA_VERSION));
    init_table(pool).await.expect("re-init must be idempotent");
    assert_eq!(get_schema_version(pool).await, Some(LAST_SCHEMA_VERSION));

    let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
    insert_user_no_password(&handler, "bob").await;
    let devs = insert_group(&handler, "Devs").await;
    insert_membership(&handler, devs, "bob").await;
    let at = |day: u32, hour: u32| {
        NaiveDate::from_ymd_opt(2024, 5, day)
            .unwrap()
            .and_hms_micro_opt(hour, 0, 40, 123_456)
            .unwrap()
    };
    let row =
        |actor: &str, kind: &str, success: bool, timestamp: NaiveDateTime| logs::ActiveModel {
            timestamp: Set(timestamp),
            kind: Set(kind.to_owned()),
            success: Set(success),
            protocol: Set("ldap".to_owned()),
            actor: Set(Some(actor.to_owned())),
            peer: Set(Some("10.0.0.5".to_owned())),
            ..Default::default()
        };
    Logs::insert_many([
        row("bob", "bind", false, at(1, 9)),
        row("bob", "bind", true, at(1, 10)),
        row("bob", "bind", false, at(1, 12)),
        row("bob", "login", false, at(2, 12)),
        row("carol", "bind", false, at(2, 13)),
    ])
    .exec(pool)
    .await
    .expect("insert rows");

    let by_day = handler
        .summarize_log_events(LogFilter::default(), vec![LogDimension::Day], 100)
        .await
        .expect("summary by day");
    assert_eq!(
        by_day
            .iter()
            .map(|b| (b.day.as_deref(), b.count))
            .collect::<Vec<_>>(),
        vec![(Some("2024-05-01"), 3), (Some("2024-05-02"), 2)]
    );
    let by_hour = handler
        .summarize_log_events(
            LogFilter {
                kinds: vec![LogKind::Bind, LogKind::Login],
                success: Some(false),
                ..Default::default()
            },
            vec![LogDimension::Kind, LogDimension::Hour],
            100,
        )
        .await
        .expect("summary by kind and hour");
    assert_eq!(
        by_hour
            .iter()
            .map(|b| (b.kind, b.hour, b.count))
            .collect::<Vec<_>>(),
        vec![
            (Some(LogKind::Bind), Some(13), 1),
            (Some(LogKind::Login), Some(12), 1),
            (Some(LogKind::Bind), Some(12), 1),
            (Some(LogKind::Bind), Some(9), 1),
        ],
        "equal counts: newest first"
    );
    assert_eq!(
        by_hour[0].first,
        lldap_domain_handlers::instant::from_naive(at(2, 13))
    );
    let sharp = NaiveDate::from_ymd_opt(2024, 5, 2)
        .unwrap()
        .and_hms_micro_opt(14, 0, 40, 600_000)
        .unwrap();
    Logs::insert_many([row("dave", "bind", true, sharp)])
        .exec(pool)
        .await
        .expect("fractional insert");
    let stored = Logs::find()
        .filter(LogsColumn::Actor.eq("dave"))
        .one(pool)
        .await
        .expect("dave row")
        .expect("dave row");
    assert_eq!(stored.timestamp, sharp, "a .600000 fraction must not round");

    let members = handler
        .list_log_events(
            LogFilter {
                member_of: Some("devs".to_owned()),
                ..Default::default()
            },
            10,
            LogCursor::After(0),
        )
        .await
        .expect("members of devs, oldest first");
    assert_eq!(
        members.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );

    let activity = handler
        .log_activity(&UserId::new("bob"), LOGIN_KINDS.to_vec(), None)
        .await
        .expect("activity");
    assert_eq!(activity.last_success.map(|r| r.id), Some(2));
    assert_eq!(activity.last_failure.map(|r| r.id), Some(4));
    assert_eq!(activity.failures_since_last_success, 2);

    #[derive(FromQueryResult)]
    struct IndexRow {
        indexname: String,
    }
    let index_sql = match pool.get_database_backend() {
        DbBackend::Postgres => "SELECT indexname FROM pg_indexes WHERE tablename = 'logs'",
        DbBackend::MySql => {
            "SELECT index_name AS indexname FROM information_schema.statistics \
             WHERE table_schema = DATABASE() AND table_name = 'logs'"
        }
        other => panic!("no logs index query for {other:?}"),
    };
    let indexes: Vec<String> = IndexRow::find_by_statement(sea_orm::Statement::from_string(
        pool.get_database_backend(),
        index_sql.to_owned(),
    ))
    .all(pool)
    .await
    .expect("logs indexes")
    .into_iter()
    .map(|r| r.indexname)
    .collect();
    for index in LOG_INDEXES {
        assert!(indexes.iter().any(|n| n == index), "{index}: {indexes:?}");
    }

    Logs::delete_many().exec(pool).await.expect("clear rows");
    let aged = |actor: &str, days_ago: i64| logs::ActiveModel {
        timestamp: Set(chrono::Utc::now().naive_utc() - chrono::Duration::days(days_ago)),
        kind: Set("bind".to_owned()),
        success: Set(true),
        protocol: Set("ldap".to_owned()),
        actor: Set(Some(actor.to_owned())),
        ..Default::default()
    };
    Logs::insert_many(
        std::iter::once(aged("old", 40)).chain((0..5).map(|i| aged(&format!("new{i}"), 0))),
    )
    .exec(pool)
    .await
    .expect("insert rows");
    enforce_log_retention(
        pool,
        LogRetention {
            retention_days: 30,
            max_entries: 3,
        },
    )
    .await
    .expect("retention");
    let actors: Vec<_> = Logs::find()
        .order_by_asc(LogsColumn::Id)
        .all(pool)
        .await
        .expect("query")
        .into_iter()
        .filter_map(|r| r.actor)
        .collect();
    assert_eq!(actors, vec!["new2", "new3", "new4"]);
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_fresh_install_lookups_and_retention() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    fresh_install_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_fresh_install_lookups_and_retention() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    fresh_install_lane(&pool).await;
}

fn kerberos_stamp() -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap()
}

async fn insert_directory_user(pool: &DbConnection, user_id: &str, uuid: &str) {
    let when = kerberos_stamp();
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

async fn insert_principal(
    pool: &DbConnection,
    name: &str,
    user_id: Option<&str>,
) -> Result<(), sea_orm::DbErr> {
    let user_value = match user_id {
        Some(id) => Value::String(Some(Box::new(id.to_owned()))),
        None => Value::String(None),
    };
    pool.execute(
        pool.get_database_backend().build(
            Query::insert()
                .into_table(KerberosPrincipals::Table)
                .columns([
                    KerberosPrincipals::Name,
                    KerberosPrincipals::UserId,
                    KerberosPrincipals::Record,
                    KerberosPrincipals::HasKeys,
                    KerberosPrincipals::Disabled,
                    KerberosPrincipals::Kvno,
                    KerberosPrincipals::ModifiedDate,
                ])
                .values_panic([
                    name.into(),
                    user_value.into(),
                    vec![1u8].into(),
                    true.into(),
                    false.into(),
                    1i32.into(),
                    kerberos_stamp().into(),
                ]),
        ),
    )
    .await
    .map(|_| ())
}

async fn delete_directory_user(pool: &DbConnection, user_id: &str) {
    pool.execute(
        pool.get_database_backend().build(
            Query::delete()
                .from_table(Users::Table)
                .and_where(Expr::col(Users::UserId).eq(user_id)),
        ),
    )
    .await
    .unwrap();
}

async fn count_sql(pool: &DbConnection, sql: &str) -> i64 {
    CountRow::find_by_statement(sea_orm::Statement::from_string(
        pool.get_database_backend(),
        sql.to_owned(),
    ))
    .one(pool)
    .await
    .unwrap()
    .unwrap()
    .c
}

async fn assert_principal_user_rules(pool: &DbConnection) {
    insert_directory_user(pool, "alice", "11111111-1111-1111-1111-111111111111").await;
    insert_principal(pool, "alice", Some("alice"))
        .await
        .unwrap();
    delete_directory_user(pool, "alice").await;
    assert_eq!(
        count_sql(
            pool,
            "SELECT COUNT(*) as c FROM kerberos_principals WHERE name = 'alice'",
        )
        .await,
        0,
        "deleting the user removes the principal row"
    );

    insert_principal(pool, "svc/a", None).await.unwrap();
    insert_principal(pool, "svc/b", None).await.unwrap();
    assert_eq!(
        count_sql(
            pool,
            "SELECT COUNT(*) as c FROM kerberos_principals WHERE user_id IS NULL",
        )
        .await,
        2,
        "two principals may have a null user id"
    );

    insert_directory_user(pool, "bob", "22222222-2222-2222-2222-222222222222").await;
    insert_principal(pool, "bob", Some("bob")).await.unwrap();
    assert!(
        insert_principal(pool, "bob/admin", Some("bob"))
            .await
            .is_err(),
        "a user id may point at only one principal"
    );
    assert!(
        insert_principal(pool, "ghost", Some("no-such-user"))
            .await
            .is_err(),
        "a principal user id must name a user"
    );
}

async fn assert_the_alias_target_column_is_ensured(pool: &DbConnection) {
    pool.execute_unprepared("ALTER TABLE kerberos_principals DROP COLUMN alias_target")
        .await
        .unwrap();
    insert_principal(pool, "HTTP/before.example.com", None)
        .await
        .unwrap();
    ensure_v13_additions(pool).await.unwrap();
    pool.execute_unprepared(
        "UPDATE kerberos_principals SET alias_target = 'bob' \
         WHERE name = 'HTTP/before.example.com'",
    )
    .await
    .unwrap();
    let filled = "SELECT COUNT(*) as c FROM kerberos_principals WHERE alias_target = 'bob'";
    let empty = "SELECT COUNT(*) as c FROM kerberos_principals WHERE alias_target IS NULL";
    assert_eq!(
        (count_sql(pool, filled).await, count_sql(pool, empty).await),
        (
            1,
            count_sql(pool, "SELECT COUNT(*) as c FROM kerberos_principals").await - 1
        ),
        "a table made before alias_target gets the column at the next start, empty"
    );
}

#[test]
fn test_kerberos_bytes_are_longblob_on_mysql() {
    for (backend, expect) in [
        (DbBackend::MySql, "longblob"),
        (DbBackend::Postgres, "bytea"),
        (DbBackend::Sqlite, "blob"),
    ] {
        for name in ["record", "state"] {
            let sql = backend
                .build(
                    Table::create()
                        .table(Alias::new("t"))
                        .col(kerberos_bytes(ColumnDef::new(Alias::new(name)), backend).not_null()),
                )
                .to_string()
                .to_ascii_lowercase();
            assert!(sql.contains(expect), "{backend:?} {name}: {sql}");
            if !matches!(backend, DbBackend::MySql) {
                assert!(!sql.contains("longblob"), "{backend:?} {name}: {sql}");
            }
        }
    }
}

#[tokio::test]
async fn test_ensure_kerberos_tables() {
    let pool = get_in_memory_db().await;
    init_table(&pool).await.unwrap();
    #[derive(FromQueryResult)]
    struct FkFlag {
        foreign_keys: i32,
    }
    assert_eq!(
        FkFlag::find_by_statement(raw_statement("PRAGMA foreign_keys"))
            .one(&pool)
            .await
            .unwrap()
            .unwrap()
            .foreign_keys,
        1,
        "foreign keys stay on after init"
    );
    for table in ["kerberos_principals", "kerberos_policies", "kerberos_realm"] {
        assert_eq!(
            count(&pool, &format!("SELECT COUNT(*) as c FROM {table}")).await,
            0,
            "{table} is created empty"
        );
    }

    #[derive(FromQueryResult)]
    struct ColInfo {
        name: String,
        nn: i32,
        col_type: String,
    }
    let columns = |table: &'static str| {
        let pool = &pool;
        async move {
            ColInfo::find_by_statement(raw_statement(&format!(
                "SELECT name, \"notnull\" as nn, type as col_type FROM pragma_table_info('{table}')"
            )))
            .all(pool)
            .await
            .unwrap()
        }
    };
    let principal_cols = columns("kerberos_principals").await;
    let expect = [
        ("name", 1, "varchar(255)"),
        ("user_id", 0, "varchar(255)"),
        ("record", 1, "BLOB"),
        ("has_keys", 1, "boolean"),
        ("disabled", 1, "boolean"),
        ("kvno", 1, "INTEGER"),
        ("expiration", 0, "datetime_text"),
        ("password_expiration", 0, "datetime_text"),
        ("policy", 0, "varchar(255)"),
        ("modified_date", 1, "datetime_text"),
        ("alias_target", 0, "TEXT"),
    ];
    assert_eq!(principal_cols.len(), expect.len());
    for (col, (name, notnull, col_type)) in principal_cols.iter().zip(expect) {
        assert_eq!(col.name, name);
        assert_eq!(col.nn, notnull, "{name}");
        assert_eq!(col.col_type, col_type, "{name}");
    }
    let policy_cols = columns("kerberos_policies").await;
    assert_eq!(
        policy_cols
            .iter()
            .map(|c| (c.name.as_str(), c.nn, c.col_type.as_str()))
            .collect::<Vec<_>>(),
        vec![("name", 1, "varchar(255)"), ("record", 1, "BLOB")]
    );
    let realm_cols = columns("kerberos_realm").await;
    assert_eq!(
        realm_cols
            .iter()
            .map(|c| (c.name.as_str(), c.nn, c.col_type.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("id", 1, "INTEGER"),
            ("realm", 1, "varchar(255)"),
            ("generation", 1, "bigint"),
            ("open", 1, "boolean"),
            ("state", 1, "BLOB"),
        ]
    );
    #[derive(FromQueryResult)]
    struct SqlRow {
        sql: String,
    }
    let realm_sql = SqlRow::find_by_statement(raw_statement(
        "SELECT sql FROM sqlite_master WHERE name = 'kerberos_realm'",
    ))
    .one(&pool)
    .await
    .unwrap()
    .unwrap()
    .sql;
    assert!(
        !realm_sql.to_ascii_uppercase().contains("AUTOINCREMENT"),
        "{realm_sql}"
    );

    #[derive(FromQueryResult)]
    struct FkInfo {
        src: String,
        dest: String,
        on_update: String,
        on_delete: String,
    }
    let fks = FkInfo::find_by_statement(raw_statement(
        "SELECT \"from\" as src, \"table\" as dest, on_update, on_delete \
         FROM pragma_foreign_key_list('kerberos_principals')",
    ))
    .all(&pool)
    .await
    .unwrap();
    assert_eq!(fks.len(), 1);
    assert_eq!(fks[0].src, "user_id");
    assert_eq!(fks[0].dest, "users");
    assert_eq!(fks[0].on_delete, "CASCADE");
    assert_eq!(fks[0].on_update, "NO ACTION");

    #[derive(Debug, FromQueryResult)]
    struct IndexInfo {
        name: String,
        is_unique: i32,
    }
    let indexes = IndexInfo::find_by_statement(raw_statement(
        "SELECT name, \"unique\" as is_unique FROM pragma_index_list('kerberos_principals')",
    ))
    .all(&pool)
    .await
    .unwrap();
    assert!(
        indexes
            .iter()
            .any(|i| i.name == "kerberos-principals-user-id" && i.is_unique == 1),
        "{indexes:?}"
    );

    assert_principal_user_rules(&pool).await;

    #[derive(FromQueryResult)]
    struct NameRow {
        name: String,
    }
    let index_names = || {
        let pool = &pool;
        async move {
            let mut names: Vec<String> = NameRow::find_by_statement(raw_statement(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name IN \
                 ('kerberos_principals', 'kerberos_policies', 'kerberos_realm') ORDER BY name",
            ))
            .all(pool)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
            names.sort();
            names
        }
    };
    let before = index_names().await;
    insert_principal(&pool, "HTTP/kept.example.com", None)
        .await
        .unwrap();
    ensure_v13_additions(&pool).await.unwrap();
    assert_eq!(index_names().await, before);
    assert_eq!(
        count_sql(
            &pool,
            "SELECT COUNT(*) as c FROM kerberos_principals WHERE name = 'HTTP/kept.example.com'",
        )
        .await,
        1
    );
    assert_the_alias_target_column_is_ensured(&pool).await;
    let ensured = columns("kerberos_principals").await;
    let alias_target = ensured.iter().find(|c| c.name == "alias_target").unwrap();
    assert_eq!(
        (alias_target.nn, alias_target.col_type.as_str()),
        (0, "TEXT")
    );
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_ensure_kerberos_tables() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    init_table(&pool).await.unwrap();
    assert_principal_user_rules(&pool).await;
    insert_principal(&pool, "HTTP/kept.example.com", None)
        .await
        .unwrap();
    ensure_v13_additions(&pool).await.unwrap();
    assert_eq!(
        count_sql(
            &pool,
            "SELECT COUNT(*) as c FROM kerberos_principals WHERE name = 'HTTP/kept.example.com'",
        )
        .await,
        1
    );
    assert_the_alias_target_column_is_ensured(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_kerberos_batch() {
    use crate::sql_kerberos_handler::tests::{
        scenario_batch_round_trip, scenario_failure_rolls_back, scenario_stale_generation,
    };
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    scenario_batch_round_trip(&pool).await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    scenario_stale_generation(&pool).await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    scenario_failure_rolls_back(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_take_one_wins() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_kerberos_handler::tests::scenario_take_one_wins(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_read_back_waits_for_the_holder() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_kerberos_committer::tests::scenario_read_back_waits_for_the_holder(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_read_back_waits_for_the_holder() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    crate::sql_kerberos_committer::tests::scenario_read_back_waits_for_the_holder(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_first_commit_probe_waits_for_the_insert() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_kerberos_committer::tests::scenario_the_first_commit_probe_waits_for_the_insert(
        &pool,
    )
    .await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_first_commit_probe_waits_for_the_insert() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    crate::sql_kerberos_committer::tests::scenario_the_first_commit_probe_waits_for_the_insert(
        &pool,
    )
    .await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_the_lock_wait_is_bounded_and_put_back() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(5).await else {
        return;
    };
    crate::sql_kerberos_committer::tests::scenario_the_mysql_lock_wait_is_bounded_and_put_back(
        &pool,
    )
    .await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_ensure_kerberos_tables() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    init_table(&pool).await.unwrap();
    assert_principal_user_rules(&pool).await;
    insert_principal(&pool, "HTTP/kept.example.com", None)
        .await
        .unwrap();
    ensure_v13_additions(&pool).await.unwrap();
    assert_eq!(
        count_sql(
            &pool,
            "SELECT COUNT(*) as c FROM kerberos_principals WHERE name = 'HTTP/kept.example.com'",
        )
        .await,
        1
    );
    assert_the_alias_target_column_is_ensured(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_kerberos_batch() {
    use crate::sql_kerberos_handler::tests::{
        scenario_batch_round_trip, scenario_failure_rolls_back, scenario_stale_generation,
    };
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    scenario_batch_round_trip(&pool).await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    scenario_stale_generation(&pool).await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    scenario_failure_rolls_back(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_take_one_wins() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    crate::sql_kerberos_handler::tests::scenario_take_one_wins(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_kerberos_longblob() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    init_table(&pool).await.unwrap();
    for (table, column) in [
        ("kerberos_principals", "record"),
        ("kerberos_policies", "record"),
        ("kerberos_realm", "state"),
    ] {
        let row = pool
            .query_one(sea_orm::Statement::from_string(
                DbBackend::MySql,
                format!(
                    "SELECT column_type FROM information_schema.columns \
                     WHERE table_schema = DATABASE() AND table_name = '{table}' \
                     AND column_name = '{column}'"
                ),
            ))
            .await
            .expect("column type")
            .unwrap_or_else(|| panic!("{table}.{column} missing"));
        let column_type: String = row.try_get_by_index(0).expect("column_type");
        assert!(
            column_type.to_ascii_lowercase().contains("longblob"),
            "{table}.{column}: {column_type}"
        );
    }
    let blob = vec![0x5au8; 70 * 1024];
    insert_principal(&pool, "long", None).await.unwrap();
    pool.execute(
        pool.get_database_backend().build(
            Query::update()
                .table(KerberosPrincipals::Table)
                .value(KerberosPrincipals::Record, blob.clone())
                .and_where(Expr::col(KerberosPrincipals::Name).eq("long")),
        ),
    )
    .await
    .expect("store a record larger than a MySQL BLOB");
    let got = pool
        .query_one(sea_orm::Statement::from_string(
            DbBackend::MySql,
            "SELECT record FROM kerberos_principals WHERE name = 'long'".to_owned(),
        ))
        .await
        .expect("read record")
        .expect("long row");
    let stored: Vec<u8> = got.try_get_by_index(0).expect("record");
    assert_eq!(stored, blob);
}

fn dump_script_names(text: &str, prefix: &str) -> Vec<String> {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("the dump script has no {prefix} line"))
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn test_sqlite_dump_script_matches_migrated_tables() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/sqlite_dump_commands.sh");
    let text = std::fs::read_to_string(&script).unwrap();
    let left_out = dump_script_names(&text, "# left out:");
    let server_tables = dump_script_names(&text, "# server tables:");
    assert_eq!(
        left_out,
        [
            "metadata",
            "sqlite_sequence",
            "totp_steps",
            "mfa_used_proofs"
        ]
        .map(str::to_owned)
    );
    let output = std::process::Command::new("bash")
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let listed: Vec<String> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(".mode insert "))
        .map(str::to_owned)
        .collect();
    assert!(listed.iter().all(|name| !left_out.contains(name)));
    for name in &server_tables {
        assert!(listed.iter().any(|item| item == name), "{name}");
    }
    let users = listed.iter().position(|name| name == "users").unwrap();
    let after_users: Vec<&str> = listed[users + 1..users + 6]
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        after_users,
        [
            "policies",
            "ou_policies",
            "kerberos_policies",
            "kerberos_realm",
            "kerberos_principals",
        ]
    );

    let pool = get_in_memory_db().await;
    init_table(&pool).await.unwrap();
    #[derive(FromQueryResult)]
    struct NameRow {
        name: String,
    }
    let created: Vec<String> = NameRow::find_by_statement(raw_statement(
        "SELECT name FROM sqlite_master WHERE type = 'table'",
    ))
    .all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.name)
    .collect();
    let mut dumped: Vec<String> = listed
        .iter()
        .filter(|name| !server_tables.iter().any(|extra| extra == *name))
        .cloned()
        .collect();
    dumped.sort();
    let mut migrated: Vec<String> = created
        .iter()
        .filter(|name| !left_out.iter().any(|skip| skip == *name))
        .cloned()
        .collect();
    migrated.sort();
    assert_eq!(dumped, migrated);

    #[derive(FromQueryResult)]
    struct FkDest {
        dest: String,
    }
    for (index, table) in listed.iter().enumerate() {
        if !created.iter().any(|name| name == table) {
            continue;
        }
        assert!(
            table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "{table}"
        );
        let dests = FkDest::find_by_statement(raw_statement(&format!(
            "SELECT \"table\" as dest FROM pragma_foreign_key_list('{table}')"
        )))
        .all(&pool)
        .await
        .unwrap();
        for dest in dests {
            let earlier = listed.iter().position(|name| name == &dest.dest).unwrap();
            assert!(earlier < index, "{table} follows {}", dest.dest);
        }
    }
}

async fn policy_store_lane(pool: &DbConnection) {
    use lldap_domain_handlers::handler::PolicyBackendHandler;
    use lldap_domain_handlers::policies::{CreatePolicyRequest, PolicyId, UpdatePolicyRequest};
    use std::collections::BTreeMap;

    fn items(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }
    async fn state_of(handler: &SqlBackendHandler, ou: &str) -> Vec<(Option<PolicyId>, bool)> {
        handler
            .list_ou_policy_states()
            .await
            .expect("list states")
            .into_iter()
            .filter(|s| s.ou_key == ou)
            .map(|s| (s.policy_id, s.block_inheritance))
            .collect()
    }

    init_table(pool).await.expect("fresh init");
    let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
    let base = handler
        .create_policy(CreatePolicyRequest {
            name: "Lane Base".to_owned(),
            description: "lane".to_owned(),
            items: items(&[("enable-mfa", "always"), ("lockout-threshold", "5")]),
        })
        .await
        .expect("create base");
    let other = handler
        .create_policy(CreatePolicyRequest {
            name: "Lane Other".to_owned(),
            description: String::new(),
            items: items(&[("lockout-threshold", "7")]),
        })
        .await
        .expect("create other");
    let mut names: Vec<String> = handler
        .list_policies()
        .await
        .expect("list")
        .into_iter()
        .map(|p| p.name)
        .collect();
    names.sort();
    assert_eq!(names, vec!["Lane Base".to_owned(), "Lane Other".to_owned()]);
    assert_eq!(
        handler.get_policy(base).await.expect("get").items,
        items(&[("enable-mfa", "always"), ("lockout-threshold", "5")])
    );
    assert!(
        handler
            .create_policy(CreatePolicyRequest {
                name: "lane base".to_owned(),
                description: String::new(),
                items: BTreeMap::new(),
            })
            .await
            .is_err(),
        "the store must refuse a name that differs only in case"
    );

    handler
        .update_policy(UpdatePolicyRequest {
            id: base,
            name: None,
            description: None,
            items: Some(items(&[("inactivity-days", "30")])),
        })
        .await
        .expect("update");
    assert_eq!(
        handler.get_policy(base).await.expect("get").items,
        items(&[("inactivity-days", "30")])
    );

    handler.set_ou_policy("lane-a", base).await.expect("set a");
    handler
        .set_ou_policy("lane-a", other)
        .await
        .expect("set a again");
    assert_eq!(
        state_of(&handler, "lane-a").await,
        vec![(Some(other), false)]
    );
    handler.set_ou_policy("lane-b", other).await.expect("set b");
    let mut linked = handler.get_policy(other).await.expect("get").linked_ous;
    linked.sort();
    assert_eq!(linked, vec!["lane-a".to_owned(), "lane-b".to_owned()]);

    handler
        .set_ou_policy_inheritance("lane-a\\lane-n", true)
        .await
        .expect("block nested");
    let levels = handler
        .get_policy_levels("lane-a\\lane-n")
        .await
        .expect("levels");
    assert_eq!(
        levels.iter().map(|l| l.ou_key.as_str()).collect::<Vec<_>>(),
        vec!["", "lane-a", "lane-a\\lane-n"]
    );
    assert_eq!(levels[1].policy.as_ref().map(|p| p.id), Some(other));
    assert!(levels[2].blocked && levels[2].policy.is_none());

    handler.delete_policy(other).await.expect("delete other");
    assert!(state_of(&handler, "lane-a").await.is_empty());
    assert!(state_of(&handler, "lane-b").await.is_empty());
    assert_eq!(
        state_of(&handler, "lane-a\\lane-n").await,
        vec![(None, true)]
    );
    assert!(handler.get_policy(other).await.is_err());
    assert!(handler.clear_ou_policy("lane-a").await.is_err());

    handler
        .delete_ou_policy_state("lane-a\\lane-n")
        .await
        .expect("drop nested");
    assert!(state_of(&handler, "lane-a\\lane-n").await.is_empty());
    handler.delete_policy(base).await.expect("delete base");
    assert!(handler.list_policies().await.expect("list").is_empty());
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_policy_store() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    policy_store_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_policy_store() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    policy_store_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_with_a_case_twin_nobody_is_exempt_nothing_is_made_and_every_start_warns() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    crate::sql_mfa_handler::tests::exempt_twin_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_a_protected_case_twin_renamed_to_the_exempt_groups_name_exempts_its_members() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    crate::sql_mfa_handler::tests::exempt_rename_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_a_held_policy_table_refuses_sign_ins_within_the_bound_and_keeps_the_pool() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(6).await else {
        return;
    };
    crate::sql_policy_read::tests::held_table_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_a_held_table_mark_pass_gives_up_and_the_next_pass_loads_the_user() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_policy_read::tests::mark_pass_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_the_bounded_policy_read_stays_below_its_bound() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_policy_read::tests::bounded_read_timing_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_a_held_policy_table_refuses_sign_ins_within_the_bound_and_keeps_the_pool() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(6).await else {
        return;
    };
    crate::sql_policy_read::tests::held_table_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_a_held_table_mark_pass_gives_up_and_the_next_pass_loads_the_user() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(2).await else {
        return;
    };
    crate::sql_policy_read::tests::mark_pass_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_the_bounded_policy_read_stays_below_its_bound() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    crate::sql_policy_read::tests::bounded_read_timing_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_a_bounded_policy_read_leaves_its_connection_with_the_pools_defaults() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(2).await else {
        return;
    };
    crate::sql_policy_read::tests::mysql_put_back_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_a_held_policy_table_refuses_new_passwords_in_the_bound_and_keeps_the_pool() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(6).await else {
        return;
    };
    crate::sql_policy_read::tests::held_minimum_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_a_user_made_during_a_held_fill_is_counted_then_not_loaded_then_admitted() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(6).await else {
        return;
    };
    crate::sql_policy_read::tests::held_fill_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_a_held_policy_table_refuses_new_passwords_in_the_bound_and_keeps_the_pool() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(6).await else {
        return;
    };
    crate::sql_policy_read::tests::held_minimum_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_a_user_made_during_a_held_fill_is_counted_then_not_loaded_then_admitted() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(6).await else {
        return;
    };
    crate::sql_policy_read::tests::held_fill_lane(&pool).await;
}

#[tokio::test]
async fn test_init_repairs_the_login_lockouts_table_and_keeps_its_rows() {
    let pool = get_in_memory_db().await;
    init_table(&pool).await.unwrap();
    insert_directory_user(&pool, "kept", "33333333-3333-3333-3333-333333333333").await;
    pool.execute(raw_statement(
        "INSERT INTO login_lockouts (user_id, fail_count) VALUES ('kept', 2)",
    ))
    .await
    .unwrap();
    init_table(&pool).await.unwrap();
    let kept = r#"SELECT COUNT(*) as c FROM login_lockouts WHERE fail_count = 2"#;
    assert_eq!(count(&pool, kept).await, 1, "re-init keeps the rows");
    #[derive(FromQueryResult)]
    struct FkRow {
        dest: String,
        on_delete: String,
    }
    let fks = FkRow::find_by_statement(raw_statement(
        r#"SELECT "table" as dest, on_delete FROM pragma_foreign_key_list('login_lockouts')"#,
    ))
    .all(&pool)
    .await
    .unwrap();
    let fks: Vec<_> = fks.into_iter().map(|fk| (fk.dest, fk.on_delete)).collect();
    assert_eq!(fks, vec![("users".to_owned(), "CASCADE".to_owned())]);
    pool.execute(raw_statement("DROP TABLE login_lockouts"))
        .await
        .unwrap();
    ensure_v13_additions(&pool).await.unwrap();
    let all = r#"SELECT COUNT(*) as c FROM login_lockouts"#;
    assert_eq!(count(&pool, all).await, 0, "a missing table is made again");
}

#[tokio::test]
async fn test_init_repairs_the_user_activity_table_and_keeps_its_rows() {
    let pool = get_in_memory_db().await;
    init_table(&pool).await.unwrap();
    insert_directory_user(&pool, "kept", "44444444-4444-4444-4444-444444444444").await;
    pool.execute(raw_statement(
        "INSERT INTO user_activity (user_id, reenabled_at) VALUES ('kept', '2026-11-21 10:00:00')",
    ))
    .await
    .unwrap();
    init_table(&pool).await.unwrap();
    let kept = r#"SELECT COUNT(*) as c FROM user_activity WHERE reenabled_at IS NOT NULL"#;
    assert_eq!(count(&pool, kept).await, 1, "re-init keeps the rows");
    #[derive(FromQueryResult)]
    struct FkRow {
        dest: String,
        on_delete: String,
    }
    let fks = FkRow::find_by_statement(raw_statement(
        r#"SELECT "table" as dest, on_delete FROM pragma_foreign_key_list('user_activity')"#,
    ))
    .all(&pool)
    .await
    .unwrap();
    let fks: Vec<_> = fks.into_iter().map(|fk| (fk.dest, fk.on_delete)).collect();
    assert_eq!(fks, vec![("users".to_owned(), "CASCADE".to_owned())]);
    pool.execute(raw_statement("DROP TABLE user_activity"))
        .await
        .unwrap();
    ensure_v13_additions(&pool).await.unwrap();
    let all = r#"SELECT COUNT(*) as c FROM user_activity"#;
    assert_eq!(count(&pool, all).await, 0, "a missing table is made again");
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_user_activity_statements() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_activity_handler::tests::activity_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_user_activity_statements() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    crate::sql_activity_handler::tests::activity_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_two_servers_share_the_user_activity_and_recording_since() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_activity_handler::tests::two_servers_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_two_servers_share_the_user_activity_and_recording_since() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    crate::sql_activity_handler::tests::two_servers_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_a_held_activity_table_refuses_sign_ins_within_the_bound_and_keeps_the_pool()
{
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(6).await else {
        return;
    };
    crate::sql_policy_read::tests::held_activity_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_a_held_activity_table_refuses_sign_ins_within_the_bound_and_keeps_the_pool() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(6).await else {
        return;
    };
    crate::sql_policy_read::tests::held_activity_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_lockout_statements() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_lockout_handler::tests::lockout_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_lockout_statements() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    crate::sql_lockout_handler::tests::lockout_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_lockout_user_deleted_on_one_server_while_another_owes_it() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_lockout_handler::tests::gone_user_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_lockout_start_on_one_server_finish_on_another() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_lockout_handler::tests::split_login_lane(&pool, true).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_lockout_count_write_waits_on_the_period_lock_and_stores_nothing() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_lockout_handler::tests::period_overlap_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_lockout_two_zeroings_at_once_take_two_period_numbers() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_lockout_handler::tests::period_raise_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_totp_codes_at_once_spend_five_attempts_and_one_use() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(10).await else {
        return;
    };
    crate::sql_totp_steps::tests::concurrency_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_totp_codes_at_once_spend_five_attempts_and_one_use() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(10).await else {
        return;
    };
    crate::sql_totp_steps::tests::concurrency_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_one_proof_used_at_once_is_taken_once() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(10).await else {
        return;
    };
    crate::sql_used_proofs::tests::used_proofs_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_one_proof_used_at_once_is_taken_once() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(10).await else {
        return;
    };
    crate::sql_used_proofs::tests::used_proofs_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_proofs_at_once_open_one_window_and_extend_it() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(10).await else {
        return;
    };
    crate::sql_mfa_windows::tests::windows_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_proofs_at_once_open_one_window_and_extend_it() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(10).await else {
        return;
    };
    crate::sql_mfa_windows::tests::windows_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_a_proof_on_one_server_admits_a_kinit_on_the_other_after_its_reread() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_mfa_windows::tests::two_servers_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_a_factor_reset_on_one_server_ends_the_refusal_on_the_other() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    crate::sql_mfa_windows::tests::reset_elsewhere_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_a_proof_on_one_server_admits_a_kinit_on_the_other_after_its_reread() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    crate::sql_mfa_windows::tests::two_servers_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_a_factor_reset_on_one_server_ends_the_refusal_on_the_other() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    crate::sql_mfa_windows::tests::reset_elsewhere_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_a_key_change_racing_marks_leaves_no_mark_of_the_old_key() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(10).await else {
        return;
    };
    crate::sql_totp_steps::tests::key_change_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_a_key_change_racing_marks_leaves_no_mark_of_the_old_key() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(10).await else {
        return;
    };
    crate::sql_totp_steps::tests::key_change_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_totp_codes_checked_at_once_count_exactly() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(10).await else {
        return;
    };
    crate::sql_totp_steps::tests::verify_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_totp_codes_checked_at_once_count_exactly() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(10).await else {
        return;
    };
    crate::sql_totp_steps::tests::verify_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_totp_marks_into_one_gap_at_once_are_all_taken() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(10).await else {
        return;
    };
    crate::sql_totp_steps::tests::neighbour_marks_lane(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_totp_marks_into_one_gap_at_once_are_all_taken() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(10).await else {
        return;
    };
    crate::sql_totp_steps::tests::neighbour_marks_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_totp_mark_waits_for_a_key_change_held_open() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(4).await else {
        return;
    };
    crate::sql_totp_steps::tests::guard_in_flight_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_totp_mark_waits_for_a_key_change_held_open() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(4).await else {
        return;
    };
    crate::sql_totp_steps::tests::guard_in_flight_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_two_finishes_of_one_state_at_once_one_finishes() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(4).await else {
        return;
    };
    crate::sql_mfa_handler::tests::finish_race_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_two_finishes_of_one_state_at_once_one_finishes() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(4).await else {
        return;
    };
    crate::sql_mfa_handler::tests::finish_race_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_a_finish_waits_for_one_held_open_then_is_stale() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres_sized(4).await else {
        return;
    };
    crate::sql_mfa_handler::tests::finish_held_lane(&pool).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_a_finish_waits_for_one_held_open_then_is_stale() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql_sized(4).await else {
        return;
    };
    crate::sql_mfa_handler::tests::finish_held_lane(&pool).await;
}

async fn renamed_items_lane(pool: &DbConnection) {
    init_table(pool).await.expect("fresh init");
    let backend = pool.get_database_backend();
    let stored = [
        ("Old", r#"{"require-mfa":"enrolled"}"#),
        (
            "Strict",
            r#"{"lockout-threshold":"3","require-mfa":"always"}"#,
        ),
        ("Both", r#"{"enable-mfa":"off","require-mfa":"always"}"#),
        ("New", r#"{"enable-mfa":"always"}"#),
        ("Junk", "not json"),
    ];
    for (name, items) in stored {
        let insert = Query::insert()
            .into_table(Policies::Table)
            .columns([
                Policies::Name,
                Policies::LowercaseName,
                Policies::Description,
                Policies::Items,
            ])
            .values_panic([
                name.into(),
                name.to_lowercase().into(),
                "".into(),
                items.into(),
            ])
            .to_owned();
        pool.execute(backend.build(&insert)).await.expect("insert");
    }
    let read = async || {
        let select = Query::select()
            .columns([Policies::Name, Policies::Items])
            .from(Policies::Table)
            .order_by(Policies::Name, Order::Asc)
            .to_owned();
        let rows = pool.query_all(backend.build(&select)).await.expect("read");
        rows.iter()
            .map(|row| {
                let name: String = row.try_get("", "name").unwrap();
                let items: String = row.try_get("", "items").unwrap();
                (name, items)
            })
            .collect::<Vec<_>>()
    };
    let carried = vec![
        ("Both".to_owned(), r#"{"enable-mfa":"off"}"#.to_owned()),
        ("Junk".to_owned(), "not json".to_owned()),
        ("New".to_owned(), r#"{"enable-mfa":"always"}"#.to_owned()),
        ("Old".to_owned(), r#"{"enable-mfa":"enabled"}"#.to_owned()),
        (
            "Strict".to_owned(),
            r#"{"enable-mfa":"always","lockout-threshold":"3"}"#.to_owned(),
        ),
    ];
    for run in ["first", "second"] {
        ensure_v13_additions(pool).await.expect("v13 additions");
        assert_eq!(read().await, carried, "{run} start");
    }
}

#[tokio::test]
async fn test_a_stored_require_mfa_is_carried_over_to_enable_mfa_once() {
    renamed_items_lane(&get_in_memory_db().await).await;
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn test_postgres_carries_require_mfa_over_to_enable_mfa_once() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        return;
    };
    renamed_items_lane(&pool).await;
}

#[tokio::test]
#[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
async fn test_mysql_carries_require_mfa_over_to_enable_mfa_once() {
    let _lane = MYSQL_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_mysql().await else {
        return;
    };
    renamed_items_lane(&pool).await;
}
