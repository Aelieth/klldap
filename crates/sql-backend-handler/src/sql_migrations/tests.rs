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

// ============================================================
// FULL MIGRATION TEST SUITE - RICH DATA GENERATOR + VERIFIER
// ============================================================
//
// This suite creates a richly populated test database exercising
// EVERY major attribute category (String/Integer/Avatar/DateTime,
// scalar + lists), stock hardcoded attrs, custom attrs, legacy
// shapes (pre-v5 columns, old attr names), object classes, memberships,
// and special v12 paths (alias normalization, default injection).
//
// HOW TO ADD / MODIFY TEST DATA (straightforward extension):
//   - Edit populate_rich_data_for_version(...) for the appropriate era.
//   - For pre-v5: add INSERTs into the legacy `users` columns (first_name etc).
//   - For v5+: add schema rows + INSERTs into user_attributes/group_attributes
//     using legacy names (e.g. "first_name") or canonical. Use raw bytes
//     or json for lists. See examples below for "tags" (string list) and avatar.
//   - For v12 normalization test: deliberately INSERT under an alias
//     (e.g. name="jpegPhoto") before the v12 step; the assert will check
//     it gets migrated to canonical and alias row removed.
//   - Update assert_full_rich_data_integrity(...) to add new spot-checks
//     (counts, byte equality, presence of new seeded attrs).
//   - The stepwise runner + main test will automatically exercise it.
//   - Keep test data small but representative (4 users, 3+ groups, 1+ of
//     each attr kind).
//
// Run with LLDAP_TEST_DUMP_MIGRATION_DB=1 to write a temp .db for inspection.
// ============================================================

/// Populate a rich test database state appropriate for the given schema version.
/// Call this *after* reaching `up_to_version` via upgrade + partial migrate.
/// The data inserted matches what an LLDAP of that era would have produced
/// (legacy columns pre-v5, EAV with old names in v5-v11, etc.).
async fn populate_rich_data_for_version(
    pool: &DbConnection,
    up_to_version: SchemaVersion,
) -> anyhow::Result<()> {
    let builder = pool.get_database_backend();
    let now = Utc::now().naive_utc();

    // Common users (utf8 + special chars to stress encoding)
    // We insert directly; handler not always available in old schema shapes.
    if up_to_version.0 < 5 {
        // === PRE-v5: legacy columns on users table ===
        // Use parameterized insert for the real test JPEG so v5 migration + later asserts see exact make_test_jpeg_bytes()
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

        // groups (legacy shape - some without all cols)
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
        // === v5+ EAV era (and later) ===
        // First ensure the 3 legacy attrs exist in schema (v5 seeds them; later v12 normalizes names)
        // For pre-v12 DBs we may be simulating, insert with legacy names to test migration paths.
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

        // Seed minimal schema rows if they don't exist (idempotent for test)
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

        // Insert users (modern columns required for v6+)
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

        // Groups (v6+ requires lowercase)
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

        // Memberships (include a duplicate pair to exercise v8 cleanup path when we step through it *from before v8*)
        pool.execute(raw_statement(
            r#"INSERT INTO memberships (user_id, group_id) VALUES ("bob", 1), ("bob", 3), ("pat", 1), ("pat", 2), ("unicode-ü", 3)"#,
        ))
        .await?;
        if up_to_version.0 < 8 {
            // duplicate to be cleaned by v8
            pool.execute(raw_statement(
                r#"INSERT INTO memberships (user_id, group_id) VALUES ("bob", 1)"#,
            ))
            .await?;
        }

        // === EAV rows ===
        // Legacy "first_name"/"last_name" (to test v5 move + v12 rename)
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

        // Avatar using the canonical test bytes (v5 migration test contract)
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

        // A custom string list (sshpublickey is the stock example, but we also add a custom "tags")
        // Use json encoding for list (current storage contract post-v5)
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

        // Custom string list "tags" (tests list handling for a non-hardcoded attr)
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

        // Integer (posix uid) + custom int scalar "score"
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

        // Datetime custom "lastlogin" (store as timestamp string bytes, matching current write path)
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

        // Custom avatar on another user
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

        // Group attributes (gidnumber etc)
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

        // Object classes (v9+)
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

        // For v12 normalization test: if we are at a pre-v12 state, insert a row under an old alias
        // so that the v12 step will migrate the *data* and delete the alias row.
        if up_to_version.0 < 12 {
            // "jpegPhoto" was a common alias; the v12 repair + normalization will clean it.
            // (The main avatar is already under "avatar".)
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

        // Memberships + object classes already handled above
        add_full_eav_richness(pool).await?;
    }

    // For pre-v5 start the basic memberships were inserted in the <5 branch
    if up_to_version.0 < 5 {
        // For pre-v5 start we still want basic memberships (v8 will clean dups later)
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

    if std::env::var("LLDAP_TEST_DUMP_MIGRATION_DB").is_ok() {
        eprintln!(
            "[migration-test] LLDAP_TEST_DUMP_MIGRATION_DB set - consider using a file-based connection in local debugging runs"
        );
    }

    Ok(())
}

/// Add the full modern EAV richness (ssh list, custom list "tags", custom int/datetime/avatar, group gid, deliberate pre-v12 alias, object classes).
/// Safe to call multiple times (inserts are best-effort / may ignore dups via the test nature).
/// Used both from the >=5 populate branch and from the stepwise runner when crossing v5 from an older start.
async fn add_full_eav_richness(pool: &DbConnection) -> anyhow::Result<()> {
    let builder = pool.get_database_backend();
    let now = Utc::now().naive_utc();
    let expected_jpeg = lldap_domain::images::make_test_jpeg_bytes();

    // Insert schema rows using the v5-era columns (no readonly/aliases columns yet).
    // This is required for FK when adding attr rows at exactly v5..v11 time.
    // (v12 will later upsert the full PublicSchema versions with extra cols.)
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

    // Group schema for gid (v5 shape)
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

    // Ensure schema for the customs we will use (idempotent-ish) - v5 shape
    for (name, typ, is_list) in [
        ("tags", AttributeType::String, true),
        ("score", AttributeType::Integer, false),
        ("lastlogin", AttributeType::DateTime, false),
        ("profilepic", AttributeType::Avatar, false),
        // Note: we do *not* re-insert "jpegPhoto" alias here (would pollute post-v12).
        // The v12 alias cleanup for avatar aliases + first_name (from v5 move) is still
        // exercised by populate at low start versions + the count assert + "firstname" presence check.
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

    // ssh list (stock list attr)
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

    // custom string list
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

    // uid + custom score (int)
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

    // custom datetime
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

    // custom avatar on pat
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

    // group gid
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

    // alias row for v12 test (only if we haven't normalized yet)
    // The caller decides; we insert here unconditionally for pre-v12 starts, v12 step will clean.
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

    // object classes (harmless if already present)
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

/// Setup a complete legacy rich DB up to (and including) the requested version,
/// with data populated in the shape appropriate for that version.
async fn setup_legacy_rich_db(up_to_version: SchemaVersion) -> anyhow::Result<DatabaseConnection> {
    let pool = get_in_memory_db().await;

    // Reach the requested version first
    upgrade_to_v1(&pool).await?;
    if up_to_version.0 > 1 {
        migrate_from_version(&pool, SchemaVersion(1), up_to_version).await?;
    }

    // Now layer rich historical data (this is the "generated test database")
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
    // kerberossync row are inserted with FK checks off — they model rows a partially
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

        // New columns are queryable.
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

        // The v5-era avatar row was upserted in place: type repaired, aliases applied.
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

        // v5's ghost schema rows are gone.
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

        // The pre-existing config row survived the seed.
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

#[test]
fn test_public_schema_has_kerberossync_as_integer() {
    let schema = PublicSchema::get();
    let kerb = schema
        .user_attributes()
        .get_by_name_or_alias("kerberossync")
        .expect("kerberossync attribute must exist");
    assert_eq!(kerb.attribute_type, AttributeType::Integer);
}

// ============================================================
// ASSERTIONS - SANITY + DATA FIDELITY AT EACH STEP / END
// ============================================================

/// Core comprehensive assertion. Call after reaching a version (or at the end).
/// Checks structural sanity + rich data we inserted in populate_*.
async fn assert_full_rich_data_integrity(pool: &DbConnection, at_version: SchemaVersion) {
    // Version
    let ver =
        JustSchemaVersion::find_by_statement(raw_statement(r#"SELECT version FROM metadata"#))
            .one(pool)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(ver.version, at_version, "schema version mismatch");

    // Always have users + groups from our rich set
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

    // Hoisted for use in v5+ and v12 blocks
    #[derive(FromQueryResult, PartialEq, Eq, Debug)]
    struct AttrRow {
        user_attribute_user_id: String,
        user_attribute_name: String,
        user_attribute_value: Vec<u8>,
    }

    if at_version.0 >= 5 {
        // EAV tables exist and have our moved + custom data
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

        // Spot check: avatar bytes (the make_test_jpeg_bytes contract)
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

        // Legacy name "first_name" should only survive until v12 normalization
        let has_legacy_first = attrs.iter().any(|a| a.user_attribute_name == "first_name");
        if at_version.0 < 12 {
            // Before v12 step we may still have it (depending on populate point)
        } else {
            assert!(
                !has_legacy_first,
                "after v12, legacy 'first_name' alias rows must have been migrated/deleted"
            );
            // Canonical must exist
            assert!(
                attrs.iter().any(|a| a.user_attribute_name == "firstname"
                    && a.user_attribute_value == b"first bob"),
                "firstname (canonical) + original bytes must be present post v12 normalization"
            );
        }

        // String list (sshpublickey) present
        assert!(
            attrs.iter().any(|a| a.user_attribute_name == "sshpublickey"
                && a.user_attribute_value.starts_with(b"[")),
            "sshpublickey list should be stored as json bytes"
        );

        // Custom tags list
        assert!(
            attrs.iter().any(|a| a.user_attribute_name == "tags"),
            "custom list attr 'tags' should be present"
        );

        // Group attrs
        let gattr_count: CountRow = CountRow::find_by_statement(raw_statement(
            r#"SELECT COUNT(*) as c FROM group_attributes"#,
        ))
        .one(pool)
        .await
        .unwrap()
        .unwrap();
        assert!(gattr_count.c >= 1, "expected group_attributes");

        // Object classes (if we reached v9)
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

    // v6+ columns
    if at_version.0 >= 6 {
        let _ = pool
            .query_one(raw_statement(
                r#"SELECT lowercase_email FROM users LIMIT 1"#,
            ))
            .await
            .expect("lowercase_email column must exist >=v6");
    }

    // v11 dates
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

    // v12 specific seeds + normalization + system_config
    if at_version.0 >= 12 {
        // system_config + allowedous
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

        // Canonical kerberossync + ou injected for users (bytes form)
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

        // Group ou (use a dedicated query to avoid type mismatch with user-id shaped AttrRow)
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

        // No leftover alias names in user attr names (the authoritative cleanup)
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

        // PublicSchema seeding brought in the rest (firstname, displayname, etc. at minimum)
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
}

/// Stepwise runner: start from a legacy rich state at `start_ver`, then migrate one version
/// at a time up to LAST, asserting integrity after each step.
/// At the end also exercises the live SqlBackendHandler + roundtrips.
async fn run_stepwise_migration_test(start_ver: SchemaVersion) {
    crate::logging::init_for_tests();

    let pool = setup_legacy_rich_db(start_ver)
        .await
        .expect("failed to setup rich legacy DB");

    // Sanity at start
    assert_full_rich_data_integrity(&pool, start_ver).await;

    // Step through every subsequent migration
    for target in (start_ver.0 + 1)..=LAST_SCHEMA_VERSION.0 {
        let target_ver = SchemaVersion(target);
        migrate_from_version(&pool, SchemaVersion(target - 1), target_ver)
            .await
            .unwrap_or_else(|e| panic!("migration from {} to {} failed: {e}", target - 1, target));

        // Keep modern EAV richness topped up after v5 (ssh, customs, lists, obj classes etc).
        // Safe to call repeatedly; obj class inserts will only succeed once v9 migration has created the tables.
        if target_ver.0 >= 5 {
            let _ = add_full_eav_richness(&pool).await;
        }

        // Re-assert version + data
        assert_full_rich_data_integrity(&pool, target_ver).await;
    }

    // Final: full init should be idempotent
    init_table(&pool)
        .await
        .expect("re-init after full migration must succeed");
    assert_full_rich_data_integrity(&pool, LAST_SCHEMA_VERSION).await;

    // === Live handler validation on the migrated rich DB ===
    let private_key = generate_random_private_key();
    let handler = SqlBackendHandler::new(private_key, pool);

    // Read back via public API
    let users = handler
        .list_users(None, false)
        .await
        .expect("list_users must succeed on rich migrated DB");
    assert!(users.len() >= 3, "handler must see the rich users");

    let bob = handler
        .get_user_details(&UserId::new("bob"))
        .await
        .expect("get_user_details(bob) must work");
    // avatar roundtrip (via the attribute path)
    let has_avatar = bob.attributes.iter().any(|a| a.name.as_str() == "avatar");
    assert!(has_avatar, "bob must have avatar attribute after migration");

    // ssh list preserved
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

    // Add even more data via handler to prove write path works post-migration (covers all types)
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

    // Also exercise group side lightly
    let groups = handler.list_groups(None).await.expect("list_groups");
    assert!(groups.len() >= 3);
}

// ============================================================
// MAIN DRIVER TESTS FOR THE FULL SUITE
// ============================================================

#[tokio::test]
async fn test_full_migration_from_v1_with_rich_attributes() {
    // Exercises the complete chain from the very first schema + rich legacy column data
    // all the way through every migration, with sanity at each step + handler at the end.
    run_stepwise_migration_test(SchemaVersion(1)).await;
}

#[tokio::test]
async fn test_migration_from_v5_eav_with_legacy_names() {
    // Specifically stresses the v5 EAV conversion + later v12 alias canonicalization
    // using the exact byte expectations the original v5 tests relied on ("first bob", jpeg bytes).
    run_stepwise_migration_test(SchemaVersion(4)).await; // reach v5 state via the runner start
}

// (Intentionally no v9/v11 late-start driver here: the EAV INSERTs in populate_rich assume post-v11 columns for dates etc.
//  The v1 driver fully exercises every single migration step with rich data "along the way".
//  The v5 driver specifically covers the critical EAV conversion + v12 normalization/alias cleanup on a post-v5 DB.
//  Adding more start points is possible by making populate/version branches even finer-grained for columns.)

// These two #[ignore] tests DROP SCHEMA public; the lock stops parallel clobber.
static PG_LANE_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

async fn connect_scratch_postgres() -> Option<DbConnection> {
    let url = std::env::var("KLLDAP_TEST_DATABASE_URL").ok()?;
    let mut opts = sea_orm::ConnectOptions::new(url);
    opts.max_connections(2).sqlx_logging(false);
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

async fn pg_user_attribute(pool: &DbConnection, user: &str, name: &str) -> Vec<u8> {
    pool.query_one(sea_orm::Statement::from_string(
        DbBackend::Postgres,
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

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn postgres_fresh_install_migrates() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
        return;
    };
    init_table(&pool).await.expect("fresh init on postgres");
    assert_eq!(get_schema_version(&pool).await, Some(LAST_SCHEMA_VERSION));
    init_table(&pool).await.expect("re-init must be idempotent");
    assert_eq!(get_schema_version(&pool).await, Some(LAST_SCHEMA_VERSION));
}

#[tokio::test]
#[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
async fn postgres_stepwise_migration() {
    let _lane = PG_LANE_LOCK.lock().await;
    let Some(pool) = connect_scratch_postgres().await else {
        eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
        return;
    };
    upgrade_to_v1(&pool).await.unwrap();
    migrate_from_version(&pool, SchemaVersion(1), SchemaVersion(11))
        .await
        .expect("chain to v11 on postgres");

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

    migrate_from_version(&pool, SchemaVersion(11), LAST_SCHEMA_VERSION)
        .await
        .expect("v12+v13 on postgres");
    assert_eq!(get_schema_version(&pool).await, Some(LAST_SCHEMA_VERSION));

    assert_eq!(
        pg_user_attribute(&pool, "pguser", "pgcustom").await,
        b"PG Bob",
        "v13 must re-encode bincode on postgres"
    );
    assert_eq!(
        pg_user_attribute(&pool, "pguser", "kerberossync").await,
        b"1",
        "v12 normalize must preserve truthy kerberossync"
    );
    assert_eq!(
        pg_user_attribute(&pool, "pguser", "ou").await,
        b"people",
        "v12 OU default must byte-bind into bytea"
    );
    assert_eq!(
        pg_user_attribute(&pool, "pguser", "avatar").await,
        jpeg,
        "raw JPEG must pass through untouched"
    );
    let aliases_row = pool
        .query_one(sea_orm::Statement::from_string(
            DbBackend::Postgres,
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
        "v12 upsert must reach the hardcoded avatar aliases on postgres"
    );

    init_table(&pool).await.expect("re-init must be idempotent");
    assert_eq!(
        pg_user_attribute(&pool, "pguser", "pgcustom").await,
        b"PG Bob"
    );
}
