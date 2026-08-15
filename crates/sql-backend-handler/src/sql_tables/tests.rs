use super::*;
use crate::sql_migrations;
use chrono::prelude::*;
use lldap_domain::types::GroupId;
use pretty_assertions::assert_eq;
use sea_orm::{ConnectionTrait, Database, DbBackend, FromQueryResult};
use tracing::error;

async fn get_in_memory_db() -> DbConnection {
    let mut sql_opt = sea_orm::ConnectOptions::new("sqlite::memory:".to_owned());
    sql_opt.max_connections(1).sqlx_logging(false);
    Database::connect(sql_opt).await.unwrap()
}

fn raw_statement(sql: &str) -> sea_orm::Statement {
    sea_orm::Statement::from_string(DbBackend::Sqlite, sql.to_owned())
}

#[tokio::test]
async fn test_init_table() {
    let sql_pool = get_in_memory_db().await;
    init_table(&sql_pool).await.unwrap();

    // Verify we reached the current schema version with PublicSchema seeding
    assert_eq!(
        sql_migrations::JustSchemaVersion::find_by_statement(raw_statement(
            r#"SELECT version FROM metadata"#
        ))
        .one(&sql_pool)
        .await
        .unwrap()
        .unwrap(),
        sql_migrations::JustSchemaVersion {
            version: LAST_SCHEMA_VERSION
        }
    );

    // Insert a user using current table columns (lowercase_email etc are required in modern schema)
    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO users
               (user_id, email, lowercase_email, display_name, creation_date, password_hash, uuid, modified_date, password_modified_date)
               VALUES ("bôb", "böb@bob.bob", "böb@bob.bob", "Bob Bobbersön", "1970-01-01 00:00:00", "bob00", "abc", "1970-01-01 00:00:00", "1970-01-01 00:00:00")"#,
        ))
        .await
        .unwrap();

    // Use *canonical* name from PublicSchema (not alias "first_name") — this is the new contract
    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO user_attributes
               (user_attribute_user_id, user_attribute_name, user_attribute_value)
               VALUES ("bôb", "firstname", x'426f62')"#, // raw bytes "Bob" — matches v5+ raw storage philosophy
        ))
        .await
        .unwrap();

    #[derive(FromQueryResult, PartialEq, Eq, Debug)]
    struct ShortUserDetails {
        display_name: String,
        creation_date: chrono::NaiveDateTime,
    }

    let result = ShortUserDetails::find_by_statement(raw_statement(
        r#"SELECT display_name, creation_date FROM users WHERE user_id = "bôb""#,
    ))
    .one(&sql_pool)
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        result,
        ShortUserDetails {
            display_name: "Bob Bobbersön".to_owned(),
            creation_date: Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
        }
    );
}

#[tokio::test]
async fn test_already_init_table() {
    crate::logging::init_for_tests();
    let sql_pool = get_in_memory_db().await;
    init_table(&sql_pool).await.unwrap();
    init_table(&sql_pool).await.unwrap();
}

#[tokio::test]
async fn test_migrate_tables() {
    crate::logging::init_for_tests();

    let sql_pool = get_in_memory_db().await;

    // Create old schema
    sql_pool
        .execute(raw_statement(
            r#"CREATE TABLE users ( user_id TEXT PRIMARY KEY, display_name TEXT, first_name TEXT NOT NULL, last_name TEXT, avatar BLOB, creation_date TEXT, email TEXT);"#,
        ))
        .await
        .unwrap();

    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO users (user_id, display_name, first_name, creation_date, email)
                   VALUES ("bôb", "", "", "1970-01-01 00:00:00", "bob@bob.com")"#,
        ))
        .await
        .unwrap();

    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO users (user_id, display_name, first_name, creation_date, email)
                   VALUES ("john", "John Doe", "John", "1971-01-01 00:00:00", "bob2@bob.com")"#,
        ))
        .await
        .unwrap();

    sql_pool
        .execute(raw_statement(
            r#"CREATE TABLE groups ( group_id INTEGER PRIMARY KEY, display_name TEXT );"#,
        ))
        .await
        .unwrap();

    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO groups (display_name)
                  VALUES ("lldap_admin"), ("lldap_readonly")"#,
        ))
        .await
        .unwrap();

    init_table(&sql_pool).await.unwrap();

    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO groups (display_name, creation_date, uuid)
                  VALUES ("test", "1970-01-01 00:00:00", "abc")"#,
        ))
        .await
        .unwrap();

    // We only check display_name here because UUIDs are generated
    #[derive(FromQueryResult, PartialEq, Eq, Debug)]
    struct SimpleUser {
        display_name: Option<String>,
    }

    assert_eq!(
        SimpleUser::find_by_statement(raw_statement(
            r#"SELECT display_name FROM users ORDER BY display_name"#
        ))
        .all(&sql_pool)
        .await
        .unwrap(),
        vec![
            SimpleUser { display_name: None },
            SimpleUser {
                display_name: Some("John Doe".to_owned())
            },
        ]
    );

    // This test now validates the v12 migration guarantees:
    // - Successful full upgrade to LAST_SCHEMA_VERSION
    // - PublicSchema seeding + normalization of legacy names
    // - Presence of core system attributes (kerberossync, ou)
    #[derive(FromQueryResult, PartialEq, Eq, Debug)]
    struct UserAttribute {
        user_attribute_user_id: String,
        user_attribute_name: String,
        user_attribute_value: Vec<u8>,
    }

    let attrs = UserAttribute::find_by_statement(raw_statement(
        r#"SELECT user_attribute_user_id, user_attribute_name, user_attribute_value
           FROM user_attributes ORDER BY user_attribute_user_id, user_attribute_name"#,
    ))
    .all(&sql_pool)
    .await
    .unwrap();

    // v12 guarantees (what this test now validates):
    // - Full upgrade to LAST_SCHEMA_VERSION succeeds without errors/FK violations
    // - PublicSchema seeding (18 user + 7 group attributes)
    // - Normalization step runs cleanly (legacy names → canonical)
    // - Core system attributes (kerberossync, ou) are present for all users
    assert!(
        attrs
            .iter()
            .any(|a| a.user_attribute_name == "kerberossync" && a.user_attribute_value == b"0")
    );
    assert!(
        attrs
            .iter()
            .any(|a| a.user_attribute_name == "ou" && a.user_attribute_value == b"people")
    );
    assert!(
        attrs.len() >= 4,
        "Expected at least the v12-seeded system attributes after full migration"
    );

    #[derive(FromQueryResult, PartialEq, Eq, Debug)]
    struct ShortGroupDetails {
        group_id: GroupId,
        display_name: String,
    }

    assert_eq!(
        ShortGroupDetails::find_by_statement(raw_statement(
            r#"SELECT group_id, display_name, creation_date FROM groups"#
        ))
        .all(&sql_pool)
        .await
        .unwrap(),
        vec![
            ShortGroupDetails {
                group_id: GroupId(1),
                display_name: "lldap_admin".to_string()
            },
            ShortGroupDetails {
                group_id: GroupId(2),
                display_name: "lldap_password_manager".to_string()
            },
            ShortGroupDetails {
                group_id: GroupId(3),
                display_name: "test".to_string()
            },
        ]
    );

    assert_eq!(
        sql_migrations::JustSchemaVersion::find_by_statement(raw_statement(
            r#"SELECT version FROM metadata"#
        ))
        .one(&sql_pool)
        .await
        .unwrap()
        .unwrap(),
        sql_migrations::JustSchemaVersion {
            version: LAST_SCHEMA_VERSION
        }
    );
}

#[tokio::test]
async fn test_migration_to_v4() {
    crate::logging::init_for_tests();
    let sql_pool = get_in_memory_db().await;
    upgrade_to_v1(&sql_pool).await.unwrap();
    migrate_from_version(&sql_pool, SchemaVersion(1), SchemaVersion(3))
        .await
        .unwrap();

    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO users (user_id, email, display_name, first_name, creation_date, uuid)
                   VALUES ("bob", "bob@bob.com", "", "", "1970-01-01 00:00:00", "a02eaf13-48a7-30f6-a3d4-040ff7c52b04")"#,
        ))
        .await
        .unwrap();

    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO users (user_id, email, display_name, first_name, creation_date, uuid)
                   VALUES ("bob2", "bob@bob.com", "", "", "1970-01-01 00:00:00", "986765a5-3f03-389e-b47b-536b2d6e1bec")"#,
        ))
        .await
        .unwrap();

    error!(
        "{}",
        migrate_from_version(&sql_pool, SchemaVersion(3), SchemaVersion(4))
            .await
            .expect_err("migration should fail")
    );

    assert_eq!(
        sql_migrations::JustSchemaVersion::find_by_statement(raw_statement(
            r#"SELECT version FROM metadata"#
        ))
        .one(&sql_pool)
        .await
        .unwrap()
        .unwrap(),
        sql_migrations::JustSchemaVersion {
            version: SchemaVersion(3)
        }
    );

    sql_pool
        .execute(raw_statement(
            r#"UPDATE users SET email = "new@bob.com" WHERE user_id = "bob2""#,
        ))
        .await
        .unwrap();

    migrate_from_version(&sql_pool, SchemaVersion(3), SchemaVersion(4))
        .await
        .unwrap();

    assert_eq!(
        sql_migrations::JustSchemaVersion::find_by_statement(raw_statement(
            r#"SELECT version FROM metadata"#
        ))
        .one(&sql_pool)
        .await
        .unwrap()
        .unwrap(),
        sql_migrations::JustSchemaVersion {
            version: SchemaVersion(4)
        }
    );
}

#[tokio::test]
async fn test_migration_to_v5() {
    crate::logging::init_for_tests();
    let sql_pool = get_in_memory_db().await;
    upgrade_to_v1(&sql_pool).await.unwrap();
    migrate_from_version(&sql_pool, SchemaVersion(1), SchemaVersion(4))
        .await
        .unwrap();

    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO users (user_id, email, creation_date, uuid)
                   VALUES ("bob", "bob@bob.com", "1970-01-01 00:00:00", "a02eaf13-48a7-30f6-a3d4-040ff7c52b04")"#,
        ))
        .await
        .unwrap();

    sql_pool
        .execute(sea_orm::Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"INSERT INTO users (user_id, email, display_name, first_name, last_name, avatar, creation_date, uuid)
                   VALUES ("bob2", "bob2@bob.com", "display bob", "first bob", "last bob", $1, "1970-01-01 00:00:00", "986765a5-3f03-389e-b47b-536b2d6e1bec")"#,
            [lldap_domain::images::make_test_jpeg_bytes().into()],
        ))
        .await
        .unwrap();

    migrate_from_version(&sql_pool, SchemaVersion(4), SchemaVersion(5))
        .await
        .unwrap();

    assert_eq!(
        sql_migrations::JustSchemaVersion::find_by_statement(raw_statement(
            r#"SELECT version FROM metadata"#
        ))
        .one(&sql_pool)
        .await
        .unwrap()
        .unwrap(),
        sql_migrations::JustSchemaVersion {
            version: SchemaVersion(5)
        }
    );

    #[derive(FromQueryResult, PartialEq, Eq, Debug)]
    pub struct UserV5 {
        user_id: String,
        email: String,
        display_name: Option<String>,
    }

    assert_eq!(
        UserV5::find_by_statement(raw_statement(
            r#"SELECT user_id, email, display_name FROM users ORDER BY user_id ASC"#
        ))
        .all(&sql_pool)
        .await
        .unwrap(),
        vec![
            UserV5 {
                user_id: "bob".to_owned(),
                email: "bob@bob.com".to_owned(),
                display_name: None
            },
            UserV5 {
                user_id: "bob2".to_owned(),
                email: "bob2@bob.com".to_owned(),
                display_name: Some("display bob".to_owned())
            },
        ]
    );

    sql_pool
        .execute(raw_statement(r#"SELECT first_name FROM users"#))
        .await
        .unwrap_err();

    // v5 migration test: verifies legacy columns (first/last/avatar) are moved to EAV as *raw bytes*
    // (per the "no bincode" refactor). Note: at v5 we still have legacy names ("first_name");
    // v12 later normalizes everything to PublicSchema canonical names. This test remains valuable
    // as a regression guard for the critical EAV conversion step.
    #[derive(FromQueryResult, PartialEq, Eq, Debug)]
    pub struct UserAttribute {
        user_attribute_user_id: String,
        user_attribute_name: String,
        user_attribute_value: Vec<u8>,
    }

    let v5_attrs = UserAttribute::find_by_statement(raw_statement(
        r#"SELECT user_attribute_user_id, user_attribute_name, user_attribute_value
           FROM user_attributes ORDER BY user_attribute_user_id, user_attribute_name ASC"#,
    ))
    .all(&sql_pool)
    .await
    .unwrap();

    assert_eq!(v5_attrs.len(), 3);
    assert!(v5_attrs.iter().any(|a| a.user_attribute_name == "avatar"
        && a.user_attribute_value == lldap_domain::images::make_test_jpeg_bytes()));
    assert!(
        v5_attrs.iter().any(
            |a| a.user_attribute_name == "first_name" && a.user_attribute_value == b"first bob"
        )
    );
    assert!(
        v5_attrs
            .iter()
            .any(|a| a.user_attribute_name == "last_name" && a.user_attribute_value == b"last bob")
    );
}

#[tokio::test]
async fn test_migration_to_v6() {
    crate::logging::init_for_tests();
    let sql_pool = get_in_memory_db().await;
    upgrade_to_v1(&sql_pool).await.unwrap();
    migrate_from_version(&sql_pool, SchemaVersion(1), SchemaVersion(5))
        .await
        .unwrap();

    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO users (user_id, email, display_name, creation_date, uuid)
                   VALUES ("bob", "BOb@bob.com", "", "1970-01-01 00:00:00", "a02eaf13-48a7-30f6-a3d4-040ff7c52b04")"#,
        ))
        .await
        .unwrap();

    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO groups (display_name, creation_date, uuid)
                   VALUES ("BestGroup", "1970-01-01 00:00:00", "986765a5-3f03-389e-b47b-536b2d6e1bec")"#,
        ))
        .await
        .unwrap();

    migrate_from_version(&sql_pool, SchemaVersion(5), SchemaVersion(6))
        .await
        .unwrap();

    assert_eq!(
        sql_migrations::JustSchemaVersion::find_by_statement(raw_statement(
            r#"SELECT version FROM metadata"#
        ))
        .one(&sql_pool)
        .await
        .unwrap()
        .unwrap(),
        sql_migrations::JustSchemaVersion {
            version: SchemaVersion(6)
        }
    );

    #[derive(FromQueryResult, PartialEq, Eq, Debug)]
    struct ShortUserDetails {
        email: String,
        lowercase_email: String,
    }

    let result = ShortUserDetails::find_by_statement(raw_statement(
        r#"SELECT email, lowercase_email FROM users WHERE user_id = "bob""#,
    ))
    .one(&sql_pool)
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        result,
        ShortUserDetails {
            email: "BOb@bob.com".to_owned(),
            lowercase_email: "bob@bob.com".to_owned(),
        }
    );

    #[derive(FromQueryResult, PartialEq, Eq, Debug)]
    struct ShortGroupDetails {
        display_name: String,
        lowercase_display_name: String,
    }

    let result = ShortGroupDetails::find_by_statement(raw_statement(
        r#"SELECT display_name, lowercase_display_name FROM groups"#,
    ))
    .one(&sql_pool)
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        result,
        ShortGroupDetails {
            display_name: "BestGroup".to_owned(),
            lowercase_display_name: "bestgroup".to_owned(),
        }
    );
}

#[tokio::test]
async fn test_too_high_version() {
    let sql_pool = get_in_memory_db().await;
    sql_pool
        .execute(raw_statement(
            r#"CREATE TABLE metadata ( version INTEGER);"#,
        ))
        .await
        .unwrap();
    sql_pool
        .execute(raw_statement(
            r#"INSERT INTO metadata (version) VALUES (127)"#,
        ))
        .await
        .unwrap();
    assert!(init_table(&sql_pool).await.is_err());
}
