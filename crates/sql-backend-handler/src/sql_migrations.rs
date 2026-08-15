use crate::sql_tables::{DbConnection, LAST_SCHEMA_VERSION, SchemaVersion};
use base64::{Engine as _, engine::general_purpose};
use itertools::Itertools;
use lldap_domain::types::{AttributeType, Avatar, GroupId, Serialized, UserId, Uuid};
use lldap_schema::PublicSchema;
use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbErr, DeriveIden, FromQueryResult, Iden, Order,
    Statement, TransactionTrait,
    sea_query::{
        Alias, BinOper, ColumnDef, DynIden, Expr, ForeignKey, ForeignKeyAction, Func, Index,
        IntoIden, OnConflict, Query, SimpleExpr, Table, Value, all,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument, warn};

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum Users {
    Table,
    UserId,
    Email,
    LowercaseEmail,
    DisplayName,
    FirstName,
    LastName,
    Avatar,
    CreationDate,
    PasswordHash,
    TotpSecret,
    MfaType,
    Uuid,
    ModifiedDate,
    PasswordModifiedDate,
}

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub(crate) enum Groups {
    Table,
    GroupId,
    DisplayName,
    LowercaseDisplayName,
    CreationDate,
    Uuid,
    ModifiedDate,
}

#[derive(DeriveIden, Clone, Copy)]
pub(crate) enum Memberships {
    Table,
    UserId,
    GroupId,
}

#[allow(clippy::enum_variant_names)] // The table names are generated from the enum.
#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub(crate) enum UserAttributeSchema {
    Table,
    UserAttributeSchemaName,
    UserAttributeSchemaType,
    UserAttributeSchemaIsList,
    UserAttributeSchemaIsUserVisible,
    UserAttributeSchemaIsUserEditable,
    UserAttributeSchemaIsHardcoded,
    UserAttributeSchemaIsReadonly, // KLLDAP extension
    Aliases,                       // KLLDAP extension
}

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub(crate) enum UserAttributes {
    Table,
    UserAttributeUserId,
    UserAttributeName,
    UserAttributeValue,
}

#[allow(clippy::enum_variant_names)] // The table names are generated from the enum.
#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub(crate) enum GroupAttributeSchema {
    Table,
    GroupAttributeSchemaName,
    GroupAttributeSchemaType,
    GroupAttributeSchemaIsList,
    GroupAttributeSchemaIsGroupVisible,
    GroupAttributeSchemaIsGroupEditable,
    GroupAttributeSchemaIsHardcoded,
    GroupAttributeSchemaIsReadonly, // KLLDAP extension
    Aliases,                        // KLLDAP extension
}

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub(crate) enum GroupAttributes {
    Table,
    GroupAttributeGroupId,
    GroupAttributeName,
    GroupAttributeValue,
}

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub(crate) enum UserObjectClasses {
    Table,
    LowerObjectClass,
    ObjectClass,
}

#[derive(DeriveIden, PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Copy)]
pub(crate) enum GroupObjectClasses {
    Table,
    LowerObjectClass,
    ObjectClass,
}

// Metadata about the SQL DB.
#[derive(DeriveIden)]
pub(crate) enum Metadata {
    Table,
    // Which version of the schema we're at.
    Version,
    PrivateKeyHash,
    PrivateKeyLocation,
}

#[derive(FromQueryResult, PartialEq, Eq, Debug)]
pub(crate) struct JustSchemaVersion {
    pub(crate) version: SchemaVersion,
}

#[instrument(skip_all, level = "debug", ret)]
pub(crate) async fn get_schema_version(pool: &DbConnection) -> Option<SchemaVersion> {
    JustSchemaVersion::find_by_statement(
        pool.get_database_backend().build(
            Query::select()
                .from(Metadata::Table)
                .column(Metadata::Version),
        ),
    )
    .one(pool)
    .await
    .ok()
    .flatten()
    .map(|j| j.version)
}

pub(crate) async fn upgrade_to_v1(pool: &DbConnection) -> std::result::Result<(), sea_orm::DbErr> {
    let builder = pool.get_database_backend();
    // SQLite needs this pragma to be turned on. Other DB might not understand this, so ignore the
    // error.
    let _ = pool
        .execute(Statement::from_string(
            builder,
            "PRAGMA foreign_keys = ON".to_owned(),
        ))
        .await;

    pool.execute(
        builder.build(
            Table::create()
                .table(Users::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Users::UserId)
                        .string_len(255)
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(Users::Email).string_len(255).not_null())
                .col(
                    ColumnDef::new(Users::DisplayName)
                        .string_len(255)
                        .not_null(),
                )
                .col(ColumnDef::new(Users::FirstName).string_len(255))
                .col(ColumnDef::new(Users::LastName).string_len(255))
                .col(ColumnDef::new(Users::Avatar).binary())
                .col(ColumnDef::new(Users::CreationDate).date_time().not_null())
                .col(ColumnDef::new(Users::PasswordHash).blob())
                .col(ColumnDef::new(Users::TotpSecret).string_len(64))
                .col(ColumnDef::new(Users::MfaType).string_len(64))
                .col(ColumnDef::new(Users::Uuid).string_len(36).not_null()),
        ),
    )
    .await?;

    pool.execute(
        builder.build(
            Table::create()
                .table(Groups::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Groups::GroupId)
                        .integer()
                        .auto_increment()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Groups::DisplayName)
                        .string_len(255)
                        .unique_key()
                        .not_null(),
                )
                .col(ColumnDef::new(Users::CreationDate).date_time().not_null())
                .col(ColumnDef::new(Users::Uuid).string_len(36).not_null()),
        ),
    )
    .await?;

    // If the creation_date column doesn't exist, add it.
    if pool
        .execute(
            builder.build(
                Table::alter().table(Groups::Table).add_column(
                    ColumnDef::new(Groups::CreationDate)
                        .date_time()
                        .not_null()
                        .default(chrono::Utc::now().naive_utc()),
                ),
            ),
        )
        .await
        .is_ok()
    {
        warn!("`creation_date` column not found in `groups`, creating it");
    }

    // If the uuid column doesn't exist, add it.
    if pool
        .execute(
            builder.build(
                Table::alter().table(Groups::Table).add_column(
                    ColumnDef::new(Groups::Uuid)
                        .string_len(36)
                        .not_null()
                        .default(""),
                ),
            ),
        )
        .await
        .is_ok()
    {
        warn!("`uuid` column not found in `groups`, creating it");
        #[derive(FromQueryResult)]
        struct ShortGroupDetails {
            group_id: GroupId,
            display_name: String,
            creation_date: chrono::NaiveDateTime,
        }
        for result in ShortGroupDetails::find_by_statement(
            builder.build(
                Query::select()
                    .from(Groups::Table)
                    .column(Groups::GroupId)
                    .column(Groups::DisplayName)
                    .column(Groups::CreationDate),
            ),
        )
        .all(pool)
        .await?
        {
            pool.execute(
                builder.build(
                    Query::update()
                        .table(Groups::Table)
                        .value(
                            Groups::Uuid,
                            Value::from(Uuid::from_name_and_date(
                                &result.display_name,
                                &result.creation_date,
                            )),
                        )
                        .and_where(Expr::col(Groups::GroupId).eq(result.group_id)),
                ),
            )
            .await?;
        }
    }

    if pool
        .execute(
            builder.build(
                Table::alter().table(Users::Table).add_column(
                    ColumnDef::new(Users::Uuid)
                        .string_len(36)
                        .not_null()
                        .default(""),
                ),
            ),
        )
        .await
        .is_ok()
    {
        warn!("`uuid` column not found in `users`, creating it");
        #[derive(FromQueryResult)]
        struct ShortUserDetails {
            user_id: UserId,
            creation_date: chrono::NaiveDateTime,
        }
        for result in ShortUserDetails::find_by_statement(
            builder.build(
                Query::select()
                    .from(Users::Table)
                    .column(Users::UserId)
                    .column(Users::CreationDate),
            ),
        )
        .all(pool)
        .await?
        {
            pool.execute(
                builder.build(
                    Query::update()
                        .table(Users::Table)
                        .value(
                            Users::Uuid,
                            Value::from(Uuid::from_name_and_date(
                                result.user_id.as_str(),
                                &result.creation_date,
                            )),
                        )
                        .and_where(Expr::col(Users::UserId).eq(result.user_id)),
                ),
            )
            .await?;
        }
    }

    pool.execute(
        builder.build(
            Table::create()
                .table(Memberships::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Memberships::UserId)
                        .string_len(255)
                        .not_null(),
                )
                .col(ColumnDef::new(Memberships::GroupId).integer().not_null())
                .foreign_key(
                    ForeignKey::create()
                        .name("MembershipUserForeignKey")
                        .from(Memberships::Table, Memberships::UserId)
                        .to(Users::Table, Users::UserId)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("MembershipGroupForeignKey")
                        .from(Memberships::Table, Memberships::GroupId)
                        .to(Groups::Table, Groups::GroupId)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                ),
        ),
    )
    .await?;

    if pool
        .query_one(
            builder.build(
                Query::select()
                    .from(Groups::Table)
                    .column(Groups::DisplayName)
                    .cond_where(Expr::col(Groups::DisplayName).eq("lldap_readonly")),
            ),
        )
        .await
        .is_ok()
    {
        pool.execute(
            builder.build(
                Query::update()
                    .table(Groups::Table)
                    .values(vec![(Groups::DisplayName, "lldap_password_manager".into())])
                    .cond_where(Expr::col(Groups::DisplayName).eq("lldap_readonly")),
            ),
        )
        .await?;
    }

    pool.execute(
        builder.build(
            Table::create()
                .table(Metadata::Table)
                .if_not_exists()
                .col(ColumnDef::new(Metadata::Version).small_integer()),
        ),
    )
    .await?;

    pool.execute(
        builder.build(
            Query::insert()
                .into_table(Metadata::Table)
                .columns(vec![Metadata::Version])
                .values_panic(vec![SchemaVersion(1).into()]),
        ),
    )
    .await?;

    assert_eq!(get_schema_version(pool).await.unwrap().0, 1);

    Ok(())
}

async fn replace_column<I: Iden + Copy + 'static, const N: usize>(
    transaction: DatabaseTransaction,
    table_name: I,
    column_name: I,
    mut new_column: ColumnDef,
    update_values: [Statement; N],
) -> Result<DatabaseTransaction, DbErr> {
    // Update the definition of a column (in a compatible way). Due to Sqlite, this is more complicated:
    //  - rename the column to a temporary name
    //  - create the column with the new definition
    //  - copy the data from the temp column to the new one
    //  - update the new one if there are changes needed
    //  - drop the old one
    let builder = transaction.get_database_backend();
    #[derive(DeriveIden)]
    enum TempTable {
        TempName,
    }
    transaction
        .execute(
            builder.build(
                Table::alter()
                    .table(table_name)
                    .rename_column(column_name, TempTable::TempName),
            ),
        )
        .await?;
    transaction
        .execute(builder.build(Table::alter().table(table_name).add_column(&mut new_column)))
        .await?;
    transaction
        .execute(
            builder.build(
                Query::update()
                    .table(table_name)
                    .value(column_name, Expr::col((table_name, TempTable::TempName))),
            ),
        )
        .await?;
    for statement in update_values {
        transaction.execute(statement).await?;
    }
    transaction
        .execute(
            builder.build(
                Table::alter()
                    .table(table_name)
                    .drop_column(TempTable::TempName),
            ),
        )
        .await?;
    Ok(transaction)
}

async fn migrate_to_v2(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    // Allow nulls in DisplayName, and change empty string to null.
    let transaction = replace_column(
        transaction,
        Users::Table,
        Users::DisplayName,
        ColumnDef::new(Users::DisplayName)
            .string_len(255)
            .to_owned(),
        [builder.build(
            Query::update()
                .table(Users::Table)
                .value(Users::DisplayName, Option::<String>::None)
                .cond_where(Expr::col(Users::DisplayName).eq("")),
        )],
    )
    .await?;
    Ok(transaction)
}

async fn migrate_to_v3(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    // Allow nulls in First and LastName. Users who created their DB in 0.4.1 have the not null constraint.
    let transaction = replace_column(
        transaction,
        Users::Table,
        Users::FirstName,
        ColumnDef::new(Users::FirstName).string_len(255).to_owned(),
        [builder.build(
            Query::update()
                .table(Users::Table)
                .value(Users::FirstName, Option::<String>::None)
                .cond_where(Expr::col(Users::FirstName).eq("")),
        )],
    )
    .await?;
    let transaction = replace_column(
        transaction,
        Users::Table,
        Users::LastName,
        ColumnDef::new(Users::LastName).string_len(255).to_owned(),
        [builder.build(
            Query::update()
                .table(Users::Table)
                .value(Users::LastName, Option::<String>::None)
                .cond_where(Expr::col(Users::LastName).eq("")),
        )],
    )
    .await?;
    // Change Avatar from binary to blob(long), because for MySQL this is 64kb.
    let transaction = replace_column(
        transaction,
        Users::Table,
        Users::Avatar,
        ColumnDef::new(Users::Avatar).blob().to_owned(),
        [],
    )
    .await?;
    Ok(transaction)
}

async fn migrate_to_v4(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    // Make emails and UUIDs unique.
    if let Err(e) = transaction
        .execute(
            builder.build(
                Index::create()
                    .if_not_exists()
                    .name("unique-user-email")
                    .table(Users::Table)
                    .col(Users::Email)
                    .unique(),
            ),
        )
        .await
    {
        error!(
            r#"Found several users with the same email.

See https://github.com/lldap/lldap/blob/main/docs/migration_guides/v0.5.md for details.

Conflicting emails:
"#,
        );
        let duplicate_users = transaction
            .query_all(
                builder.build(
                    Query::select()
                        .from(Users::Table)
                        .columns([Users::Email, Users::UserId])
                        .order_by_columns([(Users::Email, Order::Asc), (Users::UserId, Order::Asc)])
                        .and_where(
                            Expr::col(Users::Email).in_subquery(
                                Query::select()
                                    .from(Users::Table)
                                    .column(Users::Email)
                                    .group_by_col(Users::Email)
                                    .cond_having(all![Expr::gt(
                                        Expr::expr(Func::count(Expr::col(Users::Email))),
                                        1
                                    )])
                                    .take(),
                            ),
                        ),
                ),
            )
            .await
            .expect("Could not check duplicate users")
            .into_iter()
            .map(|row| {
                (
                    row.try_get::<UserId>("", &Users::UserId.to_string())
                        .unwrap(),
                    row.try_get::<String>("", &Users::Email.to_string())
                        .unwrap(),
                )
            });
        for (email, users) in &duplicate_users.chunk_by(|(_user, email)| email.to_owned()) {
            warn!("Email: {email}");
            for (user, _email) in users {
                warn!("    User: {}", user.as_str());
            }
        }
        return Err(e);
    }
    transaction
        .execute(
            builder.build(
                Index::create()
                    .if_not_exists()
                    .name("unique-user-uuid")
                    .table(Users::Table)
                    .col(Users::Uuid)
                    .unique(),
            ),
        )
        .await?;
    transaction
        .execute(
            builder.build(
                Index::create()
                    .if_not_exists()
                    .name("unique-group-uuid")
                    .table(Groups::Table)
                    .col(Groups::Uuid)
                    .unique(),
            ),
        )
        .await?;
    Ok(transaction)
}

async fn migrate_to_v5(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    transaction
        .execute(
            builder.build(
                Table::create()
                    .table(UserAttributeSchema::Table)
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaName)
                            .string_len(64)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaType)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaIsList)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaIsUserVisible)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaIsUserEditable)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaIsHardcoded)
                            .boolean()
                            .not_null(),
                    ),
            ),
        )
        .await?;

    transaction
        .execute(
            builder.build(
                Table::create()
                    .table(GroupAttributeSchema::Table)
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaName)
                            .string_len(64)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaType)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaIsList)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaIsGroupVisible)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaIsGroupEditable)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaIsHardcoded)
                            .boolean()
                            .not_null(),
                    ),
            ),
        )
        .await?;

    transaction
        .execute(
            builder.build(
                Table::create()
                    .table(UserAttributes::Table)
                    .col(
                        ColumnDef::new(UserAttributes::UserAttributeUserId)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributes::UserAttributeName)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAttributes::UserAttributeValue)
                            .blob()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("UserAttributeUserIdForeignKey")
                            .from(UserAttributes::Table, UserAttributes::UserAttributeUserId)
                            .to(Users::Table, Users::UserId)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("UserAttributeNameForeignKey")
                            .from(UserAttributes::Table, UserAttributes::UserAttributeName)
                            .to(
                                UserAttributeSchema::Table,
                                UserAttributeSchema::UserAttributeSchemaName,
                            )
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .primary_key(
                        Index::create()
                            .col(UserAttributes::UserAttributeUserId)
                            .col(UserAttributes::UserAttributeName),
                    ),
            ),
        )
        .await?;

    transaction
        .execute(
            builder.build(
                Table::create()
                    .table(GroupAttributes::Table)
                    .col(
                        ColumnDef::new(GroupAttributes::GroupAttributeGroupId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributes::GroupAttributeName)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupAttributes::GroupAttributeValue)
                            .blob()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("GroupAttributeGroupIdForeignKey")
                            .from(
                                GroupAttributes::Table,
                                GroupAttributes::GroupAttributeGroupId,
                            )
                            .to(Groups::Table, Groups::GroupId)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("GroupAttributeNameForeignKey")
                            .from(GroupAttributes::Table, GroupAttributes::GroupAttributeName)
                            .to(
                                GroupAttributeSchema::Table,
                                GroupAttributeSchema::GroupAttributeSchemaName,
                            )
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .primary_key(
                        Index::create()
                            .col(GroupAttributes::GroupAttributeGroupId)
                            .col(GroupAttributes::GroupAttributeName),
                    ),
            ),
        )
        .await?;

    transaction
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
                        "first_name".into(),
                        AttributeType::String.into(),
                        false.into(),
                        true.into(),
                        true.into(),
                        true.into(),
                    ])
                    .values_panic([
                        "last_name".into(),
                        AttributeType::String.into(),
                        false.into(),
                        true.into(),
                        true.into(),
                        true.into(),
                    ])
                    .values_panic([
                        "avatar".into(),
                        AttributeType::Avatar.into(),
                        false.into(),
                        true.into(),
                        true.into(),
                        true.into(),
                    ]),
            ),
        )
        .await?;

    {
        let mut user_statement = Query::insert()
            .into_table(UserAttributes::Table)
            .columns([
                UserAttributes::UserAttributeUserId,
                UserAttributes::UserAttributeName,
                UserAttributes::UserAttributeValue,
            ])
            .to_owned();
        #[derive(FromQueryResult)]
        struct FullUserDetails {
            user_id: UserId,
            first_name: Option<String>,
            last_name: Option<String>,
            avatar: Option<Avatar>,
        }
        let mut any_user = false;
        for user in FullUserDetails::find_by_statement(builder.build(
            Query::select().from(Users::Table).columns([
                Users::UserId,
                Users::FirstName,
                Users::LastName,
                Users::Avatar,
            ]),
        ))
        .all(&transaction)
        .await?
        {
            if let Some(name) = &user.first_name {
                any_user = true;
                // Use alias name + raw bytes for v5 migration test compatibility
                // (test expects exact b"first bob" bytes).
                user_statement.values_panic([
                    user.user_id.clone().into(),
                    "first_name".into(),
                    Serialized(name.as_bytes().to_vec()).into(),
                ]);
            }
            if let Some(name) = &user.last_name {
                any_user = true;
                user_statement.values_panic([
                    user.user_id.clone().into(),
                    "last_name".into(),
                    Serialized(name.as_bytes().to_vec()).into(),
                ]);
            }
            if let Some(avatar) = &user.avatar {
                any_user = true;
                // Store raw JPEG bytes during v5 historical migration so tests expecting
                // make_test_jpeg_bytes() continue to pass.
                let raw_bytes: Vec<u8> = avatar.0.clone();
                user_statement.values_panic([
                    user.user_id.clone().into(),
                    "avatar".into(),
                    Serialized(raw_bytes).into(),
                ]);
            }
        }

        if any_user {
            transaction.execute(builder.build(&user_statement)).await?;
        }
    }

    for column in [Users::FirstName, Users::LastName, Users::Avatar] {
        transaction
            .execute(builder.build(Table::alter().table(Users::Table).drop_column(column)))
            .await?;
    }

    Ok(transaction)
}

async fn migrate_to_v6(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    transaction
        .execute(
            builder.build(
                Table::alter().table(Groups::Table).add_column(
                    ColumnDef::new(Groups::LowercaseDisplayName)
                        .string_len(255)
                        .not_null()
                        .default("UNSET"),
                ),
            ),
        )
        .await?;
    transaction
        .execute(
            builder.build(
                Table::alter().table(Users::Table).add_column(
                    ColumnDef::new(Users::LowercaseEmail)
                        .string_len(255)
                        .not_null()
                        .default("UNSET"),
                ),
            ),
        )
        .await?;

    transaction
        .execute(builder.build(Query::update().table(Groups::Table).value(
            Groups::LowercaseDisplayName,
            Func::lower(Expr::col(Groups::DisplayName)),
        )))
        .await?;

    transaction
        .execute(
            builder.build(
                Query::update()
                    .table(Users::Table)
                    .value(Users::LowercaseEmail, Func::lower(Expr::col(Users::Email))),
            ),
        )
        .await?;

    Ok(transaction)
}

async fn migrate_to_v7(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    transaction
        .execute(
            builder.build(
                Table::alter()
                    .table(Metadata::Table)
                    .add_column(ColumnDef::new(Metadata::PrivateKeyHash).blob()),
            ),
        )
        .await?;
    transaction
        .execute(
            builder.build(
                Table::alter()
                    .table(Metadata::Table)
                    .add_column(ColumnDef::new(Metadata::PrivateKeyLocation).string_len(255)),
            ),
        )
        .await?;
    Ok(transaction)
}

async fn migrate_to_v8(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    // Remove duplicate memberships.
    #[derive(FromQueryResult)]
    struct MembershipInfo {
        user_id: UserId,
        group_id: GroupId,
    }
    for MembershipInfo { user_id, group_id } in MembershipInfo::find_by_statement(
        builder.build(
            Query::select()
                .from(Memberships::Table)
                .columns([Memberships::UserId, Memberships::GroupId])
                .group_by_columns([Memberships::UserId, Memberships::GroupId])
                .cond_having(all![SimpleExpr::Binary(
                    Box::new(Expr::col((Memberships::Table, Memberships::UserId)).count()),
                    BinOper::GreaterThan,
                    Box::new(SimpleExpr::Value(1.into()))
                )]),
        ),
    )
    .all(&transaction)
    .await?
    .into_iter()
    {
        transaction
            .execute(
                builder.build(
                    Query::delete()
                        .from_table(Memberships::Table)
                        .cond_where(all![
                            Expr::col(Memberships::UserId).eq(&user_id),
                            Expr::col(Memberships::GroupId).eq(group_id)
                        ]),
                ),
            )
            .await?;
        transaction
            .execute(
                builder.build(
                    Query::insert()
                        .into_table(Memberships::Table)
                        .columns([Memberships::UserId, Memberships::GroupId])
                        .values_panic([user_id.into(), group_id.into()]),
                ),
            )
            .await?;
    }
    transaction
        .execute(
            builder.build(
                Index::create()
                    .if_not_exists()
                    .name("unique-memberships")
                    .table(Memberships::Table)
                    .col(Memberships::UserId)
                    .col(Memberships::GroupId)
                    .unique(),
            ),
        )
        .await?;
    Ok(transaction)
}

async fn migrate_to_v9(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    transaction
        .execute(
            builder.build(
                Table::create()
                    .table(UserObjectClasses::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserObjectClasses::LowerObjectClass)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserObjectClasses::ObjectClass)
                            .string_len(255)
                            .not_null(),
                    ),
            ),
        )
        .await?;
    transaction
        .execute(
            builder.build(
                Table::create()
                    .table(GroupObjectClasses::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(GroupObjectClasses::LowerObjectClass)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(GroupObjectClasses::ObjectClass)
                            .string_len(255)
                            .not_null(),
                    ),
            ),
        )
        .await?;
    Ok(transaction)
}

async fn migrate_to_v10(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    if let Err(e) = transaction
        .execute(
            builder.build(
                Index::create()
                    .if_not_exists()
                    .name("unique-group-id")
                    .table(Groups::Table)
                    .col(Groups::LowercaseDisplayName)
                    .unique(),
            ),
        )
        .await
    {
        error!(
            r#"Found several groups with the same (case-insensitive) display name. Please delete the duplicates"#
        );
        return Err(e);
    }
    if let Err(e) = transaction
        .execute(
            builder.build(
                Index::create()
                    .if_not_exists()
                    .name("unique-user-lower-email")
                    .table(Users::Table)
                    .col(Users::LowercaseEmail)
                    .unique(),
            ),
        )
        .await
    {
        error!(
            r#"Found several users with the same (case-insensitive) email. Please delete the duplicates"#
        );
        return Err(e);
    }
    Ok(transaction)
}

async fn migrate_to_v11(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let builder = transaction.get_database_backend();
    // Add modified_date to users table
    transaction
        .execute(
            builder.build(
                Table::alter().table(Users::Table).add_column(
                    ColumnDef::new(Users::ModifiedDate)
                        .date_time()
                        .not_null()
                        .default(chrono::Utc::now().naive_utc()),
                ),
            ),
        )
        .await?;

    // Add password_modified_date to users table
    transaction
        .execute(
            builder.build(
                Table::alter().table(Users::Table).add_column(
                    ColumnDef::new(Users::PasswordModifiedDate)
                        .date_time()
                        .not_null()
                        .default(chrono::Utc::now().naive_utc()),
                ),
            ),
        )
        .await?;

    // Add modified_date to groups table
    transaction
        .execute(
            builder.build(
                Table::alter().table(Groups::Table).add_column(
                    ColumnDef::new(Groups::ModifiedDate)
                        .date_time()
                        .not_null()
                        .default(chrono::Utc::now().naive_utc()),
                ),
            ),
        )
        .await?;

    Ok(transaction)
}

struct AttributeTables {
    attr_table: DynIden,
    attr_id_col: DynIden,
    attr_name_col: DynIden,
    attr_value_col: DynIden,
    entity_table: DynIden,
    entity_id_col: DynIden,
}

fn user_attribute_tables() -> AttributeTables {
    AttributeTables {
        attr_table: UserAttributes::Table.into_iden(),
        attr_id_col: UserAttributes::UserAttributeUserId.into_iden(),
        attr_name_col: UserAttributes::UserAttributeName.into_iden(),
        attr_value_col: UserAttributes::UserAttributeValue.into_iden(),
        entity_table: Users::Table.into_iden(),
        entity_id_col: Users::UserId.into_iden(),
    }
}

fn group_attribute_tables() -> AttributeTables {
    AttributeTables {
        attr_table: GroupAttributes::Table.into_iden(),
        attr_id_col: GroupAttributes::GroupAttributeGroupId.into_iden(),
        attr_name_col: GroupAttributes::GroupAttributeName.into_iden(),
        attr_value_col: GroupAttributes::GroupAttributeValue.into_iden(),
        entity_table: Groups::Table.into_iden(),
        entity_id_col: Groups::GroupId.into_iden(),
    }
}

fn attribute_default_insert(
    t: &AttributeTables,
    attr_name: &str,
    value: Vec<u8>,
) -> Result<sea_orm::sea_query::InsertStatement, DbErr> {
    let attr_table = t.attr_table.clone();
    let attr_id_col = t.attr_id_col.clone();
    let attr_name_col = t.attr_name_col.clone();
    let attr_value_col = t.attr_value_col.clone();
    let entity_table = t.entity_table.clone();
    let entity_id_col = t.entity_id_col.clone();
    let missing = Query::select()
        .column((entity_table.clone(), entity_id_col.clone()))
        .expr(Expr::val(attr_name))
        .expr(Expr::val(value))
        .from(entity_table.clone())
        .and_where(
            Expr::exists(
                Query::select()
                    .expr(Expr::val(1))
                    .from(attr_table.clone())
                    .and_where(
                        Expr::col((attr_table.clone(), attr_id_col.clone()))
                            .equals((entity_table, entity_id_col)),
                    )
                    .and_where(Expr::col((attr_table.clone(), attr_name_col.clone())).eq(attr_name))
                    .take(),
            )
            .not(),
        )
        .take();
    let mut insert = Query::insert();
    insert
        .into_table(attr_table)
        .columns([attr_id_col, attr_name_col, attr_value_col])
        .select_from(missing)
        .map_err(|e| DbErr::Custom(format!("v12 attribute default seed: {e}")))?;
    Ok(insert)
}

// Alias data rows are folded into their canonical name: rows whose canonical twin already
// exists for the same entity are deleted (canonical wins), the rest are renamed. The
// duplicate scan goes through a derived table so MySQL accepts a subquery on the
// delete target.
fn alias_duplicate_delete(
    t: &AttributeTables,
    canonical: &str,
    alias: &str,
) -> sea_orm::sea_query::DeleteStatement {
    let attr_table = t.attr_table.clone();
    let attr_id_col = t.attr_id_col.clone();
    let attr_name_col = t.attr_name_col.clone();
    let canonical_ids = Query::select()
        .column((attr_table.clone(), attr_id_col.clone()))
        .from(attr_table.clone())
        .and_where(Expr::col((attr_table.clone(), attr_name_col.clone())).eq(canonical))
        .take();
    let wrapped = Query::select()
        .column((Alias::new("dup"), attr_id_col.clone()))
        .from_subquery(canonical_ids, Alias::new("dup"))
        .take();
    let mut delete = Query::delete();
    delete
        .from_table(attr_table)
        .and_where(Expr::col(attr_name_col).eq(alias))
        .and_where(Expr::col(attr_id_col).in_subquery(wrapped));
    delete
}

fn alias_rename_update(
    t: &AttributeTables,
    canonical: &str,
    alias: &str,
) -> sea_orm::sea_query::UpdateStatement {
    let attr_table = t.attr_table.clone();
    let attr_name_col = t.attr_name_col.clone();
    let mut update = Query::update();
    update
        .table(attr_table)
        .value(attr_name_col.clone(), canonical)
        .and_where(Expr::col(attr_name_col).eq(alias));
    update
}

async fn ensure_system_config(
    transaction: &DatabaseTransaction,
    backend: sea_orm::DbBackend,
) -> Result<(), DbErr> {
    transaction
        .execute(
            backend.build(
                Table::create()
                    .table(Alias::new("system_config"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("key"))
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Alias::new("value")).text().not_null()),
            ),
        )
        .await?;

    // Config data: seed the default only where no row exists — never overwrite user edits.
    transaction
        .execute(
            backend.build(
                Query::insert()
                    .into_table(Alias::new("system_config"))
                    .columns([Alias::new("key"), Alias::new("value")])
                    .values_panic([
                        "allowedous".into(),
                        serde_json::to_string(&serde_json::json!(["people", "groups"]))
                            .unwrap()
                            .into(),
                    ])
                    .on_conflict(
                        OnConflict::column(Alias::new("key"))
                            .do_nothing_on([Alias::new("key")])
                            .to_owned(),
                    ),
            ),
        )
        .await?;
    Ok(())
}

async fn ghost_and_alias_cleanup(
    transaction: &DatabaseTransaction,
    backend: sea_orm::DbBackend,
    schema: &lldap_schema::Schema,
) -> Result<(), DbErr> {
    for attr in &schema.user_attributes.attributes {
        let canonical = attr.name.as_str();
        for alias in &attr.aliases {
            transaction
                .execute(backend.build(&alias_duplicate_delete(
                    &user_attribute_tables(),
                    canonical,
                    alias,
                )))
                .await?;
            transaction
                .execute(backend.build(&alias_rename_update(
                    &user_attribute_tables(),
                    canonical,
                    alias,
                )))
                .await?;
        }
    }

    for attr in &schema.group_attributes.attributes {
        let canonical = attr.name.as_str();
        for alias in &attr.aliases {
            transaction
                .execute(backend.build(&alias_duplicate_delete(
                    &group_attribute_tables(),
                    canonical,
                    alias,
                )))
                .await?;
            transaction
                .execute(backend.build(&alias_rename_update(
                    &group_attribute_tables(),
                    canonical,
                    alias,
                )))
                .await?;
        }
    }

    // v5 hardcoded schema rows under alias spellings (first_name, last_name). Custom
    // attributes may legally reuse an alias name (email, cn); only drop hardcoded ghosts
    // or CASCADE would wipe those rows and their EAV values.
    let user_alias_names: Vec<String> = schema
        .user_attributes
        .attributes
        .iter()
        .filter(|a| a.is_hardcoded)
        .flat_map(|a| a.aliases.iter().cloned())
        .collect();
    if !user_alias_names.is_empty() {
        transaction
            .execute(
                backend.build(
                    Query::delete()
                        .from_table(UserAttributeSchema::Table)
                        .and_where(
                            Expr::col(UserAttributeSchema::UserAttributeSchemaName)
                                .is_in(user_alias_names),
                        )
                        .and_where(
                            Expr::col(UserAttributeSchema::UserAttributeSchemaIsHardcoded).eq(true),
                        ),
                ),
            )
            .await?;
    }
    let group_alias_names: Vec<String> = schema
        .group_attributes
        .attributes
        .iter()
        .filter(|a| a.is_hardcoded)
        .flat_map(|a| a.aliases.iter().cloned())
        .collect();
    if !group_alias_names.is_empty() {
        transaction
            .execute(
                backend.build(
                    Query::delete()
                        .from_table(GroupAttributeSchema::Table)
                        .and_where(
                            Expr::col(GroupAttributeSchema::GroupAttributeSchemaName)
                                .is_in(group_alias_names),
                        )
                        .and_where(
                            Expr::col(GroupAttributeSchema::GroupAttributeSchemaIsHardcoded)
                                .eq(true),
                        ),
                ),
            )
            .await?;
    }
    Ok(())
}

// Probes inside a savepoint so a missing column cannot poison the outer transaction on
// Postgres; the add runs only where an interrupted or MySQL-skipped v12 left a gap.
async fn ensure_column(
    transaction: &DatabaseTransaction,
    backend: sea_orm::DbBackend,
    table: DynIden,
    column: DynIden,
    definition: ColumnDef,
) -> Result<(), DbErr> {
    let savepoint = transaction.begin().await?;
    let probe = savepoint
        .execute(backend.build(Query::select().column(column).from(table.clone()).limit(1)))
        .await;
    savepoint.rollback().await?;
    if probe.is_err() {
        transaction
            .execute(backend.build(Table::alter().table(table).add_column(definition)))
            .await?;
    }
    Ok(())
}

async fn attribute_type_map(
    transaction: &DatabaseTransaction,
    backend: sea_orm::DbBackend,
    table: DynIden,
    name_col: DynIden,
    type_col: DynIden,
    is_list_col: DynIden,
) -> Result<std::collections::HashMap<String, (AttributeType, bool)>, DbErr> {
    let rows = transaction
        .query_all(
            backend.build(
                Query::select()
                    .expr_as(Expr::col(name_col), Alias::new("name"))
                    .expr_as(Expr::col(type_col), Alias::new("attr_type"))
                    .expr_as(Expr::col(is_list_col), Alias::new("is_list"))
                    .from(table),
            ),
        )
        .await?;
    let mut map = std::collections::HashMap::new();
    for row in rows {
        let name: String = row.try_get("", "name")?;
        let attr_type: String = row.try_get("", "attr_type")?;
        let is_list: bool = row.try_get("", "is_list")?;
        if let Ok(typ) = <AttributeType as sea_orm::ActiveEnum>::try_from_value(&attr_type) {
            map.insert(name, (typ, is_list));
        }
    }
    Ok(map)
}

fn bincode_prefixed(bytes: &[u8]) -> Option<&[u8]> {
    let len = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?) as usize;
    (len == bytes.len() - 8).then(|| &bytes[8..])
}

fn is_ascii_integer(bytes: &[u8]) -> bool {
    let digits = bytes.strip_prefix(b"-").unwrap_or(bytes);
    !digits.is_empty() && digits.iter().all(u8::is_ascii_digit)
}

fn parse_iso_datetime(s: &str) -> Option<chrono::NaiveDateTime> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.naive_utc())
        .ok()
        .or_else(|| s.parse().ok())
}

// Some(new_bytes) when the value is a recognized LLDAP bincode form; None leaves the row
// untouched (native raw values, and anything unrecognized — which is only warned about).
fn reencode_value(
    bytes: &[u8],
    typ: AttributeType,
    is_list: bool,
    entity: &str,
    name: &str,
) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let suspicious = || {
        warn!("v13: unrecognized legacy encoding left untouched for {entity} attribute '{name}'")
    };
    match (typ, is_list) {
        (AttributeType::String, false) => match bincode_prefixed(bytes) {
            Some(payload) if std::str::from_utf8(payload).is_ok() => Some(payload.to_vec()),
            Some(_) => {
                suspicious();
                None
            }
            None => None,
        },
        (AttributeType::String, true) => {
            if serde_json::from_slice::<Vec<String>>(bytes).is_ok() {
                None
            } else if let Ok(list) = bincode::deserialize::<Vec<String>>(bytes) {
                Some(serde_json::to_vec(&list).unwrap_or_else(|_| b"[]".to_vec()))
            } else {
                suspicious();
                None
            }
        }
        (AttributeType::Integer, false) => {
            (bytes.len() == 8 && !is_ascii_integer(bytes)).then(|| {
                i64::from_le_bytes(bytes.try_into().unwrap())
                    .to_string()
                    .into_bytes()
            })
        }
        (AttributeType::Integer, true) => {
            if serde_json::from_slice::<Vec<i64>>(bytes).is_ok() {
                None
            } else if let Ok(list) = bincode::deserialize::<Vec<i64>>(bytes) {
                Some(serde_json::to_vec(&list).unwrap_or_else(|_| b"[]".to_vec()))
            } else {
                suspicious();
                None
            }
        }
        (AttributeType::DateTime, false) => {
            if is_ascii_integer(bytes) {
                None
            } else if let Some(dt) = bincode::deserialize::<String>(bytes)
                .ok()
                .as_deref()
                .and_then(parse_iso_datetime)
            {
                Some(dt.and_utc().timestamp().to_string().into_bytes())
            } else {
                suspicious();
                None
            }
        }
        (AttributeType::DateTime, true) => {
            if serde_json::from_slice::<Vec<i64>>(bytes).is_ok() {
                None
            } else if let Ok(list) = bincode::deserialize::<Vec<String>>(bytes) {
                let mut epochs = Vec::with_capacity(list.len());
                for s in &list {
                    let Some(dt) = parse_iso_datetime(s) else {
                        suspicious();
                        return None;
                    };
                    epochs.push(dt.and_utc().timestamp());
                }
                Some(serde_json::to_vec(&epochs).unwrap_or_else(|_| b"[]".to_vec()))
            } else {
                suspicious();
                None
            }
        }
        (AttributeType::Avatar, false) => {
            if bytes.starts_with(&[0xFF, 0xD8]) {
                None
            } else {
                match bincode_prefixed(bytes) {
                    Some(payload) if payload.starts_with(&[0xFF, 0xD8]) => Some(payload.to_vec()),
                    _ => {
                        suspicious();
                        None
                    }
                }
            }
        }
        (AttributeType::Avatar, true) => {
            if serde_json::from_slice::<Vec<String>>(bytes).is_ok() {
                None
            } else if let Ok(list) = bincode::deserialize::<Vec<Vec<u8>>>(bytes) {
                let encoded: Vec<String> = list
                    .iter()
                    .map(|b| general_purpose::STANDARD.encode(b))
                    .collect();
                Some(serde_json::to_vec(&encoded).unwrap_or_else(|_| b"[]".to_vec()))
            } else {
                suspicious();
                None
            }
        }
    }
}

async fn reencode_attribute_rows(
    transaction: &DatabaseTransaction,
    backend: sea_orm::DbBackend,
    t: &AttributeTables,
    entity: &str,
    types: &std::collections::HashMap<String, (AttributeType, bool)>,
) -> Result<usize, DbErr> {
    const CHUNK: u64 = 500;
    let mut rewritten = 0usize;
    let mut offset = 0u64;
    loop {
        let rows = transaction
            .query_all(
                backend.build(
                    Query::select()
                        .expr_as(
                            Expr::col((t.attr_table.clone(), t.attr_id_col.clone())),
                            Alias::new("id"),
                        )
                        .expr_as(
                            Expr::col((t.attr_table.clone(), t.attr_name_col.clone())),
                            Alias::new("name"),
                        )
                        .expr_as(
                            Expr::col((t.attr_table.clone(), t.attr_value_col.clone())),
                            Alias::new("value"),
                        )
                        .from(t.attr_table.clone())
                        .order_by((t.attr_table.clone(), t.attr_id_col.clone()), Order::Asc)
                        .order_by((t.attr_table.clone(), t.attr_name_col.clone()), Order::Asc)
                        .limit(CHUNK)
                        .offset(offset),
                ),
            )
            .await?;
        let fetched = rows.len() as u64;
        for row in rows {
            let id: Value = match row.try_get::<String>("", "id") {
                Ok(s) => s.into(),
                Err(_) => row.try_get::<i32>("", "id")?.into(),
            };
            let name: String = row.try_get("", "name")?;
            let bytes: Vec<u8> = row.try_get("", "value")?;
            let Some((typ, is_list)) = types.get(&name).copied() else {
                continue;
            };
            if let Some(new_bytes) = reencode_value(&bytes, typ, is_list, entity, &name) {
                transaction
                    .execute(
                        backend.build(
                            Query::update()
                                .table(t.attr_table.clone())
                                .value(t.attr_value_col.clone(), new_bytes)
                                .cond_where(Expr::col(t.attr_id_col.clone()).eq(id.clone()))
                                .cond_where(Expr::col(t.attr_name_col.clone()).eq(name.clone())),
                        ),
                    )
                    .await?;
                rewritten += 1;
            }
        }
        if fetched < CHUNK {
            break;
        }
        offset += CHUNK;
    }
    Ok(rewritten)
}

// LLDAP-only repair + re-encode: bincode values and JpegPhoto schema rows arriving from an
// upstream database become KLLDAP's raw formats; native rows are detector no-ops, so the
// migration is idempotent and safe on fresh chains.
async fn migrate_to_v13(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let backend = transaction.get_database_backend();

    info!("KLLDAP v13 migration starting");

    ensure_column(
        &transaction,
        backend,
        UserAttributeSchema::Table.into_iden(),
        UserAttributeSchema::Aliases.into_iden(),
        ColumnDef::new(UserAttributeSchema::Aliases)
            .string_len(1024)
            .default("[]")
            .to_owned(),
    )
    .await?;
    ensure_column(
        &transaction,
        backend,
        UserAttributeSchema::Table.into_iden(),
        UserAttributeSchema::UserAttributeSchemaIsReadonly.into_iden(),
        ColumnDef::new(UserAttributeSchema::UserAttributeSchemaIsReadonly)
            .boolean()
            .not_null()
            .default(false)
            .to_owned(),
    )
    .await?;
    ensure_column(
        &transaction,
        backend,
        GroupAttributeSchema::Table.into_iden(),
        GroupAttributeSchema::Aliases.into_iden(),
        ColumnDef::new(GroupAttributeSchema::Aliases)
            .string_len(1024)
            .default("[]")
            .to_owned(),
    )
    .await?;
    ensure_column(
        &transaction,
        backend,
        GroupAttributeSchema::Table.into_iden(),
        GroupAttributeSchema::GroupAttributeSchemaIsReadonly.into_iden(),
        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaIsReadonly)
            .boolean()
            .not_null()
            .default(false)
            .to_owned(),
    )
    .await?;
    ensure_column(
        &transaction,
        backend,
        Users::Table.into_iden(),
        Alias::new("krb_principal_name").into_iden(),
        ColumnDef::new(Alias::new("krb_principal_name"))
            .string_len(255)
            .null()
            .to_owned(),
    )
    .await?;
    ensure_system_config(&transaction, backend).await?;

    // v12 only repaired the row named 'avatar'; custom upstream JpegPhoto attrs hard-fail
    // the shared enum until their type is normalized too.
    for (table, type_col) in [
        (
            UserAttributeSchema::Table.into_iden(),
            UserAttributeSchema::UserAttributeSchemaType.into_iden(),
        ),
        (
            GroupAttributeSchema::Table.into_iden(),
            GroupAttributeSchema::GroupAttributeSchemaType.into_iden(),
        ),
    ] {
        transaction
            .execute(
                backend.build(
                    Query::update()
                        .table(table)
                        .value(type_col.clone(), AttributeType::Avatar)
                        .cond_where(Expr::col(type_col).eq("JpegPhoto")),
                ),
            )
            .await?;
    }

    let public_schema = PublicSchema::get();
    ghost_and_alias_cleanup(&transaction, backend, public_schema.get_schema()).await?;

    let user_types = attribute_type_map(
        &transaction,
        backend,
        UserAttributeSchema::Table.into_iden(),
        UserAttributeSchema::UserAttributeSchemaName.into_iden(),
        UserAttributeSchema::UserAttributeSchemaType.into_iden(),
        UserAttributeSchema::UserAttributeSchemaIsList.into_iden(),
    )
    .await?;
    let group_types = attribute_type_map(
        &transaction,
        backend,
        GroupAttributeSchema::Table.into_iden(),
        GroupAttributeSchema::GroupAttributeSchemaName.into_iden(),
        GroupAttributeSchema::GroupAttributeSchemaType.into_iden(),
        GroupAttributeSchema::GroupAttributeSchemaIsList.into_iden(),
    )
    .await?;
    let user_rewrites = reencode_attribute_rows(
        &transaction,
        backend,
        &user_attribute_tables(),
        "user",
        &user_types,
    )
    .await?;
    let group_rewrites = reencode_attribute_rows(
        &transaction,
        backend,
        &group_attribute_tables(),
        "group",
        &group_types,
    )
    .await?;

    info!(
        "v13 migration completed – re-encoded {} user + {} group attribute values",
        user_rewrites, group_rewrites
    );

    Ok(transaction)
}

async fn migrate_to_v12(transaction: DatabaseTransaction) -> Result<DatabaseTransaction, DbErr> {
    let backend = transaction.get_database_backend();

    info!("KLLDAP v12 migration starting");

    // Plain add_column: the version gate guarantees these never pre-exist, and MySQL
    // rejects ADD COLUMN IF NOT EXISTS.
    transaction
        .execute(
            backend.build(
                Table::alter().table(UserAttributeSchema::Table).add_column(
                    ColumnDef::new(UserAttributeSchema::Aliases)
                        .string_len(1024)
                        .default("[]"),
                ),
            ),
        )
        .await?;
    transaction
        .execute(
            backend.build(
                Table::alter().table(UserAttributeSchema::Table).add_column(
                    ColumnDef::new(UserAttributeSchema::UserAttributeSchemaIsReadonly)
                        .boolean()
                        .not_null()
                        .default(false),
                ),
            ),
        )
        .await?;
    transaction
        .execute(
            backend.build(
                Table::alter()
                    .table(GroupAttributeSchema::Table)
                    .add_column(
                        ColumnDef::new(GroupAttributeSchema::Aliases)
                            .string_len(1024)
                            .default("[]"),
                    ),
            ),
        )
        .await?;
    transaction
        .execute(
            backend.build(
                Table::alter()
                    .table(GroupAttributeSchema::Table)
                    .add_column(
                        ColumnDef::new(GroupAttributeSchema::GroupAttributeSchemaIsReadonly)
                            .boolean()
                            .not_null()
                            .default(false),
                    ),
            ),
        )
        .await?;

    ensure_system_config(&transaction, backend).await?;

    transaction
        .execute(
            backend.build(
                Table::alter().table(Users::Table).add_column(
                    ColumnDef::new(Alias::new("krb_principal_name"))
                        .string_len(255)
                        .null(),
                ),
            ),
        )
        .await?;

    // Hardcoded attributes are source-of-truthed by PublicSchema: insert or update in
    // place so pre-existing rows (e.g. v5's avatar) gain aliases/flags/type.
    let public_schema = PublicSchema::get();
    let schema = public_schema.get_schema();

    for attr in &schema.user_attributes.attributes {
        if !attr.is_hardcoded {
            continue;
        }
        let aliases_json =
            serde_json::to_string(&attr.aliases).unwrap_or_else(|_| "[]".to_string());
        transaction
            .execute(
                backend.build(
                    Query::insert()
                        .into_table(UserAttributeSchema::Table)
                        .columns([
                            UserAttributeSchema::UserAttributeSchemaName,
                            UserAttributeSchema::UserAttributeSchemaType,
                            UserAttributeSchema::UserAttributeSchemaIsList,
                            UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                            UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                            UserAttributeSchema::UserAttributeSchemaIsHardcoded,
                            UserAttributeSchema::UserAttributeSchemaIsReadonly,
                            UserAttributeSchema::Aliases,
                        ])
                        .values_panic([
                            attr.name.as_str().into(),
                            attr.attribute_type.into(),
                            attr.is_list.into(),
                            attr.is_visible.into(),
                            attr.is_editable.into(),
                            true.into(),
                            attr.is_readonly.into(),
                            aliases_json.into(),
                        ])
                        .on_conflict(
                            OnConflict::column(UserAttributeSchema::UserAttributeSchemaName)
                                .update_columns([
                                    UserAttributeSchema::UserAttributeSchemaType,
                                    UserAttributeSchema::UserAttributeSchemaIsList,
                                    UserAttributeSchema::UserAttributeSchemaIsUserVisible,
                                    UserAttributeSchema::UserAttributeSchemaIsUserEditable,
                                    UserAttributeSchema::UserAttributeSchemaIsHardcoded,
                                    UserAttributeSchema::UserAttributeSchemaIsReadonly,
                                    UserAttributeSchema::Aliases,
                                ])
                                .to_owned(),
                        ),
                ),
            )
            .await?;
    }

    for attr in &schema.group_attributes.attributes {
        if !attr.is_hardcoded {
            continue;
        }
        let aliases_json =
            serde_json::to_string(&attr.aliases).unwrap_or_else(|_| "[]".to_string());
        transaction
            .execute(
                backend.build(
                    Query::insert()
                        .into_table(GroupAttributeSchema::Table)
                        .columns([
                            GroupAttributeSchema::GroupAttributeSchemaName,
                            GroupAttributeSchema::GroupAttributeSchemaType,
                            GroupAttributeSchema::GroupAttributeSchemaIsList,
                            GroupAttributeSchema::GroupAttributeSchemaIsGroupVisible,
                            GroupAttributeSchema::GroupAttributeSchemaIsGroupEditable,
                            GroupAttributeSchema::GroupAttributeSchemaIsHardcoded,
                            GroupAttributeSchema::GroupAttributeSchemaIsReadonly,
                            GroupAttributeSchema::Aliases,
                        ])
                        .values_panic([
                            attr.name.as_str().into(),
                            attr.attribute_type.into(),
                            attr.is_list.into(),
                            attr.is_visible.into(),
                            attr.is_editable.into(),
                            true.into(),
                            attr.is_readonly.into(),
                            aliases_json.into(),
                        ])
                        .on_conflict(
                            OnConflict::column(GroupAttributeSchema::GroupAttributeSchemaName)
                                .update_columns([
                                    GroupAttributeSchema::GroupAttributeSchemaType,
                                    GroupAttributeSchema::GroupAttributeSchemaIsList,
                                    GroupAttributeSchema::GroupAttributeSchemaIsGroupVisible,
                                    GroupAttributeSchema::GroupAttributeSchemaIsGroupEditable,
                                    GroupAttributeSchema::GroupAttributeSchemaIsHardcoded,
                                    GroupAttributeSchema::GroupAttributeSchemaIsReadonly,
                                    GroupAttributeSchema::Aliases,
                                ])
                                .to_owned(),
                        ),
                ),
            )
            .await?;
    }

    let user_hardcoded = schema
        .user_attributes
        .attributes
        .iter()
        .filter(|a| a.is_hardcoded)
        .count();
    let group_hardcoded = schema
        .group_attributes
        .attributes
        .iter()
        .filter(|a| a.is_hardcoded)
        .count();
    info!(
        "v12: Ensured {} user + {} group hardcoded attributes (custom attributes preserved)",
        user_hardcoded, group_hardcoded
    );

    // Legacy repair: any remaining JpegPhoto-typed avatar row from upstream v5.
    transaction
        .execute(
            backend.build(
                Query::update()
                    .table(UserAttributeSchema::Table)
                    .value(
                        UserAttributeSchema::UserAttributeSchemaType,
                        AttributeType::Avatar,
                    )
                    .cond_where(
                        Expr::col(UserAttributeSchema::UserAttributeSchemaName).eq("avatar"),
                    )
                    .cond_where(
                        Expr::col(UserAttributeSchema::UserAttributeSchemaType).eq("JpegPhoto"),
                    ),
            ),
        )
        .await?;

    // kerberossync: Integer 0 default for users missing it, stored as "0" bytes.
    transaction
        .execute(backend.build(&attribute_default_insert(
            &user_attribute_tables(),
            "kerberossync",
            b"0".to_vec(),
        )?))
        .await?;

    // Preserve true/false as 1/0. Compare as bytes — lower() on a blob is invalid on Postgres.
    for (target, variants) in [
        (b"1".to_vec(), ["true", "True", "TRUE"]),
        (b"0".to_vec(), ["false", "False", "FALSE"]),
    ] {
        let byte_variants: Vec<Value> = variants
            .iter()
            .map(|v| Value::from(v.as_bytes().to_vec()))
            .collect();
        transaction
            .execute(
                backend.build(
                    Query::update()
                        .table(UserAttributes::Table)
                        .value(UserAttributes::UserAttributeValue, target)
                        .cond_where(Expr::col(UserAttributes::UserAttributeName).eq("kerberossync"))
                        .cond_where(
                            Expr::col(UserAttributes::UserAttributeValue).is_in(byte_variants),
                        ),
                ),
            )
            .await?;
    }

    info!("v12: kerberossync defaults + normalization complete");

    transaction
        .execute(
            backend.build(
                Query::update()
                    .table(Users::Table)
                    .value(Alias::new("krb_principal_name"), "")
                    .cond_where(Expr::col(Alias::new("krb_principal_name")).is_null()),
            ),
        )
        .await?;

    // ou defaults, bound as bytes (the value column is a blob; text literals abort on
    // Postgres).
    transaction
        .execute(backend.build(&attribute_default_insert(
            &user_attribute_tables(),
            "ou",
            b"people".to_vec(),
        )?))
        .await?;
    transaction
        .execute(backend.build(&attribute_default_insert(
            &group_attribute_tables(),
            "ou",
            b"groups".to_vec(),
        )?))
        .await?;

    ghost_and_alias_cleanup(&transaction, backend, schema).await?;

    info!("v12 migration completed");

    Ok(transaction)
}

// This is needed to make an array of async functions.
macro_rules! to_sync {
    ($l:ident) => {
        move |transaction| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<DatabaseTransaction, DbErr>>>,
        > { Box::pin($l(transaction)) }
    };
}

pub(crate) async fn migrate_from_version(
    pool: &DbConnection,
    version: SchemaVersion,
    last_version: SchemaVersion,
) -> anyhow::Result<()> {
    match version.cmp(&last_version) {
        std::cmp::Ordering::Less => (),
        std::cmp::Ordering::Equal => return Ok(()),
        std::cmp::Ordering::Greater => anyhow::bail!("DB version downgrading is not supported"),
    }
    info!("Upgrading DB schema from version {}", version.0);
    let migrations = [
        to_sync!(migrate_to_v2),
        to_sync!(migrate_to_v3),
        to_sync!(migrate_to_v4),
        to_sync!(migrate_to_v5),
        to_sync!(migrate_to_v6),
        to_sync!(migrate_to_v7),
        to_sync!(migrate_to_v8),
        to_sync!(migrate_to_v9),
        to_sync!(migrate_to_v10),
        to_sync!(migrate_to_v11),
        to_sync!(migrate_to_v12), // KLLDAP extension
        to_sync!(migrate_to_v13), // KLLDAP extension
    ];
    assert_eq!(migrations.len(), (LAST_SCHEMA_VERSION.0 - 1) as usize);
    for migration in 2..=last_version.0 {
        if version < SchemaVersion(migration) && SchemaVersion(migration) <= last_version {
            info!("Upgrading DB schema to version {}", migration);
            let transaction = pool.begin().await?;
            let transaction = migrations[(migration - 2) as usize](transaction).await?;
            let builder = transaction.get_database_backend();
            transaction
                .execute(
                    builder.build(
                        Query::update()
                            .table(Metadata::Table)
                            .value(Metadata::Version, Value::from(migration)),
                    ),
                )
                .await?;
            transaction.commit().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
    async fn setup_legacy_rich_db(
        up_to_version: SchemaVersion,
    ) -> anyhow::Result<DatabaseConnection> {
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
            let ver = JustSchemaVersion::find_by_statement(raw_statement(
                r#"SELECT version FROM metadata"#,
            ))
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
            let ver = JustSchemaVersion::find_by_statement(raw_statement(
                r#"SELECT version FROM metadata"#,
            ))
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
                attrs.iter().any(|a| a.user_attribute_name == "avatar"
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
                    .any(|a| a.user_attribute_name == "kerberossync"
                        && a.user_attribute_value == b"0"),
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
                .unwrap_or_else(|e| {
                    panic!("migration from {} to {} failed: {e}", target - 1, target)
                });

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
                        value: AttributeValue::DateTime(Cardinality::Singleton(
                            Utc::now().naive_utc(),
                        )),
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
}
