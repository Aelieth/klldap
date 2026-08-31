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
use tracing::{debug, error, info, instrument, warn};

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

#[derive(DeriveIden, Clone, Copy)]
pub(crate) enum Policies {
    Table,
    Id,
    Name,
    LowercaseName,
    Description,
    Items,
}

#[derive(DeriveIden, Clone, Copy)]
pub(crate) enum OuPolicies {
    Table,
    OuKey,
    PolicyId,
    BlockInheritance,
}

#[derive(DeriveIden, Clone, Copy)]
pub(crate) enum Logs {
    Table,
    Id,
    Timestamp,
    Kind,
    Success,
    Protocol,
    Actor,
    Target,
    Peer,
    ForwardedFor,
    Detail,
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
                // Alias name and raw bytes, as a v5-era database holds them.
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
                // Raw JPEG bytes, as a v5-era database holds them.
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

    // Config data: seed the default only where no row exists, never overwrite user edits.
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

// Table via the same probe as ensure_column. Indexes are always try-created in a
// savepoint: MySQL's builder drops IF NOT EXISTS on indexes, so a missing-table-only
// path would leave a crashed half-create without them forever.
async fn ensure_logs(
    transaction: &DatabaseTransaction,
    backend: sea_orm::DbBackend,
) -> Result<(), DbErr> {
    let savepoint = transaction.begin().await?;
    let probe = savepoint
        .execute(backend.build(Query::select().expr(1).from(Logs::Table).limit(1)))
        .await;
    savepoint.rollback().await?;
    if probe.is_err() {
        transaction
            .execute(
                backend.build(
                    Table::create()
                        .table(Logs::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(Logs::Id)
                                .big_integer()
                                .auto_increment()
                                .not_null()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(Logs::Timestamp).date_time().not_null())
                        .col(ColumnDef::new(Logs::Kind).string_len(32).not_null())
                        .col(ColumnDef::new(Logs::Success).boolean().not_null())
                        .col(ColumnDef::new(Logs::Protocol).string_len(8).not_null())
                        .col(ColumnDef::new(Logs::Actor).string_len(255).null())
                        .col(ColumnDef::new(Logs::Target).string_len(255).null())
                        .col(ColumnDef::new(Logs::Peer).string_len(64).null())
                        .col(ColumnDef::new(Logs::ForwardedFor).string_len(255).null())
                        .col(ColumnDef::new(Logs::Detail).text().null()),
                ),
            )
            .await?;
    }
    ensure_index(
        transaction,
        backend,
        Index::create()
            .name("logs-timestamp")
            .table(Logs::Table)
            .col(Logs::Timestamp)
            .to_owned(),
    )
    .await?;
    // Each lookup column pairs with the timestamp: actor activity, kind boards, target
    // history and per-address counts all become one range seek.
    for (name, column) in [
        ("logs-actor", Logs::Actor),
        ("logs-kind", Logs::Kind),
        ("logs-target", Logs::Target),
        ("logs-peer", Logs::Peer),
    ] {
        ensure_index(
            transaction,
            backend,
            Index::create()
                .name(name)
                .table(Logs::Table)
                .col(column)
                .col(Logs::Timestamp)
                .to_owned(),
        )
        .await?;
    }
    Ok(())
}

async fn ensure_policies(
    transaction: &DatabaseTransaction,
    backend: sea_orm::DbBackend,
) -> Result<(), DbErr> {
    let savepoint = transaction.begin().await?;
    let probe = savepoint
        .execute(backend.build(Query::select().expr(1).from(Policies::Table).limit(1)))
        .await;
    savepoint.rollback().await?;
    if probe.is_err() {
        transaction
            .execute(
                backend.build(
                    Table::create()
                        .table(Policies::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(Policies::Id)
                                .integer()
                                .auto_increment()
                                .not_null()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(Policies::Name).string_len(255).not_null())
                        .col(
                            ColumnDef::new(Policies::LowercaseName)
                                .string_len(255)
                                .not_null(),
                        )
                        .col(ColumnDef::new(Policies::Description).text().not_null())
                        .col(ColumnDef::new(Policies::Items).text().not_null()),
                ),
            )
            .await?;
    }
    let savepoint = transaction.begin().await?;
    let probe = savepoint
        .execute(backend.build(Query::select().expr(1).from(OuPolicies::Table).limit(1)))
        .await;
    savepoint.rollback().await?;
    if probe.is_err() {
        transaction
            .execute(
                backend.build(
                    Table::create()
                        .table(OuPolicies::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(OuPolicies::OuKey)
                                .string_len(255)
                                .not_null()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(OuPolicies::PolicyId).integer().null())
                        .col(
                            ColumnDef::new(OuPolicies::BlockInheritance)
                                .boolean()
                                .not_null()
                                .default(false),
                        ),
                ),
            )
            .await?;
    }
    ensure_index(
        transaction,
        backend,
        Index::create()
            .name("unique-policy-lower-name")
            .table(Policies::Table)
            .col(Policies::LowercaseName)
            .unique()
            .to_owned(),
    )
    .await?;
    ensure_index(
        transaction,
        backend,
        Index::create()
            .name("ou-policies-policy-id")
            .table(OuPolicies::Table)
            .col(OuPolicies::PolicyId)
            .to_owned(),
    )
    .await?;
    Ok(())
}

async fn ensure_index(
    transaction: &DatabaseTransaction,
    backend: sea_orm::DbBackend,
    index: sea_orm::sea_query::IndexCreateStatement,
) -> Result<(), DbErr> {
    let savepoint = transaction.begin().await?;
    match savepoint.execute(backend.build(&index)).await {
        Ok(_) => savepoint.commit().await,
        Err(e) => {
            debug!("Index left as is: {e}");
            savepoint.rollback().await
        }
    }
}

// v13 is the pre-release schema: databases already stamped 13 pick up its later additions
// at the next boot instead of through a new version.
pub(crate) async fn ensure_v13_additions(pool: &DbConnection) -> Result<(), DbErr> {
    let transaction = pool.begin().await?;
    let backend = transaction.get_database_backend();
    ensure_logs(&transaction, backend).await?;
    ensure_policies(&transaction, backend).await?;
    transaction.commit().await
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
// untouched (native raw values, and anything unrecognized, which is only warned about).
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

    // Preserve true/false as 1/0. Compare as bytes: lower() on a blob is invalid on Postgres.
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
// Re-encodes bincode values and JpegPhoto schema rows arriving from an upstream database
// into KLLDAP's raw formats; native rows are no-ops, so it is idempotent on fresh chains.
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
    ensure_logs(&transaction, backend).await?;
    ensure_policies(&transaction, backend).await?;

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
mod tests;
