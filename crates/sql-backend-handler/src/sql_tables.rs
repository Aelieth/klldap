use crate::sql_migrations::{Metadata, get_schema_version, migrate_from_version, upgrade_to_v1};
use sea_orm::{
    ConnectionTrait, DeriveValueType, Iden, QueryResult, TryGetable, Value, sea_query::Query,
};
use serde::{Deserialize, Serialize};

pub type DbConnection = sea_orm::DatabaseConnection;

#[derive(Copy, PartialEq, Eq, Debug, Clone, PartialOrd, Ord, DeriveValueType)]
pub struct SchemaVersion(pub i16);

pub const LAST_SCHEMA_VERSION: SchemaVersion = SchemaVersion(13);

#[derive(Copy, PartialEq, Eq, Debug, Clone, PartialOrd, Ord)]
pub struct PrivateKeyHash(pub [u8; 32]);

impl TryGetable for PrivateKeyHash {
    fn try_get(res: &QueryResult, pre: &str, col: &str) -> Result<Self, sea_orm::TryGetError> {
        let index = format!("{pre}{col}");
        Self::try_get_by(res, index.as_str())
    }

    fn try_get_by_index(res: &QueryResult, index: usize) -> Result<Self, sea_orm::TryGetError> {
        Self::try_get_by(res, index)
    }

    fn try_get_by<I: sea_orm::ColIdx>(
        res: &QueryResult,
        index: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        Ok(PrivateKeyHash(
            std::convert::TryInto::<[u8; 32]>::try_into(res.try_get_by::<Vec<u8>, I>(index)?)
                .unwrap(),
        ))
    }
}

impl From<PrivateKeyHash> for Value {
    fn from(val: PrivateKeyHash) -> Self {
        Self::from(val.0.to_vec())
    }
}

pub async fn init_table(pool: &DbConnection) -> anyhow::Result<()> {
    let version = {
        if let Some(version) = get_schema_version(pool).await {
            version
        } else {
            upgrade_to_v1(pool).await?;
            SchemaVersion(1)
        }
    };
    migrate_from_version(pool, version, LAST_SCHEMA_VERSION).await?;
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ConfigLocation {
    ConfigFile(String),
    EnvironmentVariable(String),
    CommandLine,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum PrivateKeyLocation {
    KeySeed(ConfigLocation),
    KeyFile(ConfigLocation, std::ffi::OsString),
    Default,
    Tests,
}

#[derive(Debug)]
pub struct PrivateKeyInfo {
    pub private_key_hash: PrivateKeyHash,
    pub private_key_location: PrivateKeyLocation,
}

pub async fn get_private_key_info(pool: &DbConnection) -> anyhow::Result<Option<PrivateKeyInfo>> {
    let result = pool
        .query_one(
            pool.get_database_backend().build(
                Query::select()
                    .column(Metadata::PrivateKeyHash)
                    .column(Metadata::PrivateKeyLocation)
                    .from(Metadata::Table),
            ),
        )
        .await?;
    let result = match result {
        None => return Ok(None),
        Some(r) => r,
    };
    if let Ok(hash) = result.try_get("", &Metadata::PrivateKeyHash.to_string()) {
        Ok(Some(PrivateKeyInfo {
            private_key_hash: hash,
            private_key_location: serde_json::from_str(
                &result.try_get::<String>("", &Metadata::PrivateKeyLocation.to_string())?,
            )?,
        }))
    } else {
        Ok(None)
    }
}

pub async fn set_private_key_info(pool: &DbConnection, info: PrivateKeyInfo) -> anyhow::Result<()> {
    pool.execute(
        pool.get_database_backend().build(
            Query::update()
                .table(Metadata::Table)
                .value(Metadata::PrivateKeyHash, Value::from(info.private_key_hash))
                .value(
                    Metadata::PrivateKeyLocation,
                    Value::from(serde_json::to_string(&info.private_key_location).unwrap()),
                ),
        ),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
