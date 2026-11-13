use crate::sql_tables::DbConnection;
use sea_orm::sqlx::sqlite::{SqliteConnectOptions, SqliteSynchronous};
use sea_orm::{ConnectionTrait, DbBackend, DbErr, FromQueryResult, Statement};

pub const POSTGRESQL_RUNTIME_CONFIG_WAL: &str =
    "https://www.postgresql.org/docs/current/runtime-config-wal.html";
pub const MYSQL_INNODB_FLUSH_LOG_AT_TRX_COMMIT: &str = "https://dev.mysql.com/doc/refman/8.4/en/innodb-parameters.html#sysvar_innodb_flush_log_at_trx_commit";
pub const MYSQL_SYNC_BINLOG: &str = "https://dev.mysql.com/doc/refman/8.4/en/replication-options-binary-log.html#sysvar_sync_binlog";
pub const SQLITE_PRAGMA_SYNCHRONOUS: &str = "https://www.sqlite.org/pragma.html#pragma_synchronous";

pub fn sqlite_extra_synchronous(options: SqliteConnectOptions) -> SqliteConnectOptions {
    options.synchronous(SqliteSynchronous::Extra)
}

pub fn durability_warning(setting: &str, value: &str) -> Option<String> {
    let source = match setting {
        "fsync" | "full_page_writes" | "synchronous_commit" if is_off(value) => {
            POSTGRESQL_RUNTIME_CONFIG_WAL
        }
        "innodb_flush_log_at_trx_commit" if value.trim() != "1" => {
            MYSQL_INNODB_FLUSH_LOG_AT_TRX_COMMIT
        }
        _ => return None,
    };
    Some(format!("database durability: {setting}={value} ({source})"))
}

pub fn sync_binlog_warning(sync_binlog: &str, log_bin: &str) -> Option<String> {
    if !is_on(log_bin) || sync_binlog.trim() == "1" {
        return None;
    }
    Some(format!(
        "database durability: sync_binlog={sync_binlog} ({MYSQL_SYNC_BINLOG})"
    ))
}

fn is_off(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("off")
}

fn is_on(value: &str) -> bool {
    let value = value.trim();
    value == "1" || value.eq_ignore_ascii_case("on")
}

pub async fn warn_database_durability(pool: &DbConnection) -> Result<(), DbErr> {
    match pool.get_database_backend() {
        DbBackend::Sqlite => {
            let name = sqlite_synchronous_name(pool).await?;
            if name != "EXTRA" {
                return Err(DbErr::Custom(format!(
                    "SQLite synchronous is {name}, not EXTRA ({SQLITE_PRAGMA_SYNCHRONOUS})"
                )));
            }
        }
        DbBackend::Postgres => {
            for row in postgres_settings(pool).await? {
                log_warning(&row.name, &row.setting);
            }
        }
        DbBackend::MySql => {
            let row = mysql_settings(pool).await?;
            log_warning(
                "innodb_flush_log_at_trx_commit",
                &row.innodb_flush_log_at_trx_commit,
            );
            if let Some(line) = sync_binlog_warning(&row.sync_binlog, &row.log_bin) {
                tracing::warn!("{line}");
            }
        }
    }
    Ok(())
}

fn log_warning(setting: &str, value: &str) {
    if let Some(line) = durability_warning(setting, value) {
        tracing::warn!("{line}");
    }
}

async fn sqlite_synchronous_name(pool: &DbConnection) -> Result<&'static str, DbErr> {
    #[derive(FromQueryResult)]
    struct Row {
        synchronous: i32,
    }
    let row = Row::find_by_statement(Statement::from_string(
        DbBackend::Sqlite,
        "PRAGMA synchronous".to_owned(),
    ))
    .one(pool)
    .await?
    .ok_or_else(|| DbErr::Custom("PRAGMA synchronous returned no row".to_owned()))?;
    Ok(match row.synchronous {
        0 => "OFF",
        1 => "NORMAL",
        2 => "FULL",
        3 => "EXTRA",
        _ => "UNKNOWN",
    })
}

#[derive(FromQueryResult)]
struct PgSetting {
    name: String,
    setting: String,
}

async fn postgres_settings(pool: &DbConnection) -> Result<Vec<PgSetting>, DbErr> {
    PgSetting::find_by_statement(Statement::from_string(
        DbBackend::Postgres,
        "SELECT name, setting FROM pg_settings WHERE name IN \
         ('fsync', 'full_page_writes', 'synchronous_commit')"
            .to_owned(),
    ))
    .all(pool)
    .await
}

#[derive(FromQueryResult)]
struct MysqlDurability {
    innodb_flush_log_at_trx_commit: String,
    sync_binlog: String,
    log_bin: String,
}

async fn mysql_settings(pool: &DbConnection) -> Result<MysqlDurability, DbErr> {
    MysqlDurability::find_by_statement(Statement::from_string(
        DbBackend::MySql,
        "SELECT CAST(@@innodb_flush_log_at_trx_commit AS CHAR) \
         AS innodb_flush_log_at_trx_commit, \
         CAST(@@sync_binlog AS CHAR) AS sync_binlog, \
         CAST(@@log_bin AS CHAR) AS log_bin"
            .to_owned(),
    ))
    .one(pool)
    .await?
    .ok_or_else(|| DbErr::Custom("MySQL durability settings returned no row".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;

    #[test]
    fn test_warning_table() {
        let cases = [
            ("fsync", "off", Some(POSTGRESQL_RUNTIME_CONFIG_WAL)),
            ("fsync", "on", None),
            (
                "full_page_writes",
                "off",
                Some(POSTGRESQL_RUNTIME_CONFIG_WAL),
            ),
            ("full_page_writes", "ON", None),
            (
                "synchronous_commit",
                "off",
                Some(POSTGRESQL_RUNTIME_CONFIG_WAL),
            ),
            ("synchronous_commit", "local", None),
            ("synchronous_commit", "on", None),
            ("synchronous_commit", "remote_write", None),
            ("synchronous_commit", "remote_apply", None),
            (
                "innodb_flush_log_at_trx_commit",
                "0",
                Some(MYSQL_INNODB_FLUSH_LOG_AT_TRX_COMMIT),
            ),
            (
                "innodb_flush_log_at_trx_commit",
                "2",
                Some(MYSQL_INNODB_FLUSH_LOG_AT_TRX_COMMIT),
            ),
            ("innodb_flush_log_at_trx_commit", "1", None),
            ("sync_binlog", "1", None),
        ];
        for (setting, value, source) in cases {
            match (durability_warning(setting, value), source) {
                (None, None) => {}
                (Some(text), Some(source)) => {
                    assert!(text.contains(&format!("{setting}={value}")), "{text}");
                    assert!(text.contains(source), "{text}");
                }
                (got, expected) => panic!("{setting}={value}: {got:?}, expected {expected:?}"),
            }
        }
        let binlog = [
            ("0", "0", false),
            ("0", "off", false),
            ("1", "0", false),
            ("0", "1", true),
            ("0", "on", true),
            ("1", "1", false),
        ];
        for (sync_binlog, log_bin, warns) in binlog {
            let got = sync_binlog_warning(sync_binlog, log_bin);
            if warns {
                let text = got.expect(sync_binlog);
                assert!(
                    text.contains(&format!("sync_binlog={sync_binlog}")),
                    "{text}"
                );
                assert!(text.contains(MYSQL_SYNC_BINLOG), "{text}");
            } else {
                assert!(got.is_none(), "{sync_binlog} log_bin={log_bin}: {got:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_sqlite_synchronous_is_extra() {
        let path = std::env::temp_dir().join(format!(
            "klldap-sql-b5-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let mut opts = sea_orm::ConnectOptions::new(url.clone());
        opts.max_connections(1)
            .sqlx_logging(false)
            .map_sqlx_sqlite_opts(sqlite_extra_synchronous);
        let pool = Database::connect(opts).await.unwrap();
        warn_database_durability(&pool).await.unwrap();
        let mut full = sea_orm::ConnectOptions::new(url);
        full.max_connections(1)
            .sqlx_logging(false)
            .map_sqlx_sqlite_opts(|o| o.synchronous(SqliteSynchronous::Full));
        let full = Database::connect(full).await.unwrap();
        let refused = warn_database_durability(&full).await.unwrap_err();
        assert!(
            refused.to_string().contains("is FULL, not EXTRA"),
            "{refused}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    #[ignore = "needs KLLDAP_TEST_DATABASE_URL; the live read is the lane's"]
    async fn test_lane_durability_read() {
        let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
            eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
            return;
        };
        let mut opts = sea_orm::ConnectOptions::new(url);
        opts.max_connections(1)
            .sqlx_logging(false)
            .map_sqlx_sqlite_opts(sqlite_extra_synchronous);
        let pool = Database::connect(opts).await.unwrap();
        warn_database_durability(&pool).await.unwrap();
        if pool.get_database_backend() == DbBackend::MySql {
            let row = mysql_settings(&pool).await.unwrap();
            eprintln!(
                "mysql durability: innodb_flush_log_at_trx_commit={} sync_binlog={} log_bin={}",
                row.innodb_flush_log_at_trx_commit, row.sync_binlog, row.log_bin
            );
            assert!(
                durability_warning(
                    "innodb_flush_log_at_trx_commit",
                    &row.innodb_flush_log_at_trx_commit,
                )
                .is_none(),
                "innodb_flush_log_at_trx_commit={}",
                row.innodb_flush_log_at_trx_commit
            );
            assert!(
                sync_binlog_warning(&row.sync_binlog, &row.log_bin).is_none(),
                "sync_binlog={} log_bin={}",
                row.sync_binlog,
                row.log_bin
            );
        }
    }
}
