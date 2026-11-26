use crate::sql_lockout_handler::numbered;
use sea_orm::{ConnectionTrait, DbErr, Statement, Value};

/// Marks the principal of `name` for the realm's next opening, which removes it whatever user of
/// that name exists by then. A mark already there is kept with its time.
pub(crate) async fn mark_deleted(
    db: &impl ConnectionTrait,
    name: &str,
    at: i64,
) -> Result<(), DbErr> {
    use sea_orm::DbBackend;
    let backend = db.get_database_backend();
    let sql = match backend {
        DbBackend::MySql => {
            "INSERT IGNORE INTO kerberos_delete_marks (principal_name, deleted_at) VALUES (?, ?)"
        }
        DbBackend::Postgres | DbBackend::Sqlite => {
            "INSERT INTO kerberos_delete_marks (principal_name, deleted_at) VALUES (?, ?) \
             ON CONFLICT (principal_name) DO NOTHING"
        }
    };
    let values = [Value::from(name), Value::from(at)];
    let statement = Statement::from_sql_and_values(backend, numbered(backend, sql), values);
    db.execute(statement).await?;
    Ok(())
}

pub(crate) async fn delete_marks(db: &impl ConnectionTrait) -> Result<Vec<String>, DbErr> {
    let backend = db.get_database_backend();
    let sql = "SELECT principal_name FROM kerberos_delete_marks ORDER BY principal_name";
    let rows = db
        .query_all(Statement::from_string(backend, sql.to_owned()))
        .await?;
    rows.iter().map(|row| row.try_get_by_index(0)).collect()
}

pub(crate) async fn clear_delete_mark(db: &impl ConnectionTrait, name: &str) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let sql = "DELETE FROM kerberos_delete_marks WHERE principal_name = ?";
    let values = [Value::from(name)];
    let statement = Statement::from_sql_and_values(backend, numbered(backend, sql), values);
    db.execute(statement).await?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::get_initialized_db;
    use crate::sql_tables::{DbConnection, init_table};
    use pretty_assertions::assert_eq;

    async fn kept(pool: &DbConnection) -> Vec<(String, i64)> {
        let backend = pool.get_database_backend();
        let sql = "SELECT principal_name, deleted_at FROM kerberos_delete_marks \
                   ORDER BY principal_name";
        let rows = pool
            .query_all(Statement::from_string(backend, sql.to_owned()))
            .await
            .unwrap();
        let pair = |row: &sea_orm::QueryResult| -> (String, i64) {
            let name = row.try_get_by_index(0).unwrap();
            (name, row.try_get_by_index(1).unwrap())
        };
        rows.iter().map(pair).collect()
    }

    pub(crate) async fn marks_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        type Step = (&'static str, Vec<(&'static str, i64)>);
        let steps: [Step; 5] = [
            ("mark bob", vec![("bob", 10)]),
            ("mark bob again", vec![("bob", 10)]),
            ("mark ann", vec![("ann", 30), ("bob", 10)]),
            ("clear bob", vec![("ann", 30)]),
            ("clear bob again", vec![("ann", 30)]),
        ];
        for (step, want) in steps {
            match step {
                "mark bob" => mark_deleted(pool, "bob", 10).await.unwrap(),
                "mark bob again" => mark_deleted(pool, "bob", 20).await.unwrap(),
                "mark ann" => mark_deleted(pool, "ann", 30).await.unwrap(),
                _ => clear_delete_mark(pool, "bob").await.unwrap(),
            }
            let want: Vec<_> = want.into_iter().map(|(n, at)| (n.to_owned(), at)).collect();
            let names: Vec<_> = want.iter().map(|(name, _)| name.clone()).collect();
            let read = delete_marks(pool).await.unwrap();
            assert_eq!((kept(pool).await, read), (want, names), "{step}");
        }
        clear_delete_mark(pool, "ann").await.unwrap();
    }

    #[tokio::test]
    async fn test_a_mark_is_kept_once_with_its_first_time_and_cleared_by_name() {
        marks_lane(&get_initialized_db().await).await;
    }
}
