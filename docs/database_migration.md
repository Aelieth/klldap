# Migration

Migrating **from stock LLDAP** (not between database backends) is
[v0.7-from-lldap.md](migration_guides/v0.7-from-lldap.md).

Existing servers can migrate from one database backend to another. This page includes guidance for migrating from SQLite - similar concepts apply when migrating from databases of other types. SQLite and PostgreSQL are tested in CI. MySQL and MariaDB are tested for the migrations, the Kerberos tables, the conformance suite, a kill of the server after an acknowledged write, and two servers on one database. They are not power-cut tested, and schema changes there are not transactional: back up first.

NOTE: [pgloader](https://github.com/dimitri/pgloader) is a tool that can easily migrate to PostgreSQL from other databases. Consider it if your target database is PostgreSQL

The process is as follows:

1. Create empty schema on target database
2. Stop/pause LLDAP and dump existing values
3. Sanitize for target DB (not always required)
4. Insert data into target
5. Change LLDAP config to new target and restart

The steps below assume you already have PostgreSQL or MySQL set up with an empty database for LLDAP to use.

## Create schema on target

LLDAP has a command that will connect to a target database and initialize the
schema. If running with docker, run the following command to use your active
instance (this has the benefit of ensuring your container has access):

```sh
docker exec -it <LLDAP container name> /app/lldap create_schema -d <Target database url>
```

If it succeeds, you can proceed to the next step.

## Create a dump of existing data

We want to dump (almost) all existing values to some file - the exception being the `metadata` table (and sometimes
the `sqlite_sequence` table, when it exists). Be sure to stop/pause LLDAP during this step, as some
databases (SQLite in this example) will give an error if LLDAP is in the middle of a write. Stop the server
before the dump: a dump from a server that is still running, or that was not stopped cleanly, can leave
`kerberos_realm.open` set, and the moved server then waits out a thirty-five-second watch before it serves.
The dump should consist just INSERT
statements. There are various ways to do this, but a simple enough way is filtering a
whole database dump. This repo contains [a script](../scripts/sqlite_dump_commands.sh) to generate SQLite commands for creating an appropriate dump:

```sh
./sqlite_dump_commands.sh | sqlite3 /path/to/lldap/config/users.db > /path/to/dump.sql
```

The script covers KLLDAP's tables too: `user_object_classes`, `group_object_classes`,
`system_config` (your OUs and POSIX settings) and `logs` (the event history; omit that
table from the dump if you do not want to carry it over). `create_schema` seeds
`system_config` with the defaults, so delete those rows on the target before inserting
the dump (`DELETE FROM system_config;`), or the insert stops on the duplicate
`allowedous` key.

The script also dumps `policies`, `ou_policies`, `kerberos_policies`,
`kerberos_realm`, `kerberos_principals` and `login_lockouts`. It leaves out `totp_steps`:
its rows live minutes, and a moved database starts without them.
The three `kerberos_*`
tables are the Kerberos realm. **The master-key file `.k5.<REALM>` in `kerberos_options.data_dir` must
travel with the database.** Every realm record is sealed under it. If the
database holds the realm and that file is missing, the realm does not open.
The server comes up in the degraded state, and the cause says to restore the
stash from the backup taken with the database. See
[When the realm cannot open](kerberos.md#when-the-realm-cannot-open).

The directory's failed-login counts are the table `login_lockouts` (a lock is computed from a
count and the OU's policy), which the
script dumps; it follows `users`. The other principals' failed-login counts live in the file
`lockout` in that same directory.
Copy it with the database. If the moved database holds the realm and the file
is absent, the realm does not open. The server comes up in the degraded
state, and the cause says the lockout file is missing; restore it, or create
an empty one to count failed logins from zero. A file that cannot be read or
written, or that is not a kerber-rust lockout file, is the same case. An
empty file counts from zero. See
[When the realm cannot open](kerberos.md#when-the-realm-cannot-open).

## Sanitize data

Some databases might use different formats for some data - for example, PostgreSQL uses
a different syntax for hex strings than SQLite. We also want to make sure inserts are done in
a transaction in case one of the statements fail.

### To PostgreSQL

PostgreSQL uses a different hex string format. The command below should switch SQLite
format to PostgreSQL format, and wrap it all in a transaction:

```sh
sed -i -r -e "s/X'([[:xdigit:]]+'[^'])/'\\\x\\1/g" \
-e ":a; s/(INSERT INTO (user_attribute_schema|jwt_storage)\(.*\) VALUES\(.*),1([^']*\);)$/\1,true\3/; s/(INSERT INTO (user_attribute_schema|jwt_storage)\(.*\) VALUES\(.*),0([^']*\);)$/\1,false\3/; ta" \
-e "s/(INSERT INTO logs\(.*\) VALUES\([^,]*,'[^']*','[^']*',)1,/\1true,/; s/(INSERT INTO logs\(.*\) VALUES\([^,]*,'[^']*','[^']*',)0,/\1false,/" \
-e '1s/^/BEGIN;\n/' \
-e '$aSELECT setval(pg_get_serial_sequence('\''groups'\'', '\''group_id'\''), COALESCE((SELECT MAX(group_id) FROM groups), 1));' \
-e '$aSELECT setval(pg_get_serial_sequence('\''logs'\'', '\''id'\''), COALESCE((SELECT MAX(id) FROM logs), 1));' \
-e '$aCOMMIT;' /path/to/dump.sql
```

### To MySQL

MySQL mostly cooperates, but it gets some errors if you don't escape the `groups` table. It also uses
backticks to escape table name instead of quotes. Run the
following command to wrap all table names in backticks for good measure, and wrap the inserts in
a transaction:

```sh
sed -i -r -e 's/^INSERT INTO "?([a-zA-Z0-9_]+)"?/INSERT INTO `\1`/' \
-e '1s/^/START TRANSACTION;\n/' \
-e '$aCOMMIT;' \
-e '1 i\SET FOREIGN_KEY_CHECKS = 0;' /path/to/dump.sql
```

### To MariaDB

While MariaDB is supposed to be identical to MySQL, it doesn't support timezone offsets on DATETIME
strings. Use the following command to remove those and perform the additional MySQL sanitization:

```sh
sed -i -r -e "s/([^']'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9})\+00:00'([^'])/\1'\2/g" \
-e 's/^INSERT INTO "?([a-zA-Z0-9_]+)"?/INSERT INTO `\1`/' \
-e '1s/^/START TRANSACTION;\n/' \
-e '$aCOMMIT;' \
-e '1 i\SET FOREIGN_KEY_CHECKS = 0;' /path/to/dump.sql
```

## Insert data

Insert the data generated from the previous step into the target database. If you encounter errors,
you may need to manually tweak your dump, or make changed in LLDAP and recreate the dump.

### PostgreSQL

`psql -d <database> -U <username> -W < /path/to/dump.sql`

or 

`psql -d <database> -U <username> -W -f /path/to/dump.sql`

### MySQL

`mysql -u <username> -p <database> < /path/to/dump.sql`


## Switch to new database

Modify your `database_url` in `lldap_config.toml` (or `LLDAP_DATABASE_URL` in the env)
to point to your new database (the same value used when generating schema). Start
LLDAP once and check the logs to ensure there were no errors. Check a login and a ticket.

The PostgreSQL path is exercised in CI: the migration lane in
[`.github/workflows/rust.yml`](../.github/workflows/rust.yml) and the `postgres` matrix entry
of [`gate.yml`](../.github/workflows/gate.yml).
