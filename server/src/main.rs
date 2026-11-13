#![forbid(unsafe_code)]
#![forbid(non_ascii_idents)]

mod auth_service;
mod cli;
mod configuration;
mod database_string;
mod db_cleaner;
mod graphql_server;
mod healthcheck;
mod jwt_sql_tables;
mod ldap_server;
mod logging;
mod mail;
mod sql_tcp_backend_handler;
mod tcp_backend_handler;
mod tcp_server;
mod tls;

use crate::{
    cli::{Command, RunOpts, TestEmailOpts},
    configuration::{Configuration, compare_private_key_hashes},
    database_string::DatabaseUrl,
    db_cleaner::Scheduler,
};
use actix::Actor;
use actix_server::ServerBuilder;
use anyhow::{Context, Result, anyhow, bail};
use futures_util::TryFutureExt;
use lldap_sql_backend_handler::{
    LogRetention, SqlBackendHandler, register_password,
    sql_tables::{self, get_private_key_info, set_private_key_info},
    start_log_writer,
};
use sea_orm::{Database, DatabaseConnection};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tracing::{Instrument, Level, debug, error, info, instrument, span, warn};

use lldap_domain::requests::{CreateGroupRequest, CreateUserRequest};
use lldap_domain::types::{Attribute, BUILTIN_GROUPS};
use lldap_domain_handlers::kerberos::{DegradedKerberos, NoopKerberos, set_kerberos_backend};
use lldap_domain_handlers::logging::{LogKind, record};
use lldap_kerberos::boot::client_address;
use lldap_kerberos::embedded::{EmbeddedKerberos, RealmThreads};

use lldap_domain_handlers::handler::{
    GroupBackendHandler, GroupListerBackendHandler, GroupRequestFilter, MfaBackendHandler,
    UserBackendHandler, UserListerBackendHandler, UserRequestFilter,
};
use lldap_domain_handlers::mfa::{MFA_DISABLED_GROUP, MfaResetReason};

const ADMIN_PASSWORD_MISSING_ERROR: &str = "The LDAP admin password must be initialized. \
            Either set the `ldap_user_pass` config value or the `LLDAP_LDAP_USER_PASS` environment variable. \
            A minimum of 8 characters is recommended.";

async fn create_admin_user(handler: &SqlBackendHandler, config: &Configuration) -> Result<()> {
    let pass_length = config
        .ldap_user_pass
        .as_ref()
        .expect(ADMIN_PASSWORD_MISSING_ERROR)
        .unsecure()
        .len();
    assert!(
        pass_length >= 8,
        "Minimum password length is 8 characters, got {pass_length} characters"
    );
    handler
        .create_user(CreateUserRequest {
            user_id: config.ldap_user_dn.clone(),
            email: config.ldap_user_email.clone().into(),
            display_name: Some("Administrator".to_string()),
            attributes: vec![Attribute {
                name: "ou".into(),
                value: "people".to_string().into(),
            }],
        })
        .and_then(|_| {
            register_password(
                handler,
                config.ldap_user_dn.clone(),
                config
                    .ldap_user_pass
                    .as_ref()
                    .unwrap()
                    .unsecure()
                    .as_bytes(),
            )
        })
        .await
        .context("Error creating admin user")?;
    let groups = handler
        .list_groups(Some(GroupRequestFilter::DisplayName("lldap_admin".into())))
        .await?;
    assert_eq!(groups.len(), 1);
    handler
        .add_user_to_group(&config.ldap_user_dn, groups[0].id)
        .await
        .context("Error adding admin user to group")
}

async fn ensure_group_exists(handler: &SqlBackendHandler, group_name: &str) -> Result<()> {
    if handler
        .list_groups(Some(GroupRequestFilter::DisplayName(group_name.into())))
        .await?
        .is_empty()
    {
        warn!("Could not find {} group, trying to create it", group_name);
        handler
            .create_group(CreateGroupRequest {
                display_name: group_name.into(),
                attributes: vec![Attribute {
                    name: "ou".into(),
                    value: "groups".to_string().into(),
                }],
            })
            .await
            .context(format!("while creating {group_name} group"))?;
    }
    Ok(())
}

// Log lookups read here so a slow summary cannot queue binds behind SQLite's one write
// connection; other backends already run several connections.
async fn setup_read_pool(
    database_url: &DatabaseUrl,
    sql_pool: &DatabaseConnection,
) -> Result<DatabaseConnection> {
    let connect_string = database_url.to_connect_string();
    if database_url.db_type() != "sqlite" || connect_string.contains(":memory:") {
        return Ok(sql_pool.clone());
    }
    let mut sql_opt = sea_orm::ConnectOptions::new(connect_string);
    sql_opt
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .sqlx_logging(true)
        .sqlx_logging_level(log::LevelFilter::Debug)
        .map_sqlx_sqlite_opts(|options| options.read_only(true));
    Database::connect(sql_opt)
        .await
        .context("while opening the read-only pool for log lookups")
}

async fn setup_sql_tables(database_url: &DatabaseUrl) -> Result<DatabaseConnection> {
    let sql_pool = {
        let num_connections = if database_url.db_type() == "sqlite" {
            1
        } else {
            5
        };
        let mut sql_opt = sea_orm::ConnectOptions::new(database_url.to_connect_string());
        sql_opt
            .max_connections(num_connections)
            .sqlx_logging(true)
            .sqlx_logging_level(log::LevelFilter::Debug);
        Database::connect(sql_opt).await?
    };
    sql_tables::init_table(&sql_pool)
        .await
        .context("while creating base tables")?;
    jwt_sql_tables::init_table(&sql_pool)
        .await
        .context("while creating jwt tables")?;
    Ok(sql_pool)
}

fn log_retention(config: &Configuration) -> LogRetention {
    LogRetention {
        retention_days: config.log_options.retention_days,
        max_entries: config.log_options.max_entries,
    }
}

#[instrument(skip_all)]
async fn set_up_server(
    mut config: Configuration,
    sql_pool: DatabaseConnection,
) -> Result<(ServerBuilder, Option<RealmThreads>)> {
    let realm = config.kerberos_realm();
    set_kerberos_backend(Arc::new(NoopKerberos::new(realm.clone())));
    tokio::task::spawn_blocking(lldap_graphql_server::warm_transport_key);
    let private_key_info = config.get_private_key_info();
    let force_update_private_key = config.force_update_private_key;
    let key_rotated = match (
        compare_private_key_hashes(
            get_private_key_info(&sql_pool).await?.as_ref(),
            &private_key_info,
        ),
        force_update_private_key,
    ) {
        (Ok(false), true) => {
            bail!(
                "The private key has not changed, but force_update_private_key/LLDAP_FORCE_UPDATE_PRIVATE_KEY is set to true. Please set force_update_private_key to false and restart the server."
            );
        }
        (Ok(true), _) => {
            set_private_key_info(&sql_pool, private_key_info).await?;
            false
        }
        (Err(_), true) => {
            set_private_key_info(&sql_pool, private_key_info).await?;
            true
        }
        (Ok(false), false) => false,
        (Err(e), false) => {
            return Err(anyhow!("The private key encoding the passwords has changed since last successful startup. Changing the private key will invalidate all existing passwords. If you want to proceed, restart the server with the CLI arg --force-update-private-key=true or the env variable LLDAP_FORCE_UPDATE_PRIVATE_KEY=true. You probably also want --force-ldap-user-pass-reset / LLDAP_FORCE_LDAP_USER_PASS_RESET=true to reset the admin password to the value in the configuration.").context(e));
        }
    };
    let backend_handler =
        SqlBackendHandler::new(config.get_server_setup().clone(), sql_pool.clone())
            .with_read_pool(setup_read_pool(&config.database_url, &sql_pool).await?)
            .with_mfa_policy(config.mfa_policy());
    // Every sealed TOTP secret was keyed from the old private key.
    if key_rotated {
        backend_handler.clear_all_mfa().await?;
    }
    for group in BUILTIN_GROUPS {
        ensure_group_exists(&backend_handler, group).await?;
    }
    if config.enable_mfa.is_positive() {
        ensure_group_exists(&backend_handler, MFA_DISABLED_GROUP).await?;
    }
    let admin_present = if let Ok(admins) = backend_handler
        .list_users(
            Some(UserRequestFilter::MemberOf("lldap_admin".into())),
            false,
        )
        .await
    {
        !admins.is_empty()
    } else {
        false
    };
    if !admin_present {
        warn!(
            "Could not find an admin user, trying to create the user \"admin\" with the config-provided password"
        );
        create_admin_user(&backend_handler, &config)
            .await
            .map_err(|e| anyhow!("Error setting up admin login/account: {:#}", e))
            .context("while creating the admin user")?;
        record(
            LogKind::AdminBootstrap,
            Some(config.ldap_user_dn.as_str()),
            Some("admin user created"),
        );
    } else if config.force_ldap_user_pass_reset.is_positive() {
        let span = if config.force_ldap_user_pass_reset.is_yes() {
            span!(
                Level::WARN,
                "Forcing admin password reset to the config-provided password"
            )
        } else {
            span!(Level::INFO, "Resetting admin password")
        };
        register_password(
            &backend_handler,
            config.ldap_user_dn.clone(),
            config
                .ldap_user_pass
                .as_ref()
                .expect(ADMIN_PASSWORD_MISSING_ERROR)
                .unsecure()
                .as_bytes(),
        )
        .instrument(span)
        .await
        .context(format!(
            "while resetting admin password for {}",
            config.ldap_user_dn
        ))?;
        // The one-shot reset is the break-glass: it also clears the admin's second factor.
        if config.force_ldap_user_pass_reset.is_yes() {
            backend_handler
                .reset_user_mfa(&config.ldap_user_dn, MfaResetReason::ForcedAdminReset)
                .await?;
        }
        record(
            LogKind::AdminBootstrap,
            Some(config.ldap_user_dn.as_str()),
            Some("admin password reset from the configuration"),
        );
    }
    if config.force_update_private_key || config.force_ldap_user_pass_reset.is_yes() {
        bail!(
            "Restart the server without --force-update-private-key or --force-ldap-user-pass-reset to continue."
        );
    }
    let (realm_threads, embedded) = match config.kerberos_options.enabled {
        false => (None, None),
        true => match EmbeddedKerberos::start(&config.kerberos_settings()?) {
            Ok((embedded, threads)) => {
                set_kerberos_backend(embedded.clone());
                reconcile_principals(&backend_handler, &embedded).await?;
                (Some(threads), Some(embedded))
            }
            Err(e) => {
                let cause = format!("the Kerberos realm {realm} did not open: {e:#}");
                error!("{cause}");
                set_kerberos_backend(Arc::new(DegradedKerberos::new(realm.clone(), cause)));
                config.ldap_host = loopback(&config.ldap_host);
                config.http_host = loopback(&config.http_host);
                warn!(
                    "Only admins may sign in, over LDAP on {} and HTTP on {}",
                    config.ldap_host, config.http_host
                );
                (None, None)
            }
        },
    };
    let server_builder = ldap_server::build_ldap_server(
        &config,
        backend_handler.clone(),
        actix_server::Server::build(),
    )
    .context("while binding the LDAP server")?;
    let server_builder = tcp_server::build_tcp_server(&config, backend_handler, server_builder)
        .await
        .context("while binding the TCP server")?;
    // Run every hour.
    let scheduler = Scheduler::new("0 0 * * * * *", sql_pool, log_retention(&config), embedded);
    scheduler.start();
    Ok((server_builder, realm_threads))
}

fn loopback(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => "::1".to_owned(),
        _ => "127.0.0.1".to_owned(),
    }
}

async fn reconcile_principals(
    handler: &SqlBackendHandler,
    embedded: &EmbeddedKerberos,
) -> Result<()> {
    let users = handler
        .list_users(None, false)
        .await?
        .into_iter()
        .filter(|u| {
            u.user
                .krb_principal_name
                .as_deref()
                .is_some_and(|n| !n.is_empty())
        })
        .map(|u| u.user.user_id)
        .collect();
    let (updated, missing) = embedded.reconcile(users).await?;
    info!("🎟️ Kerberos reconcile: {updated} principals updated, {missing} without a principal");
    Ok(())
}

async fn serve(server: ServerBuilder, realm: Option<RealmThreads>) -> Result<()> {
    let server = server.workers(1).run();
    let Some(mut realm) = realm else {
        return server.await.context("while starting the server");
    };
    let handle = server.handle();
    let served = tokio::select! {
        served = server => served.context("while starting the server"),
        cause = realm.died() => {
            handle.stop(true).await;
            Err(anyhow!("the Kerberos realm stopped: {cause}"))
        }
    };
    tokio::task::spawn_blocking(move || realm.stop())
        .await
        .context("while stopping the Kerberos realm")?;
    served
}

async fn run_server_command(opts: RunOpts) -> Result<()> {
    debug!("CLI: {:#?}", &opts);

    let config = configuration::init_with_private_key(opts)?;
    logging::init(&config)?;
    info!("Starting LLDAP version {}", env!("CARGO_PKG_VERSION"));

    let sql_pool = setup_sql_tables(&config.database_url).await?;
    let log_writer = config.log_options.persist.then(|| {
        start_log_writer(
            sql_pool.clone(),
            log_retention(&config),
            config.log_options.bind_coalesce_seconds,
        )
    });

    // One exit path, so the one-shot force flags and errors flush the log too.
    let result = match set_up_server(config, sql_pool.clone()).await {
        Ok((server, realm)) => {
            record(LogKind::ServerStart, None, Some(env!("CARGO_PKG_VERSION")));
            serve(server, realm).await
        }
        Err(e) => Err(e),
    };
    if let Some(writer) = log_writer {
        writer.shutdown().await;
    }
    if let Err(e) = sql_pool.close().await {
        error!("Error closing database connection pool: {}", e);
    }
    result
}

async fn send_test_email_command(opts: TestEmailOpts) -> Result<()> {
    let to = opts.to.parse()?;
    let config = configuration::init(opts)?;
    logging::init(&config)?;

    mail::send_test_email(to, &config.smtp_options)
        .await
        .context("Could not send email: {:#}")
}

async fn run_healthcheck(opts: RunOpts) -> Result<()> {
    debug!("CLI: {:#?}", &opts);
    let config = configuration::init(opts)?;
    logging::init(&config)?;

    info!("Starting healthchecks");

    use tokio::time::timeout;
    let delay = Duration::from_millis(3000);
    let kerberos = async {
        if config.kerberos_options.enabled {
            healthcheck::check_kerberos(
                &client_address(
                    &config.kerberos_options.kdc_host,
                    config.kerberos_options.kdc_port,
                ),
                &config.kerberos_options.admin_keytab,
            )
            .await
        } else {
            Ok(())
        }
    };
    let (ldap, ldaps, api, kerberos) = tokio::join!(
        timeout(
            delay,
            healthcheck::check_ldap(&config.healthcheck_options.ldap_host, config.ldap_port)
        ),
        timeout(
            delay,
            healthcheck::check_ldaps(&config.healthcheck_options.ldap_host, &config.ldaps_options)
        ),
        timeout(
            delay,
            healthcheck::check_api(&config.healthcheck_options.http_host, config.http_port)
        ),
        timeout(delay, kerberos),
    );
    if healthcheck::any_failed([ldap, ldaps, api, kerberos]) {
        bail!("Healthcheck failed")
    } else {
        Ok(())
    }
}

async fn create_schema_command(opts: RunOpts) -> Result<()> {
    debug!("CLI: {:#?}", &opts);
    let config = configuration::init(opts)?;
    logging::init(&config)?;
    let sql_pool = setup_sql_tables(&config.database_url).await?;
    info!("Schema created successfully.");
    if let Err(e) = sql_pool.close().await {
        error!("Error closing database connection pool: {}", e);
    }
    Ok(())
}

#[actix::main]
async fn main() -> Result<()> {
    let cli_opts = cli::init();
    match cli_opts.command {
        Command::ExportGraphQLSchema(opts) => {
            lldap_graphql_server::api::export_schema(opts.output_file)
        }
        Command::Run(opts) => run_server_command(opts).await,
        Command::HealthCheck(opts) => run_healthcheck(opts).await,
        Command::SendTestEmail(opts) => send_test_email_command(opts).await,
        Command::CreateSchema(opts) => create_schema_command(opts).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_loopback_for_the_degraded_listeners() {
        let rows = [
            ("0.0.0.0", "127.0.0.1"),
            ("192.0.2.7", "127.0.0.1"),
            ("::", "::1"),
            ("2001:db8::7", "::1"),
            ("lldap.example.com", "127.0.0.1"),
            ("", "127.0.0.1"),
        ];
        for (host, expected) in rows {
            assert_eq!(loopback(host), expected, "{host}");
        }
    }
}
