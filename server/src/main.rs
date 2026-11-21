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
    cli::{Command, RunOpts, TestEmailOpts, UnlockOpts},
    configuration::{Configuration, compare_private_key_hashes},
    database_string::DatabaseUrl,
    db_cleaner::Scheduler,
};
use actix::Actor;
use actix_server::ServerBuilder;
use anyhow::{Context, Result, anyhow, bail};
use futures_util::TryFutureExt;
use lldap_sql_backend_handler::{
    KerberosLost, LogRetention, SqlBackendHandler, realm_marked_open, register_password,
    sql_tables::{self, get_private_key_info, set_private_key_info},
    sqlite_extra_synchronous, start_kerberos_committer, start_log_writer, unlock_login_on,
    warn_database_durability,
};
use sea_orm::{Database, DatabaseConnection};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tracing::{Instrument, Level, debug, error, info, instrument, span, warn};

use lldap_domain::requests::{CreateGroupRequest, CreateUserRequest};
use lldap_domain::types::{Attribute, BUILTIN_GROUPS, UserId, kerberos_sync_enabled};
use lldap_domain_handlers::enforcement::{
    CacheFollower, StartWarning, policy_cache, start_policy_cache,
};
use lldap_domain_handlers::kerberos::{
    DegradedKerberos, KerberosSync, NoopKerberos, kerberos_backend, kerberos_store,
    set_kerberos_backend,
};
use lldap_domain_handlers::lockout::{UNLOCKED_BY_TOOL, lock_clock, lockout, start_lockout};
use lldap_domain_handlers::logging::{self as rows, LogKind, event, record};
use lldap_domain_handlers::password::{
    PASSWORD_MIN_LENGTH, PasswordChangeError, PasswordSync, change_password_everywhere,
    password_rules,
};
use lldap_kerberos::boot::{RealmSettings, client_address};
use lldap_kerberos::embedded::{EmbeddedKerberos, FOLLOW_EVERY, Opened, RealmThreads, Records};

use lldap_domain_handlers::handler::{
    GroupBackendHandler, GroupListerBackendHandler, GroupRequestFilter, MfaBackendHandler,
    PolicyBackendHandler, UserBackendHandler, UserListerBackendHandler, UserRequestFilter,
};
use lldap_domain_handlers::mfa::{MfaPolicy, MfaResetReason};

const ADMIN_PASSWORD_MISSING_ERROR: &str = "The LDAP admin password must be initialized. \
            Either set the `ldap_user_pass` config value or the `LLDAP_LDAP_USER_PASS` environment variable. \
            A minimum of 8 characters is recommended.";

const RESTART_WITHOUT_FORCE: &str = "Restart the server without --force-update-private-key or \
                                     --force-ldap-user-pass-reset to continue.";

const RESET_TOO_SHORT: &str = "The forced reset of the admin's password \
    (force_ldap_user_pass_reset) needs at least 8 characters in ldap_user_pass. Set a longer \
    password, or take the forced reset out of the configuration.";

const RESET_HAS_NUL: &str = "The forced reset of the admin's password \
    (force_ldap_user_pass_reset) cannot take a NUL character (U+0000) in ldap_user_pass. Set \
    another password, or take the forced reset out of the configuration.";

const KERBEROS_OFF: &str = "Kerberos is not enabled (kerberos_options.enabled is false)";

fn sync_turned_off(cause: &str) -> String {
    format!(
        "Kerberos sync turned off by the forced reset of the admin's password, because {cause}: \
         a principal, if there is one, is removed by the holder's next status pass, within a \
         minute, or at the next start with Kerberos enabled"
    )
}

/// The forced reset when Kerberos cannot take part, as upstream's; an admin with sync has it
/// turned off in the same transaction as the password.
async fn reset_without_realm(
    handler: &SqlBackendHandler,
    config: &Configuration,
    sync: PasswordSync,
    cause: &str,
) -> Result<()> {
    let admin = &config.ldap_user_dn;
    let password = admin_password(config).as_bytes();
    let reset = match sync {
        PasswordSync::Off => {
            register_password(handler, admin.clone(), password)
                .instrument(reset_span(config))
                .await
        }
        PasswordSync::On => {
            let detail = sync_turned_off(cause);
            let row = event(
                LogKind::KerberosSync,
                Some(admin.as_str()),
                true,
                Some(&detail),
            );
            handler
                .reset_password_without_sync(admin, password, row)
                .instrument(reset_span(config))
                .await
        }
    };
    reset.with_context(|| format!("while resetting admin password for {admin}"))?;
    info!("Reset the password of {admin} from the configuration");
    match sync {
        PasswordSync::On => warn!(
            "The forced reset of {admin}'s password ran without the Kerberos realm and turned its \
             Kerberos sync off, because {cause}: the directory password is the configured one. \
             Turn the sync on again once Kerberos runs; the next password change then makes the \
             principal. The holder's status pass removes the one left behind within a minute, \
             or the next start with Kerberos does."
        ),
        PasswordSync::Off if cause != KERBEROS_OFF => warn!(
            "The forced reset of {admin}'s password ran without the Kerberos realm, because \
             {cause}: the directory password is the configured one."
        ),
        PasswordSync::Off => {}
    }
    finish_reset(
        handler,
        config,
        "admin password reset from the configuration",
    )
    .await
}

struct SetAside(Arc<dyn KerberosSync>);

impl SetAside {
    fn new(realm: String) -> Self {
        let kerberos = kerberos_backend();
        set_kerberos_backend(Arc::new(NoopKerberos::new(realm)));
        Self(kerberos)
    }
}

impl Drop for SetAside {
    fn drop(&mut self) {
        set_kerberos_backend(self.0.clone());
    }
}

/// `reset_without_realm` with a realm already installed: the realm takes no part meanwhile.
async fn reset_aside(
    handler: &SqlBackendHandler,
    config: &Configuration,
    sync: PasswordSync,
    cause: &str,
) -> Result<()> {
    let _aside = SetAside::new(config.kerberos_realm());
    reset_without_realm(handler, config, sync, cause).await
}

/// The start's passes, then the deferred reset. Some: the realm is not usable and the reset is
/// still deferred; a failed reset with the realm runs at once without it, and the passes again.
async fn before_serve(
    mut passes: impl AsyncFnMut() -> Result<()>,
    deferred: &mut Option<PasswordSync>,
    with_realm: impl AsyncFnOnce(PasswordSync) -> Result<()>,
    aside: impl AsyncFnOnce(PasswordSync, String) -> Result<()>,
    realm: &str,
) -> Result<Option<anyhow::Error>> {
    if let Err(e) = passes().await {
        return Ok(Some(e));
    }
    let Some(sync) = deferred.take() else {
        return Ok(None);
    };
    if let Err(e) = with_realm(sync).await {
        let cause = format!("the forced reset with the Kerberos realm {realm} failed: {e:#}");
        error!("{cause}");
        aside(sync, cause).await?;
        if let Err(e) = passes().await {
            return Ok(Some(e));
        }
    }
    Ok(None)
}

fn reset_refused(e: PasswordChangeError) -> &'static str {
    match e {
        PasswordChangeError::HasNul => RESET_HAS_NUL,
        _ => RESET_TOO_SHORT,
    }
}

fn admin_password(config: &Configuration) -> &str {
    config
        .ldap_user_pass
        .as_ref()
        .expect(ADMIN_PASSWORD_MISSING_ERROR)
        .unsecure()
}

fn reset_span(config: &Configuration) -> tracing::Span {
    if config.force_ldap_user_pass_reset.is_yes() {
        span!(
            Level::WARN,
            "Forcing admin password reset to the config-provided password"
        )
    } else {
        span!(Level::INFO, "Resetting admin password")
    }
}

// The one-shot reset is the break-glass: it also clears the admin's second factor.
async fn finish_reset(
    handler: &SqlBackendHandler,
    config: &Configuration,
    detail: &str,
) -> Result<()> {
    if config.force_ldap_user_pass_reset.is_yes() {
        handler
            .reset_user_mfa(&config.ldap_user_dn, MfaResetReason::ForcedAdminReset)
            .await?;
    }
    record(
        LogKind::AdminBootstrap,
        Some(config.ldap_user_dn.as_str()),
        Some(detail),
    );
    Ok(())
}

async fn reset_with_realm(
    handler: &SqlBackendHandler,
    config: &Configuration,
    sync: PasswordSync,
) -> Result<()> {
    let admin = &config.ldap_user_dn;
    change_password_everywhere(
        handler,
        admin,
        admin_password(config),
        sync,
        PASSWORD_MIN_LENGTH,
    )
    .instrument(reset_span(config))
    .await
    .map_err(|e| anyhow!("{e}"))
    .with_context(|| format!("while resetting admin password for {admin}"))?;
    let detail = match sync {
        PasswordSync::On => {
            info!("Reset the password and the Kerberos keys of {admin} from the configuration");
            "admin password and Kerberos keys reset from the configuration"
        }
        PasswordSync::Off => {
            info!("Reset the password of {admin} from the configuration");
            "admin password reset from the configuration"
        }
    };
    finish_reset(handler, config, detail).await
}

/// The first start's floor of 8, counted in characters as every other check counts.
fn first_start_floor(password: &str) -> Result<(), String> {
    let pass_length = password.chars().count();
    match pass_length >= 8 {
        true => Ok(()),
        false => Err(format!(
            "Minimum password length is 8 characters, got {pass_length} characters"
        )),
    }
}

fn admin_min_length_warning(len: usize, min: usize) -> Option<String> {
    (len < min).then(|| {
        format!(
            "The admin password in ldap_user_pass has {len} characters; the admin's \
             password-min-length is {min}: the configuration's password is checked against 8 \
             only, and a change of it is held to {min}"
        )
    })
}

/// One warning, on the starts that apply the configuration's password; an unread minimum, none.
async fn warn_admin_min_length(handler: &SqlBackendHandler, config: &Configuration) {
    let len = admin_password(config).chars().count();
    if let Ok(min) = handler.password_min_length(&config.ldap_user_dn).await
        && let Some(text) = admin_min_length_warning(len, min)
    {
        warn!("{text}");
    }
}

async fn create_admin_user(handler: &SqlBackendHandler, config: &Configuration) -> Result<()> {
    if let Err(why) = first_start_floor(admin_password(config)) {
        panic!("{why}");
    }
    if let Err(e) = password_rules(admin_password(config), PASSWORD_MIN_LENGTH) {
        bail!("The admin password in ldap_user_pass is refused: {e}");
    }
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

/// A count, never a name: 0.8.0 stored the item and checked nothing.
async fn warn_ous_asking_mfa(handler: &SqlBackendHandler, server: Option<MfaPolicy>) {
    static WARNING: StartWarning = StartWarning::new();
    let Ok(policies) = handler.list_policies().await else {
        return;
    };
    if let Some(text) = WARNING.take(server, &policies) {
        warn!("{text}");
    }
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
        if database_url.db_type() == "sqlite" {
            sql_opt.map_sqlx_sqlite_opts(sqlite_extra_synchronous);
        }
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
            .with_mfa_setting(config.mfa_policy())
            .with_proofs(config.proof_settings()?);
    // Every sealed TOTP secret was keyed from the old private key.
    if key_rotated {
        backend_handler.clear_all_mfa().await?;
    }
    for group in BUILTIN_GROUPS {
        ensure_group_exists(&backend_handler, group).await?;
    }
    let mut deferred = None;
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
        warn_admin_min_length(&backend_handler, &config).await;
    } else if config.force_ldap_user_pass_reset.is_positive() {
        if let Err(e) = password_rules(admin_password(&config), PASSWORD_MIN_LENGTH) {
            bail!(reset_refused(e));
        }
        warn_admin_min_length(&backend_handler, &config).await;
        let admin = backend_handler
            .get_user_details(&config.ldap_user_dn)
            .await
            .with_context(|| {
                format!("while resetting admin password for {}", config.ldap_user_dn)
            })?;
        let sync = PasswordSync::of(kerberos_sync_enabled(&admin.attributes));
        let why = match sync {
            PasswordSync::On => "the admin has Kerberos sync",
            PasswordSync::Off => "Kerberos is enabled",
        };
        if config.kerberos_options.enabled {
            deferred = Some(sync);
            info!(
                "The forced reset of {}'s password waits for the Kerberos realm: {why}",
                config.ldap_user_dn
            );
        } else {
            reset_without_realm(&backend_handler, &config, sync, KERBEROS_OFF).await?;
        }
    }
    let restart = config.force_update_private_key || config.force_ldap_user_pass_reset.is_yes();
    if restart && deferred.is_none() {
        bail!(RESTART_WITHOUT_FORCE);
    }
    let _policy_filler = start_policy_cache(&backend_handler).await;
    let _lockout = start_lockout(&backend_handler, policy_cache()).await;
    backend_handler
        .exempt_group_at_start()
        .await
        .context("while creating the lldap_mfa_disabled group")?;
    warn_ous_asking_mfa(&backend_handler, config.mfa_policy()).await;
    let (realm_threads, embedded) = match config.kerberos_options.enabled {
        false => (None, None),
        true => {
            let settings = config.kerberos_settings()?;
            let durable = warn_database_durability(&sql_pool)
                .await
                .context("while reading database durability");
            let records = Records {
                handler: Arc::new(backend_handler.clone()),
                policies: Arc::new(backend_handler.clone()),
                runtime: tokio::runtime::Handle::current(),
            };
            let opened = match durable {
                Ok(()) => open_realm(settings, records).await,
                Err(e) => Err(e),
            }
            .with_context(|| format!("the Kerberos realm {realm} did not open"));
            let mut deferred = deferred;
            let served = match opened {
                Ok((embedded, opened)) => {
                    let follower = CacheFollower::new(backend_handler.clone(), policy_cache());
                    embedded.follow_commits(Arc::new(follower));
                    set_kerberos_backend(embedded.clone());
                    let reconciling =
                        format!("reconciling the principals of the Kerberos realm {realm} failed");
                    let passing = format!("the start pass of the Kerberos realm {realm} failed");
                    let passes = async || {
                        let reconciled = reconcile_principals(&backend_handler, &embedded).await;
                        reconciled.context(reconciling.clone())?;
                        let passed = start_pass(&backend_handler, &embedded).await;
                        passed.context(passing.clone())
                    };
                    let with_realm = async |sync: PasswordSync| {
                        reset_with_realm(&backend_handler, &config, sync).await
                    };
                    let aside = async |sync: PasswordSync, cause: String| {
                        reset_aside(&backend_handler, &config, sync, &cause).await
                    };
                    match before_serve(passes, &mut deferred, with_realm, aside, &realm).await? {
                        Some(e) => Err(e),
                        None if restart => {
                            drop(opened);
                            bail!(RESTART_WITHOUT_FORCE);
                        }
                        None => match embedded.unavailable() {
                            Some(lost) => Err(anyhow!("{lost}").context(format!(
                                "the KDC of the Kerberos realm {realm} was not started"
                            ))),
                            None => serve_realm(opened)
                                .await
                                .with_context(|| format!("the Kerberos realm {realm} did not open"))
                                .map(|threads| {
                                    let turns = embedded.follow_every(FOLLOW_EVERY);
                                    (threads.following(turns), embedded)
                                }),
                        },
                    }
                }
                Err(e) => Err(e),
            };
            match served {
                Ok((threads, embedded)) => (Some(threads), Some(embedded)),
                Err(e) => {
                    let cause = format!("{e:#}");
                    error!("{cause}");
                    if let Some(sync) = deferred {
                        let failed = e.to_string();
                        reset_aside(&backend_handler, &config, sync, &failed).await?;
                        if restart {
                            bail!(RESTART_WITHOUT_FORCE);
                        }
                    }
                    set_kerberos_backend(Arc::new(DegradedKerberos::new(realm.clone(), cause)));
                    config.ldap_host = loopback(&config.ldap_host);
                    config.http_host = loopback(&config.http_host);
                    warn!(
                        "Only admins may sign in, over LDAP on {} and HTTP on {}",
                        config.ldap_host, config.http_host
                    );
                    (None, None)
                }
            }
        }
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

async fn open_realm(
    settings: RealmSettings,
    records: Records,
) -> Result<(Arc<EmbeddedKerberos>, Opened)> {
    tokio::task::spawn_blocking(move || {
        EmbeddedKerberos::open(&settings, kerberos_store(), records)
    })
    .await
    .context("while opening the Kerberos realm")?
}

async fn serve_realm(opened: Opened) -> Result<RealmThreads> {
    tokio::task::spawn_blocking(move || opened.serve())
        .await
        .context("while starting the KDC and kadmind")?
}

async fn stop_realm(realm: RealmThreads) -> Result<()> {
    tokio::task::spawn_blocking(move || realm.stop())
        .await
        .context("while stopping the Kerberos realm")
}

enum Ended {
    Served(Result<()>),
    Died(String),
    Lost,
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

async fn start_pass(handler: &SqlBackendHandler, embedded: &EmbeddedKerberos) -> Result<()> {
    let users = handler
        .list_users(None, false)
        .await?
        .into_iter()
        .map(|u| {
            let sync = kerberos_sync_enabled(&u.user.attributes);
            (u.user.user_id, sync)
        })
        .collect();
    let pass = embedded.start_pass(users).await?;
    info!(
        "🎟️ Kerberos start pass: {} principals marked, {} removed, {} disabled, {} set from \
         lldap_disabled",
        pass.marked, pass.removed, pass.disabled, pass.followed
    );
    Ok(())
}

async fn serve(
    server: ServerBuilder,
    realm: Option<RealmThreads>,
    lost: Option<tokio::sync::watch::Receiver<Option<KerberosLost>>>,
) -> Result<()> {
    if let Some(lost) = lost.as_ref().filter(|lost| lost.borrow().is_some()) {
        if let Some(realm) = realm {
            stop_realm(realm).await?;
        }
        return realm_lost(lost);
    }
    let server = server.workers(1).run();
    match (realm, lost) {
        (None, None) => server.await.context("while starting the server"),
        (None, Some(mut lost)) => tokio::select! {
            served = server => served.context("while starting the server"),
            _ = lost.changed() => realm_lost(&lost),
        },
        (Some(mut realm), None) => {
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
        (Some(mut realm), Some(mut lost)) => {
            let handle = server.handle();
            let ended = tokio::select! {
                served = server => Ended::Served(served.context("while starting the server")),
                cause = realm.died() => Ended::Died(cause),
                _ = lost.changed() => Ended::Lost,
            };
            match ended {
                Ended::Lost => {
                    stop_realm(realm).await?;
                    handle.stop(true).await;
                    realm_lost(&lost)
                }
                Ended::Died(cause) => {
                    handle.stop(true).await;
                    stop_realm(realm).await?;
                    Err(anyhow!("the Kerberos realm stopped: {cause}"))
                }
                Ended::Served(served) => {
                    stop_realm(realm).await?;
                    served
                }
            }
        }
    }
}

fn realm_lost(lost: &tokio::sync::watch::Receiver<Option<KerberosLost>>) -> Result<()> {
    match lost.borrow().clone() {
        Some(cause @ KerberosLost::Occupied) => Err(anyhow!("{cause}")),
        Some(cause) => Err(anyhow!("the Kerberos realm was lost: {cause}")),
        None => Err(anyhow!("the Kerberos realm was lost")),
    }
}

async fn run_server_command(opts: RunOpts) -> Result<()> {
    debug!("CLI: {:#?}", &opts);

    let config = configuration::init_with_private_key(opts)?;
    logging::init(&config)?;
    info!("Starting LLDAP version {}", env!("CARGO_PKG_VERSION"));

    let sql_pool = setup_sql_tables(&config.database_url).await?;
    if !config.kerberos_options.enabled && realm_marked_open(&sql_pool).await {
        warn!(
            "Kerberos is disabled on this server, but this database's Kerberos realm is marked \
             open: another server holds it, or the last server with Kerberos stopped without \
             closing it. On a lone server this is harmless; to close the realm, start once with \
             Kerberos enabled, wait out its thirty-five-second watch and stop cleanly. Beside a \
             holder, every server on one database needs the same kerberos_options.enabled: this \
             server's deletes, sync changes and lldap_disabled changes reach the realm's \
             principals through the holder's status pass, within a minute"
        );
    }
    let committer = config
        .kerberos_options
        .enabled
        .then(|| start_kerberos_committer(sql_pool.clone()));
    let lost = committer.as_ref().map(|committer| committer.lost());
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
            serve(server, realm, lost).await
        }
        Err(e) => Err(e),
    };
    lockout().stop().await;
    if let Some(committer) = committer {
        committer.shutdown().await;
    }
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

async fn unlock_command(opts: UnlockOpts) -> Result<()> {
    debug!("CLI: {:#?}", &opts);
    let user = UserId::new(&opts.user);
    let config = configuration::init(opts)?;
    logging::init(&config)?;
    let sql_pool = setup_sql_tables(&config.database_url).await?;
    let row = event(
        LogKind::AccountUnlock,
        Some(user.as_str()),
        true,
        Some(UNLOCKED_BY_TOOL),
    );
    let unlocked = unlock_login_on(&sql_pool, &user, lock_clock(), row.clone()).await;
    if let Err(e) = sql_pool.close().await {
        error!("Error closing database connection pool: {}", e);
    }
    unlocked.with_context(|| format!("while unlocking {user}"))?;
    rows::print(&row);
    println!("Unlocked {user}; a running server sees it within 30 seconds.");
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
        Command::Unlock(opts) => unlock_command(opts).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_the_realm_engine_follows_its_commits_before_it_takes_requests() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let at = |needle: &str| {
            let found = production.find(needle);
            found.unwrap_or_else(|| panic!("main.rs no longer has `{needle}`"))
        };
        let made = at("CacheFollower::new(backend_handler.clone(), policy_cache())");
        let installed = at("embedded.follow_commits(Arc::new(follower))");
        let serving = at("set_kerberos_backend(embedded.clone())");
        assert!(
            made < installed && installed < serving,
            "the cache's follower is installed before the realm engine takes requests"
        );
    }

    #[test]
    fn test_a_forced_reset_is_refused_only_for_its_password() {
        let floor = reset_refused(PasswordChangeError::TooShort(8));
        let nul = reset_refused(PasswordChangeError::HasNul);
        let off = sync_turned_off(KERBEROS_OFF);
        let rows = [
            (floor, "at least 8 characters"),
            (floor, "take the forced reset out of the configuration"),
            (nul, "cannot take a NUL character (U+0000)"),
            (nul, "take the forced reset out of the configuration"),
            (
                off.as_str(),
                "Kerberos sync turned off by the forced reset of the admin's password",
            ),
            (
                off.as_str(),
                "Kerberos is not enabled (kerberos_options.enabled is false)",
            ),
            (
                off.as_str(),
                "a principal, if there is one, is removed by the holder's next status pass, \
                 within a minute, or at the next start with Kerberos enabled",
            ),
        ];
        for (sentence, part) in rows {
            assert!(sentence.contains(part), "{part}: {sentence}");
        }
    }

    #[tokio::test]
    async fn test_each_kerberos_failure_before_serve_leaves_the_reset_to_the_directory() {
        use PasswordSync::{Off, On};
        let failed = |why: &str| Err(anyhow!("{}", why.to_owned()));
        let aside = |sync: &str, why: &str| {
            format!(
                "aside {sync}: the forced reset with the Kerberos realm EXAMPLE.COM failed: {why}"
            )
        };
        let calls = |list: &[&str]| list.iter().map(|call| (*call).to_owned()).collect();
        type Row = (
            &'static str,
            Vec<Result<()>>,
            Option<PasswordSync>,
            Result<()>,
            Option<String>,
            Vec<String>,
            Option<PasswordSync>,
        );
        let rows: Vec<Row> = vec![
            (
                "reconcile or the start pass fails: not usable, the reset still deferred",
                vec![failed("the start pass failed")],
                Some(On),
                Ok(()),
                Some("the start pass failed".to_owned()),
                calls(&["passes"]),
                Some(On),
            ),
            (
                "the reset with the realm fails: it runs without the realm, then the passes again",
                vec![Ok(()), Ok(())],
                Some(On),
                failed("a password change is in progress, try again"),
                None,
                calls(&[
                    "passes",
                    "with the realm On",
                    &aside("On", "a password change is in progress, try again"),
                    "passes",
                ]),
                None,
            ),
            (
                "the same for an admin without sync",
                vec![Ok(()), Ok(())],
                Some(Off),
                failed("the realm was lost"),
                None,
                calls(&[
                    "passes",
                    "with the realm Off",
                    &aside("Off", "the realm was lost"),
                    "passes",
                ]),
                None,
            ),
            (
                "the passes after the reset without the realm fail: not usable, no second reset",
                vec![Ok(()), failed("the start pass failed")],
                Some(On),
                failed("refused by Kerberos: password policy: min_length 20"),
                Some("the start pass failed".to_owned()),
                calls(&[
                    "passes",
                    "with the realm On",
                    &aside("On", "refused by Kerberos: password policy: min_length 20"),
                    "passes",
                ]),
                None,
            ),
            (
                "the reset with the realm commits: nothing else",
                vec![Ok(())],
                Some(On),
                Ok(()),
                None,
                calls(&["passes", "with the realm On"]),
                None,
            ),
            (
                "no reset",
                vec![Ok(())],
                None,
                Ok(()),
                None,
                calls(&["passes"]),
                None,
            ),
        ];
        for (label, passes, deferred, answer, unusable, called, left) in rows {
            let calls = std::cell::RefCell::new(Vec::new());
            let answers = std::cell::RefCell::new(passes.into_iter());
            let (log, answers) = (&calls, &answers);
            let mut deferred = deferred;
            let got = before_serve(
                async || {
                    log.borrow_mut().push("passes".to_owned());
                    let next = answers.borrow_mut().next();
                    next.unwrap_or_else(|| failed("the passes ran once too often"))
                },
                &mut deferred,
                async move |sync: PasswordSync| {
                    log.borrow_mut().push(format!("with the realm {sync:?}"));
                    answer
                },
                async move |sync: PasswordSync, cause: String| {
                    log.borrow_mut().push(format!("aside {sync:?}: {cause}"));
                    Ok(())
                },
                "EXAMPLE.COM",
            )
            .await
            .unwrap();
            assert_eq!(
                (got.map(|e| e.to_string()), calls.into_inner(), deferred),
                (unusable, called, left),
                "{label}"
            );
        }
        let stopped = before_serve(
            async || Ok(()),
            &mut Some(On),
            async |_: PasswordSync| failed("busy"),
            async |_: PasswordSync, _: String| failed("the database is gone"),
            "EXAMPLE.COM",
        )
        .await;
        assert_eq!(
            stopped.map_err(|e| e.to_string()).map(|e| e.is_none()),
            Err("the database is gone".to_owned()),
            "only the directory's own failure stops the start"
        );
    }

    #[test]
    fn test_the_realm_set_aside_comes_back_after_a_panic() {
        let _one = crate::auth_service::tests::ONE_BACKEND.blocking_lock();
        let held = DegradedKerberos::new("EXAMPLE.COM".to_owned(), "held".to_owned());
        set_kerberos_backend(Arc::new(held));
        let inside = std::panic::catch_unwind(|| {
            let _aside = SetAside::new("EXAMPLE.COM".to_owned());
            let enabled = kerberos_backend().enabled();
            assert!(!enabled, "set aside: no realm takes part");
            panic!("the reset panicked");
        });
        let back = kerberos_backend().unavailable();
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        assert_eq!(
            (inside.is_err(), back),
            (true, Some("held".to_owned())),
            "the realm's backend is back after a panic inside the reset"
        );
    }

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

    #[test]
    fn test_the_first_start_counts_the_admin_password_in_characters() {
        let short = |n: usize| {
            Err(format!(
                "Minimum password length is 8 characters, got {n} characters"
            ))
        };
        let rows = [
            ("pässwö", (6, 8), short(6)),
            ("pässwör", (7, 9), short(7)),
            ("Seven-7", (7, 7), short(7)),
            ("pässwört", (8, 10), Ok(())),
            ("Eight-88", (8, 8), Ok(())),
        ];
        for (password, counts, expected) in rows {
            assert_eq!(
                (
                    (password.chars().count(), password.len()),
                    first_start_floor(password)
                ),
                (counts, expected),
                "{password}"
            );
        }
    }

    #[test]
    fn test_one_warning_when_the_admins_minimum_is_above_the_configured_password() {
        let rows = [
            (
                (9, 12),
                Some(
                    "The admin password in ldap_user_pass has 9 characters; the admin's \
                     password-min-length is 12: the configuration's password is checked against \
                     8 only, and a change of it is held to 12",
                ),
            ),
            ((12, 12), None),
            ((20, 8), None),
        ];
        for ((len, min), expected) in rows {
            assert_eq!(
                admin_min_length_warning(len, min).as_deref(),
                expected,
                "{len} {min}"
            );
        }
    }
}
