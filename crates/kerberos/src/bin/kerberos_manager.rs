use anyhow::Result;
use lldap_kerberos::manager;
use lldap_kerberos::paths::KerberosPaths;

fn main() -> Result<()> {
    let bootstrap_only = std::env::args().any(|arg| arg == "--bootstrap-only");
    println!("Kerberos manager starting...");

    let paths = KerberosPaths::from_env();
    let (config, domain) = manager::load_config(&paths)?;
    manager::render_configs(&config, &domain, &paths)?;

    let admin_princ = manager::admin_principal(&config);
    let db_created = manager::bootstrap_kdb(&paths)?;

    // /data and /var/kerberos/krb5kdc are separate volumes; either can vanish.
    manager::ensure_admin_keytab(&admin_princ, db_created, &paths)?;

    if bootstrap_only {
        println!("Bootstrap complete (--bootstrap-only); not starting daemons.");
        return Ok(());
    }

    let (kdc_child, kadmind_child) = manager::spawn_daemons()?;
    manager::wait_kdc_ready(&paths)?;
    manager::populate_ccache(&admin_princ, &paths)?;
    manager::run_daemons_to_completion(kdc_child, kadmind_child)
}
