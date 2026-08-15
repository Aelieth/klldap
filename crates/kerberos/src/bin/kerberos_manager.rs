use anyhow::Result;
use lldap_kerberos::manager;

fn main() -> Result<()> {
    let bootstrap_only = std::env::args().any(|arg| arg == "--bootstrap-only");
    println!("Kerberos manager starting...");

    let (config, domain) = manager::load_config()?;
    manager::render_configs(&config, &domain)?;

    let admin_princ = manager::admin_principal(&config);
    let db_created = manager::bootstrap_kdb()?;

    // /data and /var/kerberos/krb5kdc are separate volumes; either can vanish.
    manager::ensure_admin_keytab(&admin_princ, db_created)?;

    if bootstrap_only {
        println!("Bootstrap complete (--bootstrap-only); not starting daemons.");
        return Ok(());
    }

    let (kdc_child, kadmind_child) = manager::spawn_daemons()?;
    manager::wait_kdc_ready()?;
    manager::populate_ccache(&admin_princ)?;
    manager::run_daemons_to_completion(kdc_child, kadmind_child)
}
