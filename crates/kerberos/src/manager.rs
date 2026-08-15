//! KDC bootstrap and supervision used by the `kerberos_manager` binary.

use crate::paths::KerberosPaths;
use crate::{derive_realm_from_base_dn, domain_from_base_dn};
use anyhow::{Context, Result};
use minijinja::{Environment, context};
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Deserialize, Debug)]
pub struct KerberosConfig {
    pub realm_name: String,
    pub base_dn: String,
    pub ticket_lifetime: String,
    pub renew_lifetime: String,
    pub forwardable: bool,
    pub rdns: bool,
}

/// Run kadmin.local — only show output on error
fn run_kadmin_local(query: &str, paths: &KerberosPaths) -> Result<Output> {
    let output = Command::new("sudo")
        .arg("/usr/sbin/kadmin.local")
        .env("KRB5_CONFIG", &paths.krb5_conf)
        .arg("-q")
        .arg(query)
        .output()
        .context("Failed to spawn sudo kadmin.local")?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("kadmin.local failed!");
        if !stdout.trim().is_empty() {
            println!("stdout: {}", stdout.trim());
        }
        if !stderr.trim().is_empty() {
            println!("stderr: {}", stderr.trim());
        }
    }

    Ok(output)
}

#[derive(Debug, PartialEq)]
enum KeytabAction {
    UpToDate,
    Regenerate { create_principal: bool },
}

fn plan_admin_keytab(keytab_exists: bool, db_created: bool) -> KeytabAction {
    match (keytab_exists, db_created) {
        (true, false) => KeytabAction::UpToDate,
        (_, true) => KeytabAction::Regenerate {
            create_principal: true,
        },
        (false, false) => KeytabAction::Regenerate {
            create_principal: false,
        },
    }
}

pub fn ensure_admin_keytab(
    admin_princ: &str,
    db_created: bool,
    paths: &KerberosPaths,
) -> Result<()> {
    let create_principal = match plan_admin_keytab(paths.admin_keytab.exists(), db_created) {
        KeytabAction::UpToDate => return Ok(()),
        KeytabAction::Regenerate { create_principal } => create_principal,
    };

    if create_principal {
        println!("Creating admin principal with random key: {}", admin_princ);
        let add_output = run_kadmin_local(&format!("addprinc -randkey {}", admin_princ), paths)?;
        if !add_output.status.success() {
            anyhow::bail!("addprinc failed for {}", admin_princ);
        }
        let _ = fs::remove_file(&paths.admin_keytab);
    } else {
        println!(
            "Admin keytab {} missing — regenerating from existing KDC database.",
            paths.admin_keytab.display()
        );
    }

    // ktadd rotates the kvno; safe here since this keytab is the only consumer of the
    // admin principal's key.
    let ktadd_output = run_kadmin_local(
        &format!("ktadd -k {} {}", paths.admin_keytab.display(), admin_princ),
        paths,
    )?;
    if !ktadd_output.status.success() {
        anyhow::bail!("ktadd failed — Kerberos admin operations will fail");
    }

    ensure_admin_keytab_ownership(paths)?;

    if !paths.admin_keytab.exists() {
        anyhow::bail!("admin keytab still missing after ktadd");
    }
    println!("Admin keytab ready at {}.", paths.admin_keytab.display());
    Ok(())
}

fn ensure_admin_keytab_ownership(paths: &KerberosPaths) -> Result<()> {
    let status = Command::new("sudo")
        .arg("chown")
        .arg("lldap:lldap")
        .arg(&paths.admin_keytab)
        .status()
        .context("Failed to chown keytab")?;
    if !status.success() {
        anyhow::bail!("chown keytab failed");
    }
    fs::set_permissions(&paths.admin_keytab, fs::Permissions::from_mode(0o640))
        .context("Failed to chmod keytab")?;
    Ok(())
}

/// Load the Kerberos config (copy the template on first run) and resolve realm/DN.
pub fn load_config(paths: &KerberosPaths) -> Result<(KerberosConfig, String)> {
    if !paths.kerberos_config.exists() {
        println!("Kerberos config not found. Copying template...");
        fs::copy(&paths.kerberos_config_template, &paths.kerberos_config)
            .context("Failed to copy config template")?;
    }

    let toml_str = fs::read_to_string(&paths.kerberos_config)
        .context("Failed to read kerberos_config.toml")?;
    let full_config: toml::Table = toml::from_str(&toml_str).context("Failed to parse TOML")?;

    let kerberos_value = full_config
        .get("kerberos")
        .context("Missing [kerberos] table")?
        .clone();
    let mut config: KerberosConfig = kerberos_value
        .try_into()
        .context("Failed to deserialize [kerberos]")?;

    config.realm_name = derive_realm_from_base_dn();
    config.base_dn = env::var("LLDAP_LDAP_BASE_DN").unwrap_or_else(|_| config.base_dn.clone());
    let domain = domain_from_base_dn(&config.base_dn);

    println!("Calculated DOMAIN: {}", domain);
    println!("Effective REALM_NAME: {}", config.realm_name);
    Ok((config, domain))
}

pub fn admin_principal(config: &KerberosConfig) -> String {
    format!("admin/admin@{}", config.realm_name.to_uppercase())
}

/// Render krb5.conf, kdc.conf, and kadm5.acl; copy the Keycloak config on first run.
pub fn render_configs(config: &KerberosConfig, domain: &str, paths: &KerberosPaths) -> Result<()> {
    fs::create_dir_all(&paths.kdc_dir).context("Failed to create krb5kdc dir")?;
    render_template(&paths.krb5_template, &paths.krb5_conf, config, domain)?;
    render_template(&paths.kdc_template, &paths.kdc_conf, config, domain)?;
    ensure_kadm5_acl(&paths.kadm5_acl, &paths.kadm5_acl_template, config, domain)?;

    if !paths.keycloak_config.exists() {
        println!("Keycloak config not found. Copying template...");
        fs::copy(&paths.keycloak_template, &paths.keycloak_config)
            .context("Failed to copy keycloak_config.template.toml")?;
        Command::new("sudo")
            .arg("chown")
            .arg("lldap:lldap")
            .arg(&paths.keycloak_config)
            .status()
            .context("Failed to chown keycloak_config.toml")?;
        println!("Created default keycloak_config.toml in /data");
    } else {
        println!("Existing keycloak_config.toml found — skipping template copy.");
    }
    Ok(())
}

/// Create the KDC database if it does not exist (password-less: random master password,
/// stash only). Returns whether the database was created on this run.
pub fn bootstrap_kdb(paths: &KerberosPaths) -> Result<bool> {
    let db_created = !paths.kdc_principal().exists();

    if db_created {
        println!("First run detected — no KDC database. Bootstrapping password-less...");

        let master_pass_output = Command::new("openssl")
            .arg("rand")
            .arg("-hex")
            .arg("32")
            .output()
            .context("Failed to generate random master password")?;
        let master_pass = String::from_utf8_lossy(&master_pass_output.stdout)
            .trim()
            .to_string();
        println!(
            "Generated random master password (length: {} chars).",
            master_pass.len()
        );

        println!("Creating KDC database with piped password...");
        let mut child = Command::new("sudo")
            .arg("kdb5_util")
            .env("KRB5_CONFIG", &paths.krb5_conf)
            .arg("create")
            .arg("-s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn sudo kdb5_util")?;

        if let Some(mut stdin) = child.stdin.take() {
            writeln!(stdin, "{}", master_pass)?;
            writeln!(stdin, "{}", master_pass)?;
        }

        let output = child
            .wait_with_output()
            .context("Failed to wait on kdb5_util")?;
        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "kdb5_util failed!\nstdout: {}\nstderr: {}",
                stdout.trim(),
                stderr.trim()
            );
        }
        println!("KDC database created successfully.");

        Command::new("sudo")
            .arg("chown")
            .arg("-R")
            .arg("lldap:lldap")
            .arg(&paths.kdc_dir)
            .status()
            .context("Failed to chown DB dir")?;
        println!("Ownership set on DB files.");
    } else {
        println!("Existing KDC database detected — skipping database creation.");
    }
    Ok(db_created)
}

pub fn spawn_daemons() -> Result<(Child, Child)> {
    println!("Starting krb5kdc...");
    let kdc_child = Command::new("/usr/sbin/krb5kdc")
        .spawn()
        .context("Failed to start krb5kdc")?;

    println!("Starting kadmind...");
    let kadmind_child = Command::new("/usr/sbin/kadmind")
        .spawn()
        .context("Failed to start kadmind")?;
    Ok((kdc_child, kadmind_child))
}

/// Fail if the KDC does not accept connections on its configured port within 60s.
pub fn wait_kdc_ready(paths: &KerberosPaths) -> Result<()> {
    println!("Waiting for KDC on port {}...", paths.kdc_port);
    for _ in 0..60 {
        if TcpStream::connect(("localhost", paths.kdc_port)).is_ok() {
            println!("KDC ready on port {}.", paths.kdc_port);
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    anyhow::bail!(
        "KDC did not accept connections on port {} within 60s",
        paths.kdc_port
    )
}

pub fn populate_ccache(admin_princ: &str, paths: &KerberosPaths) -> Result<()> {
    if paths.admin_keytab.exists() {
        println!(
            "Populating ccache with keytab (daemons ready): {}",
            admin_princ
        );
        let kinit_output = Command::new("/usr/bin/kinit")
            .env("KRB5_CONFIG", &paths.krb5_conf)
            .arg("-k")
            .arg("-t")
            .arg(&paths.admin_keytab)
            .arg(admin_princ)
            .output()
            .context("Failed kinit")?;

        if !kinit_output.status.success() {
            anyhow::bail!("kinit failed");
        }
        println!("ccache populated — Kerberos sync fully password-less.");
    }
    Ok(())
}

/// Block until either daemon exits; both must exit cleanly for this to be Ok.
pub fn run_daemons_to_completion(mut kdc: Child, mut kadmind: Child) -> Result<()> {
    let kdc_status = kdc.wait().context("krb5kdc exited unexpectedly")?;
    let kadmind_status = kadmind.wait().context("kadmind exited unexpectedly")?;

    if !kdc_status.success() || !kadmind_status.success() {
        return Err(anyhow::anyhow!("Kerberos service failed"));
    }
    Ok(())
}

fn render_template(
    template_path: &Path,
    output_path: &Path,
    config: &KerberosConfig,
    domain: &str,
) -> Result<()> {
    let template_str = fs::read_to_string(template_path)
        .with_context(|| format!("Failed to read template: {}", template_path.display()))?;

    let mut env = Environment::new();
    env.add_template("template", &template_str)?;

    let tmpl = env.get_template("template")?;
    let rendered = tmpl.render(context! {
        TICKET_LIFETIME => config.ticket_lifetime,
        RENEW_LIFETIME => config.renew_lifetime,
        FORWARDABLE => config.forwardable,
        RDNS => config.rdns,
        REALM_NAME => config.realm_name,
        DOMAIN => domain,
    })?;

    fs::write(output_path, rendered)
        .with_context(|| format!("Failed to write {}", output_path.display()))?;
    println!("Generated {} successfully.", output_path.display());

    Ok(())
}

/// Ensure kadm5.acl is readable, grants `admin/admin@REALM *`, and is parseable.
fn ensure_kadm5_acl(
    acl_path: &Path,
    template_path: &Path,
    config: &KerberosConfig,
    domain: &str,
) -> Result<()> {
    let admin_princ = format!("admin/admin@{}", config.realm_name.to_uppercase());
    let required_line = format!("{}    *", admin_princ);

    if !acl_path.exists() {
        render_template(template_path, acl_path, config, domain)?;
        let _ = apply_permissions(acl_path);
        return Ok(());
    }

    let original_content = match fs::read_to_string(acl_path) {
        Ok(c) => c,
        Err(_) => {
            let _ = apply_permissions(acl_path);
            fs::read_to_string(acl_path)
                .context("kadm5.acl still unreadable after permission repair")?
        }
    };

    let _ = apply_permissions_if_needed(acl_path);

    let has_admin = has_sufficient_admin_entry(&original_content, &admin_princ);
    let sane = acl_structure_looks_valid(&original_content);

    if has_admin && sane {
        return Ok(());
    }

    match best_effort_repair_or_standardize(&original_content, &admin_princ, &required_line) {
        Some(repaired) => {
            if repaired.trim() != original_content.trim() {
                fs::write(acl_path, repaired).context("Failed to write repaired kadm5.acl")?;
                println!("Updated kadm5.acl (ensured local admin rights / standardized format).");
            }
        }
        None => {
            render_template(template_path, acl_path, config, domain)?;
        }
    }

    let _ = apply_permissions_if_needed(acl_path);
    Ok(())
}

fn apply_permissions(path: &Path) -> Result<()> {
    let perms = fs::Permissions::from_mode(0o644);
    fs::set_permissions(path, perms).context("Failed to set 0644 permissions on kadm5.acl")?;

    #[cfg(not(test))]
    {
        let _ = Command::new("sudo")
            .arg("chown")
            .arg("lldap:lldap")
            .arg(path)
            .status();
    }

    Ok(())
}

fn apply_permissions_if_needed(path: &Path) -> Result<()> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return apply_permissions(path),
    };
    let mode = meta.permissions().mode();
    if (mode & 0o644) != 0o644 {
        apply_permissions(path)?;
    }
    Ok(())
}

/// True when the file already contains a line granting the given admin principal full rights.
fn has_sufficient_admin_entry(content: &str, admin_princ: &str) -> bool {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let first = trimmed.split_whitespace().next();
        if first == Some(admin_princ) && trimmed.contains('*') {
            return true;
        }
    }
    false
}

/// Lightweight sanity check for kadm5.acl format.
/// Requires ≥1 data line and at least one line that looks like a principal + permissions.
fn acl_structure_looks_valid(content: &str) -> bool {
    let mut data_lines = 0usize;
    let mut valid_lines = 0usize;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        data_lines += 1;
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            let principal = parts[0];
            if principal.contains('@') || principal.contains('/') {
                valid_lines += 1;
            }
        }
    }

    if data_lines == 0 {
        return false;
    }

    valid_lines > 0
}

/// Repair ACL content: keep comments and other principals, force the admin `*` grant.
/// `None` means the file is too garbled — caller rewrites from the template.
fn best_effort_repair_or_standardize(
    content: &str,
    admin_princ: &str,
    required_line: &str,
) -> Option<String> {
    let mut output_lines: Vec<String> = Vec::new();
    let mut saw_admin_with_star = false;
    let mut bad_data_lines = 0usize;
    let mut total_data_lines = 0usize;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            output_lines.push(String::new());
            continue;
        }
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            output_lines.push(trimmed.to_string());
            continue;
        }

        total_data_lines += 1;
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            bad_data_lines += 1;
            continue;
        }

        let principal = parts[0];
        if principal == admin_princ {
            output_lines.push(required_line.to_string());
            saw_admin_with_star = true;
            continue;
        }

        output_lines.push(trimmed.to_string());
    }

    if !saw_admin_with_star {
        output_lines.push(required_line.to_string());
    }

    let too_garbled = total_data_lines > 0
        && (bad_data_lines > 2 || (bad_data_lines as f32 / total_data_lines as f32) > 0.5);

    if too_garbled {
        return None;
    }

    let mut result = output_lines.join("\n");
    if !result.ends_with('\n') {
        result.push('\n');
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn test_plan_admin_keytab_healthy_restart_is_noop() {
        assert_eq!(plan_admin_keytab(true, false), KeytabAction::UpToDate);
    }

    #[test]
    fn test_plan_admin_keytab_missing_with_existing_db_regenerates() {
        assert_eq!(
            plan_admin_keytab(false, false),
            KeytabAction::Regenerate {
                create_principal: false
            }
        );
    }

    #[test]
    fn test_plan_admin_keytab_first_run_creates_principal() {
        assert_eq!(
            plan_admin_keytab(false, true),
            KeytabAction::Regenerate {
                create_principal: true
            }
        );
    }

    #[test]
    fn test_plan_admin_keytab_fresh_db_overwrites_stale_keytab() {
        assert_eq!(
            plan_admin_keytab(true, true),
            KeytabAction::Regenerate {
                create_principal: true
            }
        );
    }

    fn with_temp_acl_setup<F>(f: F)
    where
        F: FnOnce(&Path, &Path),
    {
        let pid = std::process::id();
        let seq = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("kadm5_acl_test_{pid}_{seq}"));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("failed to create temp test dir for kadm5 acl tests");

        let template_path = base.join("kadm5.template.acl");
        let acl_path = base.join("kadm5.acl");

        fs::write(&template_path, "admin/admin@{{ REALM_NAME }}    *\n")
            .expect("failed to write test template");

        f(&template_path, &acl_path);

        let _ = fs::remove_dir_all(&base);
    }

    fn make_test_config(realm: &str) -> KerberosConfig {
        KerberosConfig {
            realm_name: realm.to_string(),
            base_dn: "dc=test,dc=example".to_string(),
            ticket_lifetime: "24h".to_string(),
            renew_lifetime: "7d".to_string(),
            forwardable: true,
            rdns: false,
        }
    }

    #[test]
    fn test_has_sufficient_admin_entry() {
        let admin = "admin/admin@TEST.EXAMPLE";
        let good = format!("{}    *", admin);
        let weak = format!("{}    l", admin);
        let other = "service/HTTP@TEST.EXAMPLE    x";

        assert!(has_sufficient_admin_entry(&good, admin));
        assert!(has_sufficient_admin_entry(
            &format!("# comment\n{}", good),
            admin
        ));
        assert!(has_sufficient_admin_entry(
            &format!("{}\n{}", other, good),
            admin
        ));

        assert!(!has_sufficient_admin_entry(&weak, admin));
        assert!(!has_sufficient_admin_entry(other, admin));
        assert!(!has_sufficient_admin_entry("", admin));
        assert!(!has_sufficient_admin_entry("# only comments here", admin));
    }

    #[test]
    fn test_acl_structure_looks_valid() {
        assert!(acl_structure_looks_valid("admin/admin@TEST.EXAMPLE    *"));
        assert!(acl_structure_looks_valid(
            "# comments allowed\nservice/HTTP@TEST.EXAMPLE    x\nadmin/admin@TEST.EXAMPLE    *"
        ));
        assert!(acl_structure_looks_valid("foo/bar@REALM    a"));
        assert!(!acl_structure_looks_valid(""));
        assert!(!acl_structure_looks_valid(
            "# only comments and blank lines\n\n"
        ));
        assert!(!acl_structure_looks_valid("this line has no second token"));
        assert!(!acl_structure_looks_valid(
            "!!!garbage!!!\njust one token\nno at sign or slash here at all"
        ));
    }

    #[test]
    fn test_best_effort_repair_adds_admin_and_preserves_others() {
        let admin = "admin/admin@TEST.EXAMPLE";
        let required = format!("{}    *", admin);

        let input =
            "# my custom rules\nservice/HTTP@TEST.EXAMPLE    x\nother/admin@TEST.EXAMPLE    l\n\n";
        let result =
            best_effort_repair_or_standardize(input, admin, &required).expect("should salvage");

        assert!(result.contains(&required), "admin with * must be present");
        assert!(result.contains("service/HTTP@TEST.EXAMPLE    x"));
        assert!(result.contains("other/admin@TEST.EXAMPLE    l"));
        assert!(result.contains("# my custom rules"));
        assert!(result.ends_with('\n'));
    }

    #[test]
    fn test_best_effort_repair_upgrades_weak_admin_and_adds_if_missing() {
        let admin = "admin/admin@TEST.EXAMPLE";
        let required = format!("{}    *", admin);

        let input = "admin/admin@TEST.EXAMPLE    l\n# keep this";
        let result = best_effort_repair_or_standardize(input, admin, &required).unwrap();
        assert!(result.contains(&required));
        assert!(!result.contains("admin/admin@TEST.EXAMPLE    l"));
        assert!(result.contains("# keep this"));

        let input2 = "some/service@TEST.EXAMPLE    x";
        let result2 = best_effort_repair_or_standardize(input2, admin, &required).unwrap();
        assert!(result2.contains(&required));
        assert!(result2.contains("some/service@TEST.EXAMPLE    x"));
    }

    #[test]
    fn test_best_effort_repair_returns_none_for_too_garbled() {
        let admin = "admin/admin@TEST.EXAMPLE";
        let required = format!("{}    *", admin);

        let garbled = "!!!\nfoo bar\n!!!\nno second token here\n!!!";
        assert!(
            best_effort_repair_or_standardize(garbled, admin, &required).is_none(),
            "should signal remake for heavily corrupted input"
        );

        let comments_only = "# nothing useful\n; also nothing\n";
        let res = best_effort_repair_or_standardize(comments_only, admin, &required).unwrap();
        assert!(res.contains(&required));
    }

    #[test]
    fn test_ensure_kadm5_acl_creates_default_when_missing() {
        with_temp_acl_setup(|template, acl| {
            let config = make_test_config("TEST.EXAMPLE");

            assert!(!acl.exists());

            ensure_kadm5_acl(acl, template, &config, "example")
                .expect("ensure should succeed on create path");

            let content = fs::read_to_string(acl).expect("acl should exist after ensure");
            assert!(
                content.contains("admin/admin@TEST.EXAMPLE    *"),
                "default admin line must be present"
            );
            assert!(content.trim() == "admin/admin@TEST.EXAMPLE    *");
        });
    }

    #[test]
    fn test_ensure_kadm5_acl_repairs_adds_admin_preserves_custom_and_noops_when_good() {
        with_temp_acl_setup(|template, acl| {
            let config = make_test_config("TEST.EXAMPLE");
            let required_line = "admin/admin@TEST.EXAMPLE    *";

            let initial =
                "# custom comment\nservice/HTTP@TEST.EXAMPLE    x\nrestricted@TEST.EXAMPLE    l\n";
            fs::write(acl, initial).unwrap();

            ensure_kadm5_acl(acl, template, &config, "example")
                .expect("repair ensure should succeed");

            let repaired = fs::read_to_string(acl).unwrap();
            assert!(
                repaired.contains(required_line),
                "should have added full admin"
            );
            assert!(repaired.contains("service/HTTP@TEST.EXAMPLE    x"));
            assert!(repaired.contains("restricted@TEST.EXAMPLE    l"));
            assert!(repaired.contains("# custom comment"));

            let good = "# production custom ACL\nservice/HTTP@TEST.EXAMPLE    x\nadmin/admin@TEST.EXAMPLE    *\nanother@TEST.EXAMPLE    a\n";
            fs::write(acl, good).unwrap();

            let before = fs::read_to_string(acl).unwrap();
            ensure_kadm5_acl(acl, template, &config, "example")
                .expect("noop ensure should succeed");
            let after = fs::read_to_string(acl).unwrap();

            assert_eq!(
                before, after,
                "good ACL with custom entries must not be modified"
            );
            assert!(after.contains(required_line));
            assert!(after.contains("another@TEST.EXAMPLE    a"));

            let garbage = "total\nnonsense\nwith no useful principal lines at all\n!!!\n";
            fs::write(acl, garbage).unwrap();

            ensure_kadm5_acl(acl, template, &config, "example")
                .expect("remake on garbled should succeed");

            let remade = fs::read_to_string(acl).unwrap();
            assert_eq!(remade.trim(), required_line);
        });
    }
}
