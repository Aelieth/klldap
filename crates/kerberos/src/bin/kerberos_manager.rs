use anyhow::{Context, Result};
use lldap_kerberos::{derive_realm_from_base_dn, domain_from_base_dn};
use minijinja::{Environment, context};
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Deserialize, Debug)]
struct KerberosConfig {
    realm_name: String,
    base_dn: String,
    ticket_lifetime: String,
    renew_lifetime: String,
    forwardable: bool,
    rdns: bool,
}

const ADMIN_KEYTAB_PATH: &str = "/data/kadm5.keytab";

/// Run kadmin.local — only show output on error
fn run_kadmin_local(query: &str) -> Result<Output> {
    let output = Command::new("sudo")
        .arg("/usr/sbin/kadmin.local")
        .env("KRB5_CONFIG", "/etc/krb5.conf")
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

fn ensure_admin_keytab(admin_princ: &str, db_created: bool) -> Result<()> {
    let create_principal =
        match plan_admin_keytab(Path::new(ADMIN_KEYTAB_PATH).exists(), db_created) {
            KeytabAction::UpToDate => return Ok(()),
            KeytabAction::Regenerate { create_principal } => create_principal,
        };

    if create_principal {
        println!("Creating admin principal with random key: {}", admin_princ);
        let add_output = run_kadmin_local(&format!("addprinc -randkey {}", admin_princ))?;
        if !add_output.status.success() {
            anyhow::bail!("addprinc failed for {}", admin_princ);
        }
        let _ = fs::remove_file(ADMIN_KEYTAB_PATH);
    } else {
        println!(
            "Admin keytab {} missing — regenerating from existing KDC database.",
            ADMIN_KEYTAB_PATH
        );
    }

    // ktadd rotates the kvno; safe here since this keytab is the only consumer of the
    // admin principal's key.
    let ktadd_output =
        run_kadmin_local(&format!("ktadd -k {} {}", ADMIN_KEYTAB_PATH, admin_princ))?;
    if !ktadd_output.status.success() {
        anyhow::bail!("ktadd failed — Kerberos admin operations will fail");
    }

    ensure_admin_keytab_ownership()?;

    if !Path::new(ADMIN_KEYTAB_PATH).exists() {
        anyhow::bail!("admin keytab still missing after ktadd");
    }
    println!("Admin keytab ready at {}.", ADMIN_KEYTAB_PATH);
    Ok(())
}

fn ensure_admin_keytab_ownership() -> Result<()> {
    let status = Command::new("sudo")
        .arg("chown")
        .arg("lldap:lldap")
        .arg(ADMIN_KEYTAB_PATH)
        .status()
        .context("Failed to chown keytab")?;
    if !status.success() {
        anyhow::bail!("chown keytab failed");
    }
    fs::set_permissions(ADMIN_KEYTAB_PATH, fs::Permissions::from_mode(0o640))
        .context("Failed to chmod keytab")?;
    Ok(())
}

fn main() -> Result<()> {
    println!("Kerberos manager starting...");

    // Paths
    let config_path = "/data/kerberos_config.toml";
    let template_path = "/app/kerberos_config.template.toml";

    if !Path::new(config_path).exists() {
        println!("Kerberos config not found. Copying template...");
        fs::copy(template_path, config_path).context("Failed to copy config template")?;
    }

    // Load TOML
    let toml_str =
        fs::read_to_string(config_path).context("Failed to read kerberos_config.toml")?;
    let full_config: toml::Table = toml::from_str(&toml_str).context("Failed to parse TOML")?;

    let kerberos_value = full_config
        .get("kerberos")
        .context("Missing [kerberos] table")?
        .clone();
    let mut config: KerberosConfig = kerberos_value
        .try_into()
        .context("Failed to deserialize [kerberos]")?;

    let realm_name = derive_realm_from_base_dn();
    config.realm_name = realm_name.clone();

    let base_dn = env::var("LLDAP_LDAP_BASE_DN").unwrap_or_else(|_| config.base_dn.clone());
    config.base_dn = base_dn.clone();

    let domain = domain_from_base_dn(&base_dn);

    println!("Calculated DOMAIN: {}", domain);
    println!("Effective REALM_NAME: {}", config.realm_name);

    // Render templates
    fs::create_dir_all("/var/kerberos/krb5kdc").context("Failed to create krb5kdc dir")?;
    render_template(
        "/app/krb5.template.conf",
        "/etc/krb5.conf",
        &config,
        &domain,
    )?;
    render_template(
        "/app/kdc.template.conf",
        "/var/kerberos/krb5kdc/kdc.conf",
        &config,
        &domain,
    )?;
    ensure_kadm5_acl(
        "/var/kerberos/krb5kdc/kadm5.acl",
        "/app/kadm5.template.acl",
        &config,
        &domain,
    )?;

    // Keycloak config
    let keycloak_config_path = "/data/keycloak_config.toml";
    let keycloak_template_path = "/app/keycloak_config.template.toml";

    if !Path::new(keycloak_config_path).exists() {
        println!("Keycloak config not found. Copying template...");
        fs::copy(keycloak_template_path, keycloak_config_path)
            .context("Failed to copy keycloak_config.template.toml")?;
        // Name-based chown kept for the same sanity-check reason (see the keytab chown above).
        Command::new("sudo")
            .arg("chown")
            .arg("lldap:lldap")
            .arg(keycloak_config_path)
            .status()
            .context("Failed to chown keycloak_config.toml")?;
        println!("Created default keycloak_config.toml in /data");
    } else {
        println!("Existing keycloak_config.toml found — skipping template copy.");
    }

    // --- Kerberos Bootstrap ---
    let db_path = Path::new("/var/kerberos/krb5kdc/principal");
    let admin_princ = format!("admin/admin@{}", config.realm_name.to_uppercase());
    let db_created = !db_path.exists();

    if db_created {
        println!("First run detected — no KDC database. Bootstrapping password-less...");

        // Generate random master password (in-memory only)
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
            .env("KRB5_CONFIG", "/etc/krb5.conf")
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

        // The Dockerfile guarantees the user/group exist; this acts as a runtime assertion
        // that the expected non-root identity for LLDAP artifacts is present.
        Command::new("sudo")
            .arg("chown")
            .arg("-R")
            .arg("lldap:lldap")
            .arg("/var/kerberos/krb5kdc")
            .status()
            .context("Failed to chown DB dir")?;
        println!("Ownership set on DB files.");
    } else {
        println!("Existing KDC database detected — skipping database creation.");
    }

    // /data and /var/kerberos/krb5kdc are separate volumes; either can vanish.
    ensure_admin_keytab(&admin_princ, db_created)?;

    // Start daemons
    println!("Starting krb5kdc...");
    let mut kdc_child = Command::new("/usr/sbin/krb5kdc")
        .spawn()
        .context("Failed to start krb5kdc")?;

    println!("Starting kadmind...");
    let mut kadmind_child = Command::new("/usr/sbin/kadmind")
        .spawn()
        .context("Failed to start kadmind")?;

    // Wait for KDC
    println!("Waiting for KDC on port 88...");
    for _ in 0..60 {
        if TcpStream::connect(("localhost", 88)).is_ok() {
            println!("KDC ready on port 88.");
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    // Populate ccache
    if Path::new(ADMIN_KEYTAB_PATH).exists() {
        println!(
            "Populating ccache with keytab (daemons ready): {}",
            admin_princ
        );
        let kinit_output = Command::new("/usr/bin/kinit")
            .env("KRB5_CONFIG", "/etc/krb5.conf")
            .arg("-k")
            .arg("-t")
            .arg(ADMIN_KEYTAB_PATH)
            .arg(&admin_princ)
            .output()
            .context("Failed kinit")?;

        if !kinit_output.status.success() {
            anyhow::bail!("kinit failed");
        }
        println!("ccache populated — Kerberos sync fully password-less.");
    }

    // Block on children
    let kdc_status = kdc_child.wait().context("krb5kdc exited unexpectedly")?;
    let kadmind_status = kadmind_child
        .wait()
        .context("kadmind exited unexpectedly")?;

    if !kdc_status.success() || !kadmind_status.success() {
        return Err(anyhow::anyhow!("Kerberos service failed"));
    }

    Ok(())
}

fn render_template(
    template_path: &str,
    output_path: &str,
    config: &KerberosConfig,
    domain: &str,
) -> Result<()> {
    let template_str = fs::read_to_string(template_path)
        .context(format!("Failed to read template: {}", template_path))?;

    let mut env = Environment::new();
    env.add_template("template", &template_str)?;

    let tmpl = env.get_template("template").unwrap();
    let rendered = tmpl.render(context! {
        TICKET_LIFETIME => config.ticket_lifetime,
        RENEW_LIFETIME => config.renew_lifetime,
        FORWARDABLE => config.forwardable,
        RDNS => config.rdns,
        REALM_NAME => config.realm_name,
        DOMAIN => domain,
    })?;

    fs::write(output_path, rendered).context(format!("Failed to write {}", output_path))?;
    println!("Generated {} successfully.", output_path);

    Ok(())
}

/// Ensure the kadm5.acl has sane permissions, is readable, contains the required
/// local admin principal with full rights, and has a parseable structure.
///
/// Follows the 5 rules:
/// 1. If missing → create from template (default).
/// 2. If unreadable or bad permissions → repair permissions (0644 + lldap:lldap).
/// 3. Ensure the local admin/admin@REALM has the default full (*) permissions (add/upgrade if needed).
/// 4. If structure looks wrong, best-effort repair (preserve other entries + comments); fall back to template remake if too garbled.
/// 5. If the file is present, readable, correctly permissioned, has the admin grant, and looks structurally valid → do nothing.
fn ensure_kadm5_acl(
    acl_path: &str,
    template_path: &str,
    config: &KerberosConfig,
    domain: &str,
) -> Result<()> {
    let admin_princ = format!("admin/admin@{}", config.realm_name.to_uppercase());
    let required_line = format!("{}    *", admin_princ);

    if !Path::new(acl_path).exists() {
        // 1. Create default from the shipped template.
        render_template(template_path, acl_path, config, domain)?;
        let _ = apply_permissions(acl_path);
        return Ok(());
    }

    // 2. Exists — attempt read. Recover via permission fix if needed.
    let original_content = match fs::read_to_string(acl_path) {
        Ok(c) => c,
        Err(_) => {
            let _ = apply_permissions(acl_path);
            fs::read_to_string(acl_path)
                .context("kadm5.acl still unreadable after permission repair")?
        }
    };

    // Make sure permissions allow reading (even if the read above succeeded).
    let _ = apply_permissions_if_needed(acl_path);

    // 3 + 4. Check for required admin rights and basic structural validity.
    let has_admin = has_sufficient_admin_entry(&original_content, &admin_princ);
    let sane = acl_structure_looks_valid(&original_content);

    if has_admin && sane {
        return Ok(());
    }

    // Needs repair or the admin line.
    match best_effort_repair_or_standardize(&original_content, &admin_princ, &required_line) {
        Some(repaired) => {
            if repaired.trim() != original_content.trim() {
                fs::write(acl_path, repaired).context("Failed to write repaired kadm5.acl")?;
                // Action taken — brief note is appropriate (persistent file was mutated).
                println!("Updated kadm5.acl (ensured local admin rights / standardized format).");
            }
        }
        None => {
            // 4. Too garbled to safely repair — full remake from the known-good template.
            render_template(template_path, acl_path, config, domain)?;
        }
    }

    let _ = apply_permissions_if_needed(acl_path);
    Ok(())
}

fn apply_permissions(path: &str) -> Result<()> {
    let perms = fs::Permissions::from_mode(0o644);
    fs::set_permissions(path, perms).context("Failed to set 0644 permissions on kadm5.acl")?;

    // Align ownership with the rest of the krb5kdc volume (best-effort; we are root).
    // Skip the chown in tests (avoids "invalid user lldap" noise and sudo dependency).
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

fn apply_permissions_if_needed(path: &str) -> Result<()> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return apply_permissions(path),
    };
    let mode = meta.permissions().mode();
    // Require the classic readable bits that kadmind (and tools) expect.
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

    // For the normal 1-line default or small custom ACLs, a single valid entry is sufficient.
    valid_lines > 0
}

/// Best-effort repair / standardization.
/// - Preserves comments (# or ;) and blank lines.
/// - Forces the exact required admin line with "*" (adds it or upgrades existing rights for it).
/// - Keeps other custom principal entries (best effort, lightly normalized).
/// - Returns None when the content is too corrupted to trust (caller will do full template rewrite).
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
            // Drop unparseable data lines during repair (they would break kadmind anyway).
            continue;
        }

        let principal = parts[0];
        if principal == admin_princ {
            output_lines.push(required_line.to_string());
            saw_admin_with_star = true;
            continue;
        }

        // Preserve other entries exactly (after trim). This keeps the user's
        // original spacing, any target principal column, and custom formatting.
        output_lines.push(trimmed.to_string());
    }

    if !saw_admin_with_star {
        output_lines.push(required_line.to_string());
    }

    // Garbled threshold: if a majority of real data lines were bad (or >2 bad on larger files),
    // signal that we should just rewrite from the pristine template.
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

    /// Helper that sets up an isolated temp directory with a minimal kadm5 template
    /// (only needs REALM_NAME) and yields paths for the test body. Cleans up after.
    fn with_temp_acl_setup<F>(f: F)
    where
        F: FnOnce(&Path, &Path),
    {
        let pid = std::process::id();
        let seq = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("kadm5_acl_test_{pid}_{seq}"));
        // Start clean
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("failed to create temp test dir for kadm5 acl tests");

        let template_path = base.join("kadm5.template.acl");
        let acl_path = base.join("kadm5.acl");

        // Minimal template matching the shape of the real one (ACL only uses REALM_NAME).
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
        // Good cases
        assert!(acl_structure_looks_valid("admin/admin@TEST.EXAMPLE    *"));
        assert!(acl_structure_looks_valid(
            "# comments allowed\nservice/HTTP@TEST.EXAMPLE    x\nadmin/admin@TEST.EXAMPLE    *"
        ));

        // At least one recognizable principal+perm line is enough (our default case)
        assert!(acl_structure_looks_valid("foo/bar@REALM    a"));

        // Bad cases
        assert!(!acl_structure_looks_valid(""));
        assert!(!acl_structure_looks_valid(
            "# only comments and blank lines\n\n"
        ));
        assert!(!acl_structure_looks_valid("this line has no second token"));
        // Lines either have <2 tokens or the first token doesn't look like a principal (no @ or /)
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
        // Should end with newline
        assert!(result.ends_with('\n'));
    }

    #[test]
    fn test_best_effort_repair_upgrades_weak_admin_and_adds_if_missing() {
        let admin = "admin/admin@TEST.EXAMPLE";
        let required = format!("{}    *", admin);

        // Existing admin line but weak rights
        let input = "admin/admin@TEST.EXAMPLE    l\n# keep this";
        let result = best_effort_repair_or_standardize(input, admin, &required).unwrap();
        // The weak line should have been replaced by the full-rights one
        assert!(result.contains(&required));
        assert!(!result.contains("admin/admin@TEST.EXAMPLE    l"));
        assert!(result.contains("# keep this"));

        // No admin at all
        let input2 = "some/service@TEST.EXAMPLE    x";
        let result2 = best_effort_repair_or_standardize(input2, admin, &required).unwrap();
        assert!(result2.contains(&required));
        assert!(result2.contains("some/service@TEST.EXAMPLE    x"));
    }

    #[test]
    fn test_best_effort_repair_returns_none_for_too_garbled() {
        let admin = "admin/admin@TEST.EXAMPLE";
        let required = format!("{}    *", admin);

        // Mostly bad data lines
        let garbled = "!!!\nfoo bar\n!!!\nno second token here\n!!!";
        assert!(
            best_effort_repair_or_standardize(garbled, admin, &required).is_none(),
            "should signal remake for heavily corrupted input"
        );

        // Completely empty data (only comments) is salvageable (we just add the line)
        let comments_only = "# nothing useful\n; also nothing\n";
        let res = best_effort_repair_or_standardize(comments_only, admin, &required).unwrap();
        assert!(res.contains(&required));
    }

    #[test]
    fn test_ensure_kadm5_acl_creates_default_when_missing() {
        with_temp_acl_setup(|template, acl| {
            let config = make_test_config("TEST.EXAMPLE");

            // File does not exist yet
            assert!(!acl.exists());

            ensure_kadm5_acl(
                acl.to_str().unwrap(),
                template.to_str().unwrap(),
                &config,
                "example",
            )
            .expect("ensure should succeed on create path");

            let content = fs::read_to_string(acl).expect("acl should exist after ensure");
            assert!(
                content.contains("admin/admin@TEST.EXAMPLE    *"),
                "default admin line must be present"
            );
            // The render_template path was taken, so the file should have been written by it
            assert!(content.trim() == "admin/admin@TEST.EXAMPLE    *");
        });
    }

    #[test]
    fn test_ensure_kadm5_acl_repairs_adds_admin_preserves_custom_and_noops_when_good() {
        with_temp_acl_setup(|template, acl| {
            let config = make_test_config("TEST.EXAMPLE");
            let required_line = "admin/admin@TEST.EXAMPLE    *";

            // --- Repair scenario: admin missing but other custom entries exist ---
            let initial =
                "# custom comment\nservice/HTTP@TEST.EXAMPLE    x\nrestricted@TEST.EXAMPLE    l\n";
            fs::write(acl, initial).unwrap();

            ensure_kadm5_acl(
                acl.to_str().unwrap(),
                template.to_str().unwrap(),
                &config,
                "example",
            )
            .expect("repair ensure should succeed");

            let repaired = fs::read_to_string(acl).unwrap();
            assert!(
                repaired.contains(required_line),
                "should have added full admin"
            );
            assert!(repaired.contains("service/HTTP@TEST.EXAMPLE    x"));
            assert!(repaired.contains("restricted@TEST.EXAMPLE    l"));
            assert!(repaired.contains("# custom comment"));

            // --- No-op scenario: already contains the admin with * plus custom stuff ---
            let good = "# production custom ACL\nservice/HTTP@TEST.EXAMPLE    x\nadmin/admin@TEST.EXAMPLE    *\nanother@TEST.EXAMPLE    a\n";
            fs::write(acl, good).unwrap();

            let before = fs::read_to_string(acl).unwrap();
            ensure_kadm5_acl(
                acl.to_str().unwrap(),
                template.to_str().unwrap(),
                &config,
                "example",
            )
            .expect("noop ensure should succeed");
            let after = fs::read_to_string(acl).unwrap();

            assert_eq!(
                before, after,
                "good ACL with custom entries must not be modified"
            );
            assert!(after.contains(required_line));
            assert!(after.contains("another@TEST.EXAMPLE    a"));

            // --- Garbled -> remake from template ---
            let garbage = "total\nnonsense\nwith no useful principal lines at all\n!!!\n";
            fs::write(acl, garbage).unwrap();

            ensure_kadm5_acl(
                acl.to_str().unwrap(),
                template.to_str().unwrap(),
                &config,
                "example",
            )
            .expect("remake on garbled should succeed");

            let remade = fs::read_to_string(acl).unwrap();
            // After remake it should be the clean default
            assert_eq!(remade.trim(), required_line);
        });
    }
}
