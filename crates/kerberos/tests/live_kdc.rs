use lldap_kerberos::{
    delete_kerberos_principal, derive_realm_from_base_dn, export_keytab_for_keycloak,
    principal_name, set_kerberos_principal_enabled, sync_kerberos_principal,
};
use std::io::Write;
use std::process::{Command, Stdio};

const IGNORE_REASON: &str = "needs a live KDC: run through gate/kdc-sandbox.sh (make test-kdc)";

fn require_live_kdc() {
    if std::env::var("KLLDAP_TEST_KDC").ok().as_deref() != Some("1") {
        panic!("{IGNORE_REASON}");
    }
}

fn kadmin_local(query: &str) -> String {
    let output = Command::new("kadmin.local")
        .arg("-q")
        .arg(query)
        .output()
        .expect("kadmin.local");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn kinit(principal: &str, password: &str) -> bool {
    let ccache = std::env::temp_dir().join(format!("klldap-live-kdc-{}", std::process::id()));
    let mut child = Command::new("kinit")
        .env("KRB5CCNAME", format!("FILE:{}", ccache.display()))
        .arg(principal)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("kinit");
    child
        .stdin
        .take()
        .expect("kinit stdin")
        .write_all(format!("{password}\n").as_bytes())
        .expect("write the password");
    let authenticated = child.wait().expect("kinit exit").success();
    let _ = std::fs::remove_file(&ccache);
    authenticated
}

#[test]
#[ignore = "needs a live KDC: run through gate/kdc-sandbox.sh (make test-kdc)"]
fn test_live_create_chpass_disable_delete() {
    require_live_kdc();
    let principal = principal_name("livebob");
    assert_eq!(
        principal,
        format!("livebob@{}", derive_realm_from_base_dn())
    );

    sync_kerberos_principal("livebob", "LiveBobPass2026!").expect("create");
    assert!(kadmin_local("getprinc livebob").contains(&format!("Principal: {principal}")));
    assert!(
        kinit(&principal, "LiveBobPass2026!"),
        "kinit with the initial password"
    );

    set_kerberos_principal_enabled("livebob", false).expect("disallow tix");
    assert!(kadmin_local("getprinc livebob").contains("DISALLOW_ALL_TIX"));
    assert!(
        !kinit(&principal, "LiveBobPass2026!"),
        "kinit must fail while disabled"
    );

    set_kerberos_principal_enabled("livebob", true).expect("allow tix");
    assert!(!kadmin_local("getprinc livebob").contains("DISALLOW_ALL_TIX"));
    assert!(
        kinit(&principal, "LiveBobPass2026!"),
        "kinit after re-enable"
    );

    sync_kerberos_principal("livebob", "LiveBobRotated2026!").expect("chpass");
    assert!(
        !kinit(&principal, "LiveBobPass2026!"),
        "old password must stop working"
    );
    assert!(
        kinit(&principal, "LiveBobRotated2026!"),
        "kinit with the rotated password"
    );

    delete_kerberos_principal("livebob").expect("delete");
    assert!(kadmin_local("getprinc livebob").contains("does not exist"));
}

#[test]
#[ignore = "needs a live KDC: run through gate/kdc-sandbox.sh (make test-kdc)"]
fn test_live_export_keytab_for_keycloak() {
    require_live_kdc();
    let path = export_keytab_for_keycloak("kc.sandbox.test").expect("export");
    assert_eq!(
        path,
        std::env::var("LLDAP_KERB_KEYCLOAK_KEYTAB").expect("sandbox exports the keytab path")
    );
    let listing = Command::new("klist")
        .arg("-kt")
        .arg(&path)
        .output()
        .expect("klist");
    let listing = String::from_utf8_lossy(&listing.stdout);
    let service = format!("HTTP/kc.sandbox.test@{}", derive_realm_from_base_dn());
    assert!(listing.contains(&service), "{listing}");
}
