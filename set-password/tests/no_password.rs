use std::process::Command;

const NO_PASSWORD: &str = "Error: no password given: pass --password or set LLDAP_USER_PASSWORD\n";
const TOO_SHORT: &str = "Error: New password is too short, expected at least 8 characters\n";

/// The tool against a port nothing listens on: any request it sends fails with a connection
/// error, so an answer that names the password shows nothing was sent.
#[test]
fn test_no_password_is_an_error_before_anything_is_sent() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let base_url = format!("http://{closed}/");
    type Row = (
        &'static str,
        &'static [&'static str],
        Option<&'static str>,
        &'static str,
    );
    let rows: [Row; 6] = [
        (
            "no password, the policy bypassed",
            &["--bypass-password-policy"],
            None,
            NO_PASSWORD,
        ),
        (
            "an empty --password, the policy bypassed",
            &["--bypass-password-policy", "--password", ""],
            None,
            NO_PASSWORD,
        ),
        (
            "an empty LLDAP_USER_PASSWORD, the policy bypassed",
            &["--bypass-password-policy"],
            Some(""),
            NO_PASSWORD,
        ),
        (
            "an empty --password over a set LLDAP_USER_PASSWORD, the policy bypassed",
            &["--bypass-password-policy", "--password", ""],
            Some("Env-Password-1"),
            NO_PASSWORD,
        ),
        ("no password", &[], None, NO_PASSWORD),
        (
            "control: a short password",
            &["--password", "short"],
            None,
            TOO_SHORT,
        ),
    ];
    let (mut got, mut wanted) = (Vec::new(), Vec::new());
    for (label, args, from_env, stderr) in rows {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lldap_set_password"));
        command.env_clear().args([
            "--base-url",
            &base_url,
            "--token",
            "not-a-token",
            "--username",
            "bob",
        ]);
        command.args(args);
        if let Some(password) = from_env {
            command.env("LLDAP_USER_PASSWORD", password);
        }
        let output = command.output().unwrap();
        got.push((
            label,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        ));
        wanted.push((label, Some(1), stderr.to_owned(), String::new()));
    }
    assert_eq!(got, wanted, "per row: exit code, stderr, stdout");
}
