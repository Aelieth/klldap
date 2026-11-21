use super::*;
use pretty_assertions::assert_eq;

#[test]
fn test_trusted_proxies_are_empty_unless_set_and_a_bad_entry_refuses_the_start_by_name() {
    Jail::expect_with(|jail| {
        jail.clear_env();
        jail.set_env("LLDAP_JWT_SECRET", "secret");
        let config = init(default_run_opts()).unwrap();
        let held = config.trusted_proxy_nets().unwrap().len();
        assert_eq!(
            (config.trusted_proxies.as_str(), held),
            ("", 0),
            "the default"
        );

        jail.create_file(
            "lldap_config.toml",
            "trusted_proxies = \"10.9.0.1/32, 10.9.0.2/32\"\n",
        )?;
        let config = init(default_run_opts()).unwrap();
        let held = config.trusted_proxy_nets().unwrap().len();
        assert_eq!(held, 2, "the file");

        jail.set_env("LLDAP_TRUSTED_PROXIES", "2001:db8::/64");
        let config = init(default_run_opts()).unwrap();
        assert_eq!(
            config.trusted_proxies, "2001:db8::/64",
            "the environment beats the file"
        );

        let mut opts = default_run_opts();
        opts.trusted_proxies = Some("10.9.0.3/32".to_owned());
        let config = init(opts).unwrap();
        assert_eq!(
            config.trusted_proxies, "10.9.0.3/32",
            "the command line beats both"
        );

        jail.set_env("LLDAP_TRUSTED_PROXIES", "10.9.0.1/32,proxy.example");
        let config = init(default_run_opts()).unwrap();
        let refused = config.trusted_proxy_nets().unwrap_err().to_string();
        assert_eq!(
            refused,
            "trusted_proxies \"proxy.example\" is refused: CIDR must include an explicit prefix",
            "a bad entry refuses the start, named"
        );
        Ok(())
    });
}

#[test]
fn test_the_start_holds_the_trusted_proxies_before_the_policy_cache_starts() {
    let source = include_str!("../../main.rs");
    let production = source.split("#[cfg(test)]").next().unwrap();
    let at = |needle: &str| {
        let found = production.find(needle);
        found.unwrap_or_else(|| panic!("main.rs has no `{needle}`"))
    };
    let read = at("let proxies = config.trusted_proxy_nets()?;");
    let held = at("policy_cache().set_trusted_proxies(proxies);");
    let started = at("start_policy_cache(&backend_handler)");
    assert!(
        read < held && held < started,
        "read once, a bad entry refuses the start, held before the server takes requests"
    );
}
