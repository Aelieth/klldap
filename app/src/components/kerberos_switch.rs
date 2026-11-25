use crate::infra::form_utils::AttributeValue;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct KerberosSwitchProps {
    pub enabled: bool,
    pub on_toggle: Callback<bool>,
    #[prop_or_default]
    pub show_banner: bool,
    #[prop_or_default]
    pub username: Option<String>,
    #[prop_or_default]
    pub kerberos_disabled: bool,
    #[prop_or_default]
    pub locked: bool,
}

pub const SYNC_LOCKED: &str =
    "The Kerberos realm is not ready: Kerberos sync cannot be changed until it is.";

/// Only a ready realm takes a sync change; with Kerberos disabled the switch still turns sync off.
pub fn sync_locked(state: &str) -> bool {
    !matches!(state, "ready" | "disabled")
}

fn sync_hint(locked: bool, kerberos_disabled: bool) -> &'static str {
    match (locked, kerberos_disabled) {
        (true, _) => SYNC_LOCKED,
        (false, true) => {
            "Kerberos is disabled: OFF turns sync off; the next start with Kerberos removes the principal."
        }
        (false, false) => {
            "ON = sync principal on next password change. OFF = delete principal immediately."
        }
    }
}

#[function_component(KerberosSwitch)]
pub fn kerberos_switch(props: &KerberosSwitchProps) -> Html {
    html! {
        <div class="mb-3 row">
            <label class="form-label col-4 col-form-label" for="kerberossync_toggle">
                {"Kerberos Sync"}
                <button
                    data-bs-placement="right"
                    title="Sync Kerberos principal and password for SSO with KDE/GNOME."
                    type="button"
                    class="btn btn-sm btn-link"
                    aria-label="Kerberos Sync Info">
                    <i aria-label="Info" class="bi bi-info-circle"></i>
                </button>
            </label>
            <div class="col-8 d-flex align-items-center">
                <div class="btn-group" role="group" style="width: 120px;">
                    <button
                        type="button"
                        class={classes!("btn", "btn-outline-primary", if props.enabled { "active" } else { "" })}
                        disabled={props.locked}
                        onclick={props.on_toggle.reform(|_| true)}>
                        {"On"}
                    </button>
                    <button
                        type="button"
                        class={classes!("btn", "btn-outline-secondary", if !props.enabled { "active" } else { "" })}
                        disabled={props.locked}
                        onclick={props.on_toggle.reform(|_| false)}>
                        {"Off"}
                    </button>
                </div>
                <div class="form-text text-muted ms-3">
                    { sync_hint(props.locked, props.kerberos_disabled) }
                </div>
            </div>

            { if props.show_banner {
                html! {
                    <div class="alert alert-info mt-2 col-12">
                        {"After Save Changes "}
                        {props.username.as_deref().unwrap_or("user")}
                        {" password must be changed by admin or self to finish the sync."}
                    </div>
                }
            } else { html! {} }}
        </div>
    }
}

pub fn prepare_kerberos_update(
    enabled: bool,
    original_enabled: bool,
) -> (Vec<AttributeValue>, Vec<String>) {
    if enabled == original_enabled {
        return (vec![], vec![]);
    }

    let to_insert = vec![AttributeValue {
        name: "kerberossync".to_string(),
        values: vec![if enabled { "1" } else { "0" }.to_string()],
    }];

    let mut to_remove = vec![];

    // When turning OFF, also remove krbprincipalname so the backend triggers principal deletion
    if !enabled {
        to_remove.push("krbprincipalname".to_string());
    }

    (to_insert, to_remove)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_a_ready_realm_takes_a_sync_change_and_a_disabled_one_still_turns_sync_off() {
        let rows = [
            ("ready", false),
            ("disabled", false),
            ("directory-only", true),
            ("admin-only", true),
            ("unsettled", true),
            ("lost", true),
        ];
        for (state, locked) in rows {
            assert_eq!(sync_locked(state), locked, "{state}");
            assert_eq!(sync_hint(locked, false) == SYNC_LOCKED, locked, "{state}");
        }
    }
}
