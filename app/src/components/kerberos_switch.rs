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
                        onclick={props.on_toggle.reform(|_| true)}>
                        {"On"}
                    </button>
                    <button
                        type="button"
                        class={classes!("btn", "btn-outline-secondary", if !props.enabled { "active" } else { "" })}
                        onclick={props.on_toggle.reform(|_| false)}>
                        {"Off"}
                    </button>
                </div>
                <div class="form-text text-muted ms-3">
                    {"ON = sync principal on next password change. OFF = delete principal immediately."}
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
