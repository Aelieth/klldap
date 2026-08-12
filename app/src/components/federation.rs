use crate::components::{keycloak_settings::KeycloakSettings, posix_options::PosixOptions};
use yew::prelude::*;

#[function_component(Federation)]
pub fn federation() -> Html {
    html! {
        <div class="container">
            <KeycloakSettings />
            <div class="row mt-4">
                <div class="col-md-6">
                    <PosixOptions on_status_update={Callback::noop()} />
                </div>
            </div>
        </div>
    }
}
