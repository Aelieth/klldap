use crate::{
    components::create_user::{GetKerberosInfo, get_kerberos_info},
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::Result;
use yew::prelude::*;

const DIRECTORY_ONLY: &str = "The Kerberos realm did not open and this server is directory-only: \
    the directory is served to everyone.";
const ADMIN_ONLY: &str = "The Kerberos realm did not open and this server is admin-only: only \
    admins may sign in.";
const UNAVAILABLE: &str = "Kerberos sign-in, password changes of users with Kerberos sync and \
    changes to Kerberos sync are unavailable until the realm opens.";

/// What an admin is told while `kerberosInfo.state` is one a closed realm goes on serving in.
fn closed_realm(state: &str) -> Option<&'static str> {
    match state {
        "directory-only" => Some(DIRECTORY_ONLY),
        "admin-only" => Some(ADMIN_ONLY),
        _ => None,
    }
}

/// The admins' notice under the header: the state, what is unavailable, and the cause.
pub struct KerberosNotice {
    common: CommonComponentParts<Self>,
    closed: Option<(&'static str, Option<String>)>,
}

pub enum Msg {
    KerberosInfoResponse(Result<get_kerberos_info::ResponseData>),
}

impl CommonComponent<KerberosNotice> for KerberosNotice {
    fn handle_msg(&mut self, _: &Context<Self>, msg: <Self as Component>::Message) -> Result<bool> {
        let Msg::KerberosInfoResponse(info) = msg;
        let info = info?.kerberos_info;
        self.closed = closed_realm(&info.state).map(|state| (state, info.cause));
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for KerberosNotice {
    type Message = Msg;
    type Properties = ();

    fn create(_: &Context<Self>) -> Self {
        Self {
            common: CommonComponentParts::<Self>::create(),
            closed: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
        if first_render {
            self.common.call_graphql::<GetKerberosInfo, _>(
                ctx,
                get_kerberos_info::Variables {},
                Msg::KerberosInfoResponse,
                "Error trying to fetch the Kerberos state",
            );
        }
    }

    fn view(&self, _: &Context<Self>) -> Html {
        let Some((state, cause)) = &self.closed else {
            return html! {};
        };
        html! {
          <div class="container">
            <div class="alert alert-warning" role="alert" id="kerberos-notice">
              <h6 class="fw-bold">
                <i class="bi-exclamation-triangle me-2"></i>
                {*state}
              </h6>
              <p class="mb-0">{UNAVAILABLE}</p>
              { if let Some(cause) = cause {
                html! { <p class="mb-0 mt-2 small">{"Cause: "}{cause}</p> }
              } else {
                html! {}
              }}
            </div>
          </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_notice_is_for_the_two_states_a_closed_realm_serves_in() {
        let rows = [
            ("ready", None),
            ("disabled", None),
            ("unsettled", None),
            ("lost", None),
            ("directory-only", Some(DIRECTORY_ONLY)),
            ("admin-only", Some(ADMIN_ONLY)),
        ];
        for (state, said) in rows {
            assert_eq!(closed_realm(state), said, "{state}");
        }
    }
}
