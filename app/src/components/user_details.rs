use crate::infra::queries::{
    AddUserToGroup, GetGroupList, RemoveUserFromGroup, add_user_to_group, get_group_list,
    remove_user_from_group,
};
use crate::{
    components::{
        add_user_to_group::AddUserToGroupComponent,
        remove_user_from_group::RemoveUserFromGroupComponent,
        reset_mfa::ResetMfa,
        router::{AppRoute, Link},
        user_details_form::UserDetailsForm,
    },
    infra::{
        common_component::{CommonComponent, CommonComponentParts},
        form_utils::GraphQlAttributeSchema,
        schema::AttributeType,
    },
};
use anyhow::{Error, Result, anyhow, bail};
use graphql_client::GraphQLQuery;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_details.graphql",
    response_derives = "Debug, Hash, PartialEq, Eq, Clone",
    custom_scalars_module = "crate::infra::graphql",
    extern_enums("AttributeType")
)]
pub struct GetUserDetails;

pub type User = get_user_details::GetUserDetailsUser;
pub type Group = get_user_details::GetUserDetailsUserGroups;
pub type Attribute = get_user_details::GetUserDetailsUserAttributes;
pub type AttributeSchema = get_user_details::GetUserDetailsSchemaUserSchemaAttributes;

impl From<&AttributeSchema> for GraphQlAttributeSchema {
    fn from(attr: &AttributeSchema) -> Self {
        Self {
            name: attr.name.clone(),
            is_list: attr.is_list,
            is_readonly: attr.is_readonly,
            is_editable: attr.is_editable,
        }
    }
}

pub struct UserDetails {
    common: CommonComponentParts<Self>,
    user_and_schema: Option<(User, Vec<AttributeSchema>)>,
    lldap_disabled_group_id: Option<i64>,
}

impl UserDetails {
    fn mut_groups(&mut self) -> &mut Vec<Group> {
        &mut self.user_and_schema.as_mut().unwrap().0.groups
    }
}

pub enum Msg {
    UserDetailsResponse(Result<get_user_details::ResponseData>),
    OnError(Error),
    OnUserAddedToGroup(Group),
    OnUserRemovedFromGroup((String, i64)),
    OnMfaReset,
    Refresh,
    AddToLldapDisabled,
    AddToLldapDisabledResponse(Result<add_user_to_group::ResponseData>),
    RemoveFromLldapDisabled,
    RemoveFromLldapDisabledResponse(Result<remove_user_from_group::ResponseData>),
    GroupListResponse(Result<get_group_list::ResponseData>),
    GroupListResponseThenAdd(Result<get_group_list::ResponseData>),
}

#[derive(yew::Properties, Clone, PartialEq, Eq)]
pub struct Props {
    pub username: String,
    pub is_admin: bool,
    pub is_self: bool,
    pub mfa_enabled: bool,
    pub mfa_required: bool,
}

impl CommonComponent<UserDetails> for UserDetails {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::UserDetailsResponse(response) => match response {
                Ok(data) => {
                    let user = data.user;
                    // Store the lldap_disabled group id if present (for toggle button)
                    self.lldap_disabled_group_id = user
                        .groups
                        .iter()
                        .find(|g| g.display_name == "lldap_disabled")
                        .map(|g| g.id);
                    self.user_and_schema = Some((user, data.schema.user_schema.attributes));
                }
                Err(e) => {
                    self.user_and_schema = None;
                    self.lldap_disabled_group_id = None;
                    bail!("Error getting user details: {}", e);
                }
            },
            Msg::OnError(e) => return Err(e),
            Msg::OnUserAddedToGroup(group) => {
                self.mut_groups().push(group);
            }
            Msg::OnUserRemovedFromGroup((_, group_id)) => {
                self.mut_groups().retain(|g| g.id != group_id);
            }
            Msg::OnMfaReset => {
                self.user_and_schema.as_mut().unwrap().0.mfa_enrolled = Some(false);
            }
            Msg::Refresh => {
                self.common.call_graphql::<GetUserDetails, _>(
                    ctx,
                    get_user_details::Variables {
                        id: ctx.props().username.clone(),
                    },
                    Msg::UserDetailsResponse,
                    "Error trying to fetch user details",
                );
            }
            Msg::AddToLldapDisabled => {
                if let Some(group_id) = self.lldap_disabled_group_id {
                    self.common.call_graphql::<AddUserToGroup, _>(
                        ctx,
                        add_user_to_group::Variables {
                            user: ctx.props().username.clone(),
                            group: group_id,
                        },
                        Msg::AddToLldapDisabledResponse,
                        "Error trying to add user to lldap_disabled group",
                    );
                } else {
                    // ID missing (user not yet in group) — fetch group list first, then retry
                    self.common.call_graphql::<GetGroupList, _>(
                        ctx,
                        get_group_list::Variables {},
                        Msg::GroupListResponseThenAdd,
                        "Error fetching group list before adding to lldap_disabled",
                    );
                }
                return Ok(false);
            }
            Msg::AddToLldapDisabledResponse(Ok(_)) => {
                ctx.link().send_message(Msg::Refresh);
                return Ok(true);
            }
            Msg::AddToLldapDisabledResponse(Err(e)) => {
                self.common.error = Some(e);
                return Ok(true);
            }
            Msg::RemoveFromLldapDisabled => {
                if let Some(group_id) = self.lldap_disabled_group_id {
                    self.common.call_graphql::<RemoveUserFromGroup, _>(
                        ctx,
                        remove_user_from_group::Variables {
                            user: ctx.props().username.clone(),
                            group: group_id,
                        },
                        Msg::RemoveFromLldapDisabledResponse,
                        "Error trying to remove user from lldap_disabled group",
                    );
                }
                return Ok(false);
            }
            Msg::RemoveFromLldapDisabledResponse(Ok(_)) => {
                ctx.link().send_message(Msg::Refresh);
                return Ok(true);
            }
            Msg::RemoveFromLldapDisabledResponse(Err(e)) => {
                self.common.error = Some(e);
                return Ok(true);
            }
            Msg::GroupListResponse(Ok(data)) => {
                // Always store the lldap_disabled group id even if user is not a member
                self.lldap_disabled_group_id = data
                    .groups
                    .into_iter()
                    .find(|g| g.display_name == "lldap_disabled")
                    .map(|g| g.id);
                return Ok(true);
            }
            Msg::GroupListResponse(Err(_)) => {
                // Non-fatal; button will still work if user is already in the group
                return Ok(true);
            }
            Msg::GroupListResponseThenAdd(Ok(data)) => {
                // Find the lldap_disabled group ID from the fresh list
                if let Some(group) = data
                    .groups
                    .into_iter()
                    .find(|g| g.display_name == "lldap_disabled")
                {
                    self.lldap_disabled_group_id = Some(group.id);
                    self.common.call_graphql::<AddUserToGroup, _>(
                        ctx,
                        add_user_to_group::Variables {
                            user: ctx.props().username.clone(),
                            group: group.id,
                        },
                        Msg::AddToLldapDisabledResponse,
                        "Error trying to add user to lldap_disabled group",
                    );
                } else {
                    self.common.error =
                        Some(anyhow!("lldap_disabled group does not exist in the system"));
                }
                return Ok(false);
            }
            Msg::GroupListResponseThenAdd(Err(e)) => {
                self.common.error = Some(e);
                return Ok(true);
            }
        }
        Ok(true)
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for UserDetails {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut component = Self {
            common: CommonComponentParts::<Self>::create(),
            user_and_schema: None,
            lldap_disabled_group_id: None,
        };
        component.get_user_details(ctx);
        component.common.call_graphql::<GetGroupList, _>(
            ctx,
            get_group_list::Variables {},
            Msg::GroupListResponse,
            "Error trying to fetch group list for disabled toggle",
        );
        component
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match (&self.user_and_schema, &self.common.error) {
            (Some((u, schema)), error) => {
                let can_change_password = ctx.props().is_admin || ctx.props().is_self;
                let is_disabled = u.groups.iter().any(|g| g.display_name == "lldap_disabled");
                let mfa_enrolled = u.mfa_enrolled.unwrap_or(false);
                // Under "always" an account may not be left without a factor.
                let own_reset_blocked = ctx.props().is_self && ctx.props().mfa_required;

                let link = ctx.link();

                // Its own row, whatever the two-factor buttons below it do.
                let toggle_row = if ctx.props().is_admin {
                    let onclick = if is_disabled {
                        link.callback(|_| Msg::RemoveFromLldapDisabled)
                    } else {
                        link.callback(|_| Msg::AddToLldapDisabled)
                    };
                    let (label, btn_class) = if is_disabled {
                        ("✖️ Disabled", "btn btn-outline-secondary")
                    } else {
                        ("🟢 Enabled", "btn btn-success")
                    };
                    html! {
                        <div class="d-flex flex-row-reverse mb-2">
                        <button
                            class={btn_class}
                            onclick={onclick}
                            disabled={self.common.is_task_running()}
                            title={if is_disabled { "Remove from lldap_disabled group (enable user)" } else { "Add to lldap_disabled group (disable user)" }}
                        >
                            {label}
                        </button>
                        </div>
                    }
                } else {
                    html! {}
                };

                html! {
                  <>
                  <h3>{u.id.to_string()}</h3>
                  {toggle_row}
                  <div class="d-flex flex-row-reverse">
                  { if can_change_password {
                    html! {
                      <Link
                      to={AppRoute::ChangePassword{user_id: u.id.clone()}}
                      classes="btn btn-secondary">
                      <i class="bi-key me-2"></i>
                      {"Modify password"}
                      </Link>
                    }
                  } else { html! {} }}
                  { if ctx.props().is_self && ctx.props().mfa_enabled {
                    html! {
                      <Link
                      to={AppRoute::RegisterMfa{user_id: u.id.clone()}}
                      classes="btn btn-secondary me-2">
                      <i class="bi-qr-code me-2"></i>
                      { if mfa_enrolled { "Reconfigure two-factor" } else { "Set up two-factor" }}
                      </Link>
                    }
                  } else { html! {} }}
                  { if ctx.props().is_admin && ctx.props().mfa_enabled && !own_reset_blocked {
                    html! {
                      <ResetMfa
                      username={u.id.clone()}
                      disabled={!mfa_enrolled}
                      on_mfa_reset={link.callback(|_| Msg::OnMfaReset)}
                      on_error={link.callback(Msg::OnError)} />
                    }
                  } else if ctx.props().is_self && mfa_enrolled && !own_reset_blocked {
                    html! {
                      <Link
                      to={AppRoute::ResetOwnMfa{user_id: u.id.clone()}}
                      classes="btn btn-danger me-2">
                      <i class="bi-qr-code me-2"></i>
                      {"Reset two-factor"}
                      </Link>
                    }
                  } else { html! {} }}
                  </div>

                  <div class="d-flex justify-content-between align-items-center">
                  <h5 class="row m-3 fw-bold">{"User details"}</h5>
                  { if ctx.props().mfa_enabled && u.mfa_enrolled.is_some() {
                    html! {
                      <span class="my-3">
                      {"Two-factor: "}
                      <span class="border rounded px-1">
                      { if mfa_enrolled { "Enabled" } else { "Disabled" }}
                      </span>
                      </span>
                    }
                  } else { html! {} }}
                  </div>

                  <UserDetailsForm
                  user={u.clone()}
                  user_attributes_schema={schema.clone()}
                  is_admin={ctx.props().is_admin}
                  is_edited_user_admin={u.groups.iter().any(|g| g.display_name == "lldap_admin")}
                  on_updated={link.callback(|_| Msg::Refresh)}
                  />

                  {self.view_group_memberships(ctx, u)}
                  {self.view_add_group_button(ctx, u)}
                  {self.view_messages(error)}
                  </>
                }
            }
            (None, None) => html! {{"Loading user details..."}},
            (None, Some(e)) => {
                html! {<div class="alert alert-danger">{"Error: "}{e.to_string()}</div>}
            }
        }
    }
}

impl UserDetails {
    fn get_user_details(&mut self, ctx: &Context<Self>) {
        self.common.call_graphql::<GetUserDetails, _>(
            ctx,
            get_user_details::Variables {
                id: ctx.props().username.clone(),
            },
            Msg::UserDetailsResponse,
            "Error trying to fetch user details",
        );
    }

    fn view_messages(&self, error: &Option<Error>) -> Html {
        if let Some(e) = error {
            html! { <div class="alert alert-danger"><span>{"Error: "}{e.to_string()}</span></div> }
        } else {
            html! {}
        }
    }

    fn view_group_memberships(&self, ctx: &Context<Self>, u: &User) -> Html {
        let link = ctx.link();
        let make_group_row = |group: &Group| {
            let display_name = group.display_name.clone();
            html! {
                <tr key={format!("groupRow_{}", display_name)}>
                {if ctx.props().is_admin {
                    html! {
                        <>
                        <td>
                        <Link to={AppRoute::GroupDetails{group_id: group.id}}>
                        {&group.display_name}
                        </Link>
                        </td>
                        <td>
                        <RemoveUserFromGroupComponent
                        username={u.id.clone()}
                        group_id={group.id}
                        on_user_removed_from_group={link.callback(Msg::OnUserRemovedFromGroup)}
                        on_error={link.callback(Msg::OnError)}/>
                        </td>
                        </>
                    }
                } else {
                    html! { <td>{&group.display_name}</td> }
                }}
                </tr>
            }
        };
        html! {
            <>
            <h5 class="row m-3 fw-bold">{"Group memberships"}</h5>
            <div class="table-responsive">
            <table class="table table-hover">
            <thead>
            <tr key="headerRow">
            <th>{"Group"}</th>
            { if ctx.props().is_admin { html!{ <th></th> }} else { html!{} }}
            </tr>
            </thead>
            <tbody>
            {if u.groups.is_empty() {
                html! {
                    <tr key="EmptyRow">
                    <td>{"This user is not a member of any groups."}</td>
                    </tr>
                }
            } else {
                html! {<>{u.groups.iter().map(make_group_row).collect::<Vec<_>>()}</>}
            }}
            </tbody>
            </table>
            </div>
            </>
        }
    }

    fn view_add_group_button(&self, ctx: &Context<Self>, u: &User) -> Html {
        let link = ctx.link();
        if ctx.props().is_admin {
            html! {
                <AddUserToGroupComponent
                username={u.id.clone()}
                groups={u.groups.clone()}
                on_error={link.callback(Msg::OnError)}
                on_user_added_to_group={link.callback(Msg::OnUserAddedToGroup)}/>
            }
        } else {
            html! {}
        }
    }
}
