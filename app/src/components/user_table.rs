use crate::infra::queries::{ListOusQuery, list_ous_query};
use crate::{
    components::{
        change_ou::OuChangeKind,
        delete_user::DeleteUser,
        ou_table::OuTable,
        router::{AppRoute, Link},
        table_action_bar::TableActionBar,
        table_bulk_selection::TableBulkSelection,
    },
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{Error, Result};
use graphql_client::GraphQLQuery;
use list_ous_query::ResponseData as OusResponseData;
use list_users_query::ResponseData;
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_users.graphql",
    response_derives = "Debug, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListUsersQuery;

type User = list_users_query::ListUsersQueryUsers;

pub struct UserTable {
    common: CommonComponentParts<Self>,
    users: Option<Vec<User>>,
    ou_filter: String,
    search_term: String,
    search_field: String,
    ous: Vec<String>,
    bulk_selection: TableBulkSelection<String>,
}

pub enum Msg {
    ListUsersResponse(Result<ResponseData>),
    ListOusResponse(Result<OusResponseData>),
    OnUserDeleted(String),
    OnError(Error),
    OuFilterChanged(String),
    SearchTermChanged(String),
    SearchFieldChanged(String),
    ToggleUserSelection(String),
    ToggleSelectAll,
    OuCreated(String),
    OuDeleted(String),
    ChangeOuForSelected(String),
    CreateOuError(String),
}

impl CommonComponent<UserTable> for UserTable {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ListUsersResponse(users) => {
                self.users = Some(users?.users.into_iter().collect());
                Ok(true)
            }
            Msg::ListOusResponse(ous) => {
                self.ous = ous?.list_ous;
                Ok(true)
            }
            Msg::OnError(e) => Err(e),
            Msg::CreateOuError(err) => {
                self.common.error = Some(anyhow::Error::msg(err));
                Ok(true)
            }
            Msg::OnUserDeleted(user_id) => {
                if let Some(users) = &mut self.users {
                    users.retain(|u| u.id != user_id);
                }
                self.bulk_selection.clear();
                Ok(true)
            }
            Msg::OuFilterChanged(ou) => {
                self.ou_filter = ou;
                Ok(true)
            }
            Msg::SearchTermChanged(term) => {
                self.search_term = term;
                Ok(true)
            }
            Msg::SearchFieldChanged(field) => {
                self.search_field = field;
                Ok(true)
            }
            Msg::ToggleUserSelection(user_id) => {
                self.bulk_selection.toggle(user_id);
                Ok(true)
            }
            Msg::ToggleSelectAll => {
                if let Some(users) = &self.users {
                    let mut filtered = users.clone();
                    if self.ou_filter != "All" {
                        filtered.retain(|u| Self::get_ou(u) == self.ou_filter);
                    }
                    if !self.search_term.is_empty() {
                        let term = self.search_term.to_lowercase();
                        filtered.retain(|u| match self.search_field.as_str() {
                            "User ID" => u.id.to_lowercase().contains(&term),
                            "Email" => u.email.to_lowercase().contains(&term),
                            "Display Name" => u.display_name.to_lowercase().contains(&term),
                            "First Name" => Self::get_attribute_value(u, "firstname")
                                .unwrap_or_default()
                                .to_lowercase()
                                .contains(&term),
                            "Last Name" => Self::get_attribute_value(u, "lastname")
                                .unwrap_or_default()
                                .to_lowercase()
                                .contains(&term),
                            "Creation Date" => Self::get_creation_date_str(u).contains(&term),
                            _ => true,
                        });
                    }
                    self.bulk_selection
                        .toggle_all(&filtered.iter().map(|u| u.id.clone()).collect::<Vec<_>>());
                }
                Ok(true)
            }
            Msg::OuCreated(new_ou) => {
                if !new_ou.trim().is_empty() && !self.ous.contains(&new_ou) {
                    self.ous.push(new_ou);
                }
                Ok(true)
            }
            Msg::OuDeleted(deleted_ou) => {
                self.ous.retain(|o| o != &deleted_ou);
                if self.ou_filter == deleted_ou {
                    self.ou_filter = "All".to_string();
                }
                Ok(true)
            }
            Msg::ChangeOuForSelected(_new_ou) => {
                self.bulk_selection.clear();
                self.common.call_graphql::<ListUsersQuery, _>(
                    ctx,
                    list_users_query::Variables { where_: None },
                    Msg::ListUsersResponse,
                    "Error trying to fetch users after OU change",
                );
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl UserTable {
    fn get_attribute_value(user: &User, name: &str) -> Option<String> {
        user.attributes
            .iter()
            .find(|a| a.schema.name == name)
            .and_then(|a| a.value.first().cloned())
    }

    fn get_kerberos_sync(user: &User) -> bool {
        Self::get_attribute_value(user, "kerberossync")
            .and_then(|v| v.parse::<i64>().ok())
            .is_some_and(|i| i != 0)
    }

    fn get_ou(user: &User) -> String {
        Self::get_attribute_value(user, "ou").unwrap_or_else(|| "people".to_string())
    }

    fn get_creation_date_str(user: &User) -> String {
        user.creation_date.naive_local().date().to_string()
    }

    fn is_user_disabled(user: &User) -> bool {
        user.is_disabled
    }
}

impl Component for UserTable {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = UserTable {
            common: CommonComponentParts::<Self>::create(),
            users: None,
            ou_filter: "All".to_string(),
            search_term: String::new(),
            search_field: "User ID".to_string(),
            ous: vec![],
            bulk_selection: TableBulkSelection::default(),
        };

        table.common.call_graphql::<ListUsersQuery, _>(
            ctx,
            list_users_query::Variables { where_: None },
            Msg::ListUsersResponse,
            "Error trying to fetch users",
        );

        table.common.call_graphql::<ListOusQuery, _>(
            ctx,
            list_ous_query::Variables {},
            Msg::ListOusResponse,
            "Error trying to fetch OUs",
        );

        table
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let filtered_users = self.users.as_ref().map_or(vec![], |users| {
            let mut filtered = users.clone();
            if self.ou_filter != "All" {
                filtered.retain(|u| Self::get_ou(u) == self.ou_filter);
            }
            if !self.search_term.is_empty() {
                let term = self.search_term.to_lowercase();
                filtered.retain(|u| match self.search_field.as_str() {
                    "User ID" => u.id.to_lowercase().contains(&term),
                    "Email" => u.email.to_lowercase().contains(&term),
                    "Display Name" => u.display_name.to_lowercase().contains(&term),
                    "First Name" => Self::get_attribute_value(u, "firstname")
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains(&term),
                    "Last Name" => Self::get_attribute_value(u, "lastname")
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains(&term),
                    "Creation Date" => Self::get_creation_date_str(u).contains(&term),
                    _ => true,
                });
            }
            filtered
        });

        html! {
            <div>
            <OuTable
            ou_filter={self.ou_filter.clone()}
            ous={self.ous.clone()}
            on_ou_changed={ctx.link().callback(Msg::OuFilterChanged)}
            on_ou_created={ctx.link().callback(Msg::OuCreated)}
            on_ou_deleted={ctx.link().callback(Msg::OuDeleted)}
            on_error={ctx.link().callback(|e: Error| Msg::CreateOuError(e.to_string()))}
            error={self.common.error.as_ref().map(|e| e.to_string())}
            default_primary={"people".to_string()}
            />
            <hr class="my-4" />

            <TableActionBar
                create_route={AppRoute::CreateUser}
                create_label={"Create User".to_string()}
                create_icon={"bi-person-plus me-2".to_string()}
                kind={OuChangeKind::Users(self.bulk_selection.selected.clone())}
                ous={self.ous.clone()}
                on_ou_changed={ctx.link().callback(|new_ou: String| Msg::ChangeOuForSelected(new_ou))}
                on_error={ctx.link().callback(Msg::OnError)}
                search_field={self.search_field.clone()}
                search_term={self.search_term.clone()}
                search_fields={vec![
                    "User ID".to_string(),
                    "Email".to_string(),
                    "Display Name".to_string(),
                    "First Name".to_string(),
                    "Last Name".to_string(),
                    "Creation Date".to_string(),
                ]}
                on_search_field_changed={ctx.link().callback(Msg::SearchFieldChanged)}
                on_search_term_changed={ctx.link().callback(Msg::SearchTermChanged)}
            />

            {self.view_users(ctx, &filtered_users)}

            <div class="row justify-content-start mt-3">
                <div class="col-auto">
                    <DeleteUser
                        selected_users={self.bulk_selection.selected.clone()}
                        on_user_deleted={ctx.link().callback(Msg::OnUserDeleted)}
                        on_error={ctx.link().callback(Msg::OnError)}
                    />
                </div>
            </div>

            {self.view_errors()}
            </div>
        }
    }
}

impl UserTable {
    fn view_users(&self, ctx: &Context<Self>, filtered_users: &[User]) -> Html {
        let all_selected = self.bulk_selection.all_selected(
            &filtered_users
                .iter()
                .map(|u| u.id.clone())
                .collect::<Vec<_>>(),
        );

        html! {
            <div class="table-responsive">
            <table class="table table-hover">
            <thead>
            <tr>
            <th>
            <input type="checkbox" checked={all_selected}
            onclick={ctx.link().callback(|_| Msg::ToggleSelectAll)} />
            </th>
            <th class="fw-bold fs-8">{"User ID"}</th>
            <th class="fw-bold fs-8">{"OU"}</th>
            <th class="fw-bold fs-8">{"Email"}</th>
            <th class="fw-bold fs-8">{"Display name"}</th>
            <th class="fw-bold fs-8">{"First name"}</th>
            <th class="fw-bold fs-8">{"Last name"}</th>
            <th class="fw-bold fs-8">{"Creation date"}</th>
            <th class="fw-bold fs-8">{"Kerberos Sync"}</th>
            </tr>
            </thead>
            <tbody>
            {for filtered_users.iter().map(|u| self.view_user(ctx, u))}
            </tbody>
            </table>
            </div>
        }
    }

    fn view_user(&self, ctx: &Context<Self>, user: &User) -> Html {
        let first_name = Self::get_attribute_value(user, "firstname").unwrap_or_default();
        let last_name = Self::get_attribute_value(user, "lastname").unwrap_or_default();
        let kerberos_sync = Self::get_kerberos_sync(user);
        let ou = Self::get_ou(user);
        let is_selected = self.bulk_selection.is_selected(&user.id);
        let user_id = user.id.clone();
        let is_disabled = Self::is_user_disabled(user);

        let row_class = if is_disabled { "text-muted" } else { "" };

        html! {
            <tr key={user.id.clone()} class={row_class}>
            <td>
            <input type="checkbox" checked={is_selected}
            onclick={ctx.link().callback(move |_| Msg::ToggleUserSelection(user_id.clone()))} />
            </td>
            <td>
            {if is_disabled {
                html! { <span class="text-danger">{"✖️ "}</span> }
            } else {
                html! {}
            }}
            <Link
                to={AppRoute::UserDetails{user_id: user.id.clone()}}
                classes={if is_disabled { "text-muted" } else { "" }}>
                {&user.id}
            </Link>
            </td>
            <td>{ou}</td>
            <td>{&user.email}</td>
            <td>{&user.display_name}</td>
            <td>{first_name}</td>
            <td>{last_name}</td>
            <td>{user.creation_date.naive_local().date()}</td>
            <td>
            {if kerberos_sync {
                crate::components::fragments::icons::checkmark()
            } else {
                html! { <span class="text-muted">{"–"}</span> }
            }}
            </td>
            </tr>
        }
    }

    fn view_errors(&self) -> Html {
        match &self.common.error {
            None => html! {},
            Some(e) => html! {<div class="alert alert-danger">{"Error: "}{e.to_string()}</div>},
        }
    }
}
