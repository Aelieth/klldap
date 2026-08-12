use crate::infra::queries::{GetGroupList, ListOusQuery, get_group_list, list_ous_query};
use crate::{
    components::{
        change_ou::OuChangeKind,
        delete_group::DeleteGroup,
        ou_table::OuTable,
        router::{AppRoute, Link},
        table_action_bar::TableActionBar,
        table_bulk_selection::TableBulkSelection,
    },
    infra::common_component::{CommonComponent, CommonComponentParts},
};
use anyhow::{Error, Result};
use list_ous_query::ResponseData as OusResponseData;
use yew::prelude::*;

use get_group_list::ResponseData;

pub type Group = get_group_list::GetGroupListGroups;

pub struct GroupTable {
    common: CommonComponentParts<Self>,
    groups: Option<Vec<Group>>,
    ou_filter: String,
    search_term: String,
    search_field: String,
    ous: Vec<String>,
    bulk_selection: TableBulkSelection<i64>,
}

pub enum Msg {
    ListGroupsResponse(Result<ResponseData>),
    ListOusResponse(Result<OusResponseData>),
    OnGroupDeleted(i64),
    OnError(Error),
    OuFilterChanged(String),
    SearchTermChanged(String),
    SearchFieldChanged(String),
    ToggleGroupSelection(i64),
    ToggleSelectAll,
    OuCreated(String),
    OuDeleted(String),
    ChangeOuForSelected(String),
    CreateOuError(String),
}

impl CommonComponent<GroupTable> for GroupTable {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::ListGroupsResponse(groups) => {
                self.groups = Some(groups?.groups.into_iter().collect());
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
            Msg::OnGroupDeleted(group_id) => {
                if let Some(groups) = &mut self.groups {
                    groups.retain(|g| g.id != group_id);
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
            Msg::ToggleGroupSelection(group_id) => {
                self.bulk_selection.toggle(group_id);
                Ok(true)
            }
            Msg::ToggleSelectAll => {
                if let Some(groups) = &self.groups {
                    let mut filtered = groups.clone();
                    if self.ou_filter != "All" {
                        filtered.retain(|g| Self::get_ou(g) == self.ou_filter);
                    }
                    if !self.search_term.is_empty() {
                        let term = self.search_term.to_lowercase();
                        filtered.retain(|g| match self.search_field.as_str() {
                            "Group Name" => g.display_name.to_lowercase().contains(&term),
                            "Creation Date" => Self::get_creation_date_str(g).contains(&term),
                            "Member Count <" => Self::member_count_less_than(g, &term),
                            "Member Count >" => Self::member_count_greater_than(g, &term),
                            _ => true,
                        });
                    }
                    self.bulk_selection
                        .toggle_all(&filtered.iter().map(|g| g.id).collect::<Vec<_>>());
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
                self.common.call_graphql::<GetGroupList, _>(
                    ctx,
                    get_group_list::Variables {},
                    Msg::ListGroupsResponse,
                    "Error trying to fetch groups after OU change",
                );
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl GroupTable {
    fn get_attribute_value(group: &Group, name: &str) -> Option<String> {
        group
            .attributes
            .iter()
            .find(|a| a.schema.name == name)
            .and_then(|a| a.value.first().cloned())
    }

    fn get_ou(group: &Group) -> String {
        Self::get_attribute_value(group, "ou").unwrap_or_default()
    }

    fn get_creation_date_str(group: &Group) -> String {
        group.creation_date.naive_local().date().to_string()
    }

    fn get_member_count(group: &Group) -> u64 {
        group.member_count as u64
    }

    fn member_count_less_than(group: &Group, term: &str) -> bool {
        if let Ok(num) = term.parse::<u64>() {
            Self::get_member_count(group) < num
        } else {
            false
        }
    }

    fn member_count_greater_than(group: &Group, term: &str) -> bool {
        if let Ok(num) = term.parse::<u64>() {
            Self::get_member_count(group) > num
        } else {
            false
        }
    }
}

impl Component for GroupTable {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let mut table = GroupTable {
            common: CommonComponentParts::<Self>::create(),
            groups: None,
            ou_filter: "All".to_string(),
            search_term: String::new(),
            search_field: "Group Name".to_string(),
            ous: vec![],
            bulk_selection: TableBulkSelection::default(),
        };

        table.common.call_graphql::<GetGroupList, _>(
            ctx,
            get_group_list::Variables {},
            Msg::ListGroupsResponse,
            "Error trying to fetch groups",
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
        let filtered_groups = self.groups.as_ref().map_or(vec![], |groups| {
            let mut filtered = groups.clone();
            if self.ou_filter != "All" {
                filtered.retain(|g| Self::get_ou(g) == self.ou_filter);
            }
            if !self.search_term.is_empty() {
                let term = self.search_term.to_lowercase();
                filtered.retain(|g| match self.search_field.as_str() {
                    "Group Name" => g.display_name.to_lowercase().contains(&term),
                    "Creation Date" => Self::get_creation_date_str(g).contains(&term),
                    "Member Count <" => Self::member_count_less_than(g, &term),
                    "Member Count >" => Self::member_count_greater_than(g, &term),
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
            default_primary={"groups".to_string()}
            />
            <hr class="my-4" />

            <TableActionBar
                create_route={AppRoute::CreateGroup}
                create_label={"Create Group".to_string()}
                create_icon={"bi-people-fill me-2".to_string()}
                kind={OuChangeKind::Groups(self.bulk_selection.selected.clone())}
                ous={self.ous.clone()}
                on_ou_changed={ctx.link().callback(|new_ou: String| Msg::ChangeOuForSelected(new_ou))}
                on_error={ctx.link().callback(Msg::OnError)}
                search_field={self.search_field.clone()}
                search_term={self.search_term.clone()}
                search_fields={vec![
                    "Group Name".to_string(),
                    "Creation Date".to_string(),
                    "Member Count <".to_string(),
                    "Member Count >".to_string(),
                ]}
                on_search_field_changed={ctx.link().callback(Msg::SearchFieldChanged)}
                on_search_term_changed={ctx.link().callback(Msg::SearchTermChanged)}
            />

            {self.view_groups(ctx, &filtered_groups)}

            <div class="row justify-content-start mt-3">
                <div class="col-auto">
                    <DeleteGroup
                        selected_groups={self.bulk_selection.selected.clone()}
                        on_group_deleted={ctx.link().callback(Msg::OnGroupDeleted)}
                        on_error={ctx.link().callback(Msg::OnError)}
                    />
                </div>
            </div>

            {self.view_errors()}
            </div>
        }
    }
}

impl GroupTable {
    fn view_groups(&self, ctx: &Context<Self>, filtered_groups: &[Group]) -> Html {
        let all_selected = self
            .bulk_selection
            .all_selected(&filtered_groups.iter().map(|g| g.id).collect::<Vec<_>>());

        html! {
            <div class="table-responsive">
            <table class="table table-hover">
            <thead>
            <tr>
            <th>
            <input type="checkbox" checked={all_selected}
            onclick={ctx.link().callback(|_| Msg::ToggleSelectAll)} />
            </th>
            <th class="fw-bold fs-8">{"Group name"}</th>
            <th class="fw-bold fs-8">{"OU"}</th>
            <th class="fw-bold fs-8">{"Creation date"}</th>
            <th class="fw-bold fs-8">{"Members"}</th>
            </tr>
            </thead>
            <tbody>
            {for filtered_groups.iter().map(|g| self.view_group(ctx, g))}
            </tbody>
            </table>
            </div>
        }
    }

    fn view_group(&self, ctx: &Context<Self>, group: &Group) -> Html {
        let is_selected = self.bulk_selection.is_selected(&group.id);
        let group_id = group.id;

        html! {
            <tr key={group.id}>
            <td>
            <input type="checkbox" checked={is_selected}
            onclick={ctx.link().callback(move |_| Msg::ToggleGroupSelection(group_id))} />
            </td>
            <td><Link to={AppRoute::GroupDetails{group_id: group.id}}>{&group.display_name}</Link></td>
            <td>{Self::get_ou(group)}</td>
            <td>{group.creation_date.naive_local().date()}</td>
            <td>{Self::get_member_count(group)}</td>
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
