//! The one-page policies workbench: an OU tree pane and an inspector with
//! view / pick / edit modes. Every emit here originates from a DOM event on a
//! plain control — never send_message from view/changed/rendered (the house
//! Select re-emits on every render, which once locked the whole browser).
use crate::infra::{
    common_component::{CommonComponent, CommonComponentParts},
    form_utils::{input_checked, input_value, select_value},
    modal::ModalHandle,
    ou_policy::{
        DraftEntry, OuRow, ROOT_OU_WIRE, catalog_text, flatten_ou_rows, format_item_value,
        governing_policy, ou_display_name, policy_color, validate_draft_items,
    },
    queries::{ListOusQuery, list_ous_query},
    schema::{PolicyScope, PolicyValueKind},
};
use anyhow::Result;
use graphql_client::GraphQLQuery;
use std::collections::{HashMap, HashSet};
use yew::prelude::*;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_policy_list.graphql",
    response_derives = "Debug, Clone, PartialEq, Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetPolicyList;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_policy_item_catalog.graphql",
    response_derives = "Debug, Clone, PartialEq, Eq",
    custom_scalars_module = "crate::infra::graphql",
    extern_enums("PolicyScope", "PolicyValueKind")
)]
pub struct GetPolicyItemCatalog;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_ou_policy_states.graphql",
    response_derives = "Debug, Clone, PartialEq, Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetOuPolicyStates;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_effective_policy_items.graphql",
    response_derives = "Debug, Clone, PartialEq, Eq",
    custom_scalars_module = "crate::infra::graphql",
    extern_enums("PolicyScope")
)]
pub struct GetEffectivePolicyItems;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/create_policy.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct CreatePolicy;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/update_policy.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct UpdatePolicy;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/delete_policy.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct DeletePolicyQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/set_ou_policy.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct SetOuPolicyQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/clear_ou_policy.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ClearOuPolicyQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/set_ou_policy_inheritance.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct SetOuPolicyInheritanceQuery;

pub type Policy = get_policy_list::GetPolicyListPolicies;
type PolicyItem = get_policy_list::GetPolicyListPoliciesItems;
type CatalogRow = get_policy_item_catalog::GetPolicyItemCatalogPolicyItemCatalog;
type EffectiveItem = get_effective_policy_items::GetEffectivePolicyItemsEffectivePolicyItems;

const DEFAULT_CHIP_COLOR: &str = "#adb5bd";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    View,
    Pick,
    Edit,
}

struct PolicyDraft {
    id: Option<i64>,
    orig_name: String,
    name: String,
    description: String,
    enabled: HashMap<String, bool>,
    values: HashMap<String, String>,
    attach_after: bool,
    error: Option<String>,
}

struct PendingUpdate {
    id: i64,
    name: String,
    description: String,
    items: Vec<(String, String)>,
}

#[derive(Properties, PartialEq)]
pub struct Props {
    pub domain: Option<String>,
}

pub struct PolicyWorkbench {
    common: CommonComponentParts<Self>,
    ous: Option<Vec<String>>,
    policies: Option<Vec<Policy>>,
    catalog: Option<Vec<CatalogRow>>,
    states_loaded: bool,
    direct: HashMap<String, (i64, String)>,
    blocked: HashSet<String>,
    effective: HashMap<String, Vec<EffectiveItem>>,
    selected: String,
    mode: Mode,
    draft: Option<PolicyDraft>,
    pending_update: Option<PendingUpdate>,
    modal: ModalHandle,
    success_message: Option<String>,
}

pub enum Msg {
    OusResponse(Result<list_ous_query::ResponseData>),
    PoliciesResponse(Result<get_policy_list::ResponseData>),
    CatalogResponse(Result<get_policy_item_catalog::ResponseData>),
    StatesResponse(Result<get_ou_policy_states::ResponseData>),
    EffectiveResponse(String, Result<get_effective_policy_items::ResponseData>),
    SelectOu(String),
    StartPick,
    StartEditor {
        policy_id: Option<i64>,
        attach_after: bool,
    },
    CancelToView,
    DraftNameChanged(String),
    DraftDescriptionChanged(String),
    DraftRuleToggled(String),
    DraftValueChanged(String, String),
    SubmitDraft,
    CreateResponse(Result<create_policy::ResponseData>),
    UpdateResponse(i64, Result<update_policy::ResponseData>),
    UsePolicy(i64),
    SetResponse(
        String,
        i64,
        String,
        Result<set_ou_policy_query::ResponseData>,
    ),
    RemovePolicy,
    ClearResponse(String, Result<clear_ou_policy_query::ResponseData>),
    ToggleBlock(bool),
    BlockResponse(
        String,
        bool,
        Result<set_ou_policy_inheritance_query::ResponseData>,
    ),
    ClickedDeletePolicy,
    DismissModal,
    ConfirmDeletePolicy,
    DeleteResponse(i64, Result<delete_policy_query::ResponseData>),
}

impl CommonComponent<PolicyWorkbench> for PolicyWorkbench {
    fn handle_msg(
        &mut self,
        ctx: &Context<Self>,
        msg: <Self as Component>::Message,
    ) -> Result<bool> {
        match msg {
            Msg::OusResponse(response) => {
                self.ous = Some(response?.list_ous);
                Ok(true)
            }
            Msg::PoliciesResponse(response) => {
                self.policies = Some(response?.policies);
                Ok(true)
            }
            Msg::CatalogResponse(response) => {
                self.catalog = Some(response?.policy_item_catalog);
                Ok(true)
            }
            Msg::StatesResponse(response) => {
                self.direct.clear();
                self.blocked.clear();
                for state in response?.ou_policy_states {
                    if let (Some(id), Some(name)) = (state.policy_id, state.policy_name) {
                        self.direct.insert(state.ou.clone(), (id, name));
                    }
                    if state.block_inheritance {
                        self.blocked.insert(state.ou);
                    }
                }
                self.states_loaded = true;
                Ok(true)
            }
            Msg::EffectiveResponse(ou, response) => {
                self.effective.insert(ou, response?.effective_policy_items);
                Ok(true)
            }
            Msg::SelectOu(ou) => {
                if !self.effective.contains_key(&ou) {
                    self.fetch_effective(ctx, ou.clone());
                }
                self.selected = ou;
                self.mode = Mode::View;
                self.draft = None;
                Ok(true)
            }
            Msg::StartPick => {
                self.mode = Mode::Pick;
                Ok(true)
            }
            Msg::StartEditor {
                policy_id,
                attach_after,
            } => {
                self.start_editor(policy_id, attach_after);
                Ok(true)
            }
            Msg::CancelToView => {
                self.mode = Mode::View;
                self.draft = None;
                Ok(true)
            }
            Msg::DraftNameChanged(name) => {
                if let Some(draft) = &mut self.draft {
                    draft.name = name;
                    draft.error = None;
                }
                Ok(true)
            }
            Msg::DraftDescriptionChanged(description) => {
                if let Some(draft) = &mut self.draft {
                    draft.description = description;
                }
                Ok(true)
            }
            Msg::DraftRuleToggled(key) => {
                if let Some(draft) = &mut self.draft {
                    let enabled = draft.enabled.entry(key).or_insert(false);
                    *enabled = !*enabled;
                    draft.error = None;
                }
                Ok(true)
            }
            Msg::DraftValueChanged(key, value) => {
                if let Some(draft) = &mut self.draft {
                    draft.values.insert(key, value);
                    draft.error = None;
                }
                Ok(true)
            }
            Msg::SubmitDraft => self.submit_draft(ctx),
            Msg::CreateResponse(response) => {
                let created = response?.create_policy;
                let id = created.id;
                let name = created.name.clone();
                let attach = self.draft.as_ref().is_some_and(|d| d.attach_after);
                if let Some(policies) = &mut self.policies {
                    policies.push(Policy {
                        id,
                        name: created.name,
                        description: created.description,
                        items: created
                            .items
                            .into_iter()
                            .map(|i| PolicyItem {
                                key: i.key,
                                value: i.value,
                            })
                            .collect(),
                        linked_ous: created.linked_ous,
                    });
                }
                self.draft = None;
                self.mode = Mode::View;
                if attach {
                    let ou = self.selected.clone();
                    let callback_ou = ou.clone();
                    self.common.call_graphql::<SetOuPolicyQuery, _>(
                        ctx,
                        set_ou_policy_query::Variables { ou, policy_id: id },
                        move |response| {
                            Msg::SetResponse(callback_ou.clone(), id, name.clone(), response)
                        },
                        "Error trying to set OU policy",
                    );
                } else {
                    self.finish_mutation(ctx, format!("Policy {name} created"));
                }
                Ok(true)
            }
            Msg::UpdateResponse(id, response) => {
                let pending = self.pending_update.take();
                response?;
                if let (Some(pending), Some(policies)) =
                    (pending.filter(|p| p.id == id), self.policies.as_mut())
                {
                    if let Some(policy) = policies.iter_mut().find(|p| p.id == id) {
                        policy.name = pending.name.clone();
                        policy.description = pending.description;
                        policy.items = pending
                            .items
                            .into_iter()
                            .map(|(key, value)| PolicyItem { key, value })
                            .collect();
                    }
                    for (_, name) in self.direct.values_mut().filter(|(pid, _)| *pid == id) {
                        *name = pending.name.clone();
                    }
                }
                self.finish_mutation(ctx, "Policy saved".to_owned());
                Ok(true)
            }
            Msg::UsePolicy(id) => {
                let Some(name) = self.policy_name(id) else {
                    return Ok(false);
                };
                let ou = self.selected.clone();
                let callback_ou = ou.clone();
                self.common.call_graphql::<SetOuPolicyQuery, _>(
                    ctx,
                    set_ou_policy_query::Variables { ou, policy_id: id },
                    move |response| {
                        Msg::SetResponse(callback_ou.clone(), id, name.clone(), response)
                    },
                    "Error trying to set OU policy",
                );
                Ok(true)
            }
            Msg::SetResponse(ou, id, name, response) => {
                if response.is_err() {
                    // The policy may exist without the link (create→attach chain):
                    // resync instead of guessing.
                    self.refetch_states_and_policies(ctx);
                }
                response?;
                self.direct.insert(ou.clone(), (id, name.clone()));
                let display = ou_display_name(&ou, ctx.props().domain.as_deref());
                self.finish_mutation(ctx, format!("Policy {name} set on {display}"));
                Ok(true)
            }
            Msg::RemovePolicy => {
                let ou = self.selected.clone();
                let callback_ou = ou.clone();
                self.common.call_graphql::<ClearOuPolicyQuery, _>(
                    ctx,
                    clear_ou_policy_query::Variables { ou },
                    move |response| Msg::ClearResponse(callback_ou.clone(), response),
                    "Error trying to clear OU policy",
                );
                Ok(true)
            }
            Msg::ClearResponse(ou, response) => {
                response?;
                let name = self
                    .direct
                    .remove(&ou)
                    .map(|(_, name)| name)
                    .unwrap_or_default();
                let display = ou_display_name(&ou, ctx.props().domain.as_deref());
                self.finish_mutation(ctx, format!("Policy {name} removed from {display}"));
                Ok(true)
            }
            Msg::ToggleBlock(blocked) => {
                let ou = self.selected.clone();
                let callback_ou = ou.clone();
                self.common.call_graphql::<SetOuPolicyInheritanceQuery, _>(
                    ctx,
                    set_ou_policy_inheritance_query::Variables { ou, blocked },
                    move |response| Msg::BlockResponse(callback_ou.clone(), blocked, response),
                    "Error trying to set inheritance",
                );
                Ok(true)
            }
            Msg::BlockResponse(ou, blocked, response) => {
                response?;
                let display = ou_display_name(&ou, ctx.props().domain.as_deref());
                let message = if blocked {
                    self.blocked.insert(ou);
                    format!("Rules from above now blocked for {display}")
                } else {
                    self.blocked.remove(&ou);
                    format!("Rules from above now inherited for {display}")
                };
                self.finish_mutation(ctx, message);
                Ok(true)
            }
            Msg::ClickedDeletePolicy => {
                self.modal.show();
                Ok(true)
            }
            Msg::DismissModal => {
                self.modal.hide();
                Ok(true)
            }
            Msg::ConfirmDeletePolicy => {
                self.modal.hide();
                let Some(id) = self.draft.as_ref().and_then(|d| d.id) else {
                    return Ok(false);
                };
                self.common.call_graphql::<DeletePolicyQuery, _>(
                    ctx,
                    delete_policy_query::Variables { policy_id: id },
                    move |response| Msg::DeleteResponse(id, response),
                    "Error trying to delete policy",
                );
                Ok(true)
            }
            Msg::DeleteResponse(id, response) => {
                response?;
                let name = self.policy_name(id).unwrap_or_default();
                if let Some(policies) = &mut self.policies {
                    policies.retain(|p| p.id != id);
                }
                self.direct.retain(|_, (pid, _)| *pid != id);
                self.finish_mutation(ctx, format!("Policy {name} deleted"));
                Ok(true)
            }
        }
    }

    fn mut_common(&mut self) -> &mut CommonComponentParts<Self> {
        &mut self.common
    }
}

impl Component for PolicyWorkbench {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut page = Self {
            common: CommonComponentParts::<Self>::create(),
            ous: None,
            policies: None,
            catalog: None,
            states_loaded: false,
            direct: HashMap::new(),
            blocked: HashSet::new(),
            effective: HashMap::new(),
            selected: ROOT_OU_WIRE.to_owned(),
            mode: Mode::View,
            draft: None,
            pending_update: None,
            modal: ModalHandle::new(),
            success_message: None,
        };
        page.common.call_graphql::<ListOusQuery, _>(
            ctx,
            list_ous_query::Variables {},
            Msg::OusResponse,
            "Error trying to fetch OUs",
        );
        page.common.call_graphql::<GetPolicyList, _>(
            ctx,
            get_policy_list::Variables {},
            Msg::PoliciesResponse,
            "Error trying to fetch policies",
        );
        page.common.call_graphql::<GetPolicyItemCatalog, _>(
            ctx,
            get_policy_item_catalog::Variables {},
            Msg::CatalogResponse,
            "Error trying to fetch the policy catalog",
        );
        page.common.call_graphql::<GetOuPolicyStates, _>(
            ctx,
            get_ou_policy_states::Variables {},
            Msg::StatesResponse,
            "Error trying to fetch OU policy states",
        );
        page.fetch_effective(ctx, ROOT_OU_WIRE.to_owned());
        page
    }

    fn rendered(&mut self, _: &Context<Self>, first_render: bool) {
        self.modal.init_on_first_render(first_render);
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        // The effective refetch chained after every mutation must not wipe the
        // freshly set success banner.
        if !matches!(msg, Msg::EffectiveResponse(..)) {
            self.success_message = None;
        }
        CommonComponentParts::<Self>::update(self, ctx, msg)
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let loaded = self.ous.is_some()
            && self.policies.is_some()
            && self.catalog.is_some()
            && self.states_loaded;
        if !loaded {
            return match &self.common.error {
                Some(e) => {
                    html! { <div class="alert alert-danger">{"Error: "}{e.to_string()}</div> }
                }
                None => html! { {"Loading..."} },
            };
        }
        let link = ctx.link();
        html! {
            <div class="w-100">
                <div class="d-flex align-items-center flex-wrap gap-2 mb-2">
                    <h5 class="fw-bold mb-0">{"Policies"}</h5>
                    <span class="text-muted small">
                        {"One policy per organizational unit · rules flow down · the closest OU wins"}
                    </span>
                    <span class="flex-grow-1"></span>
                    <button
                        class="btn btn-primary btn-sm"
                        type="button"
                        disabled={self.common.is_task_running()}
                        onclick={link.callback(|_| Msg::StartEditor { policy_id: None, attach_after: false })}>
                        <i class="bi-journal-plus me-1"></i>
                        {"New policy"}
                    </button>
                </div>
                <div class="d-flex border rounded overflow-hidden wb-frame">
                    {self.view_tree_pane(ctx)}
                    <div class="flex-grow-1 p-3 d-flex flex-column gap-3" style="min-width: 0">
                        {self.view_inspector_header(ctx)}
                        { match self.mode {
                            Mode::View => self.view_inspector(ctx),
                            Mode::Pick => self.view_pick(ctx),
                            Mode::Edit => self.view_editor(ctx),
                        } }
                    </div>
                </div>
                { if let Some(e) = &self.common.error {
                    html! { <div class="alert alert-danger mt-3">{"Error: "}{e.to_string()}</div> }
                } else { html! {} } }
                { if let Some(message) = &self.success_message {
                    html! { <div class="alert alert-success mt-3">{message}</div> }
                } else { html! {} } }
                {self.view_delete_modal(ctx)}
            </div>
        }
    }
}

impl PolicyWorkbench {
    fn fetch_effective(&mut self, ctx: &Context<Self>, ou: String) {
        let callback_ou = ou.clone();
        self.common.call_graphql::<GetEffectivePolicyItems, _>(
            ctx,
            get_effective_policy_items::Variables { ou },
            move |response| Msg::EffectiveResponse(callback_ou.clone(), response),
            "Error trying to fetch effective policy items",
        );
    }

    fn refetch_states_and_policies(&mut self, ctx: &Context<Self>) {
        self.common.call_graphql::<GetOuPolicyStates, _>(
            ctx,
            get_ou_policy_states::Variables {},
            Msg::StatesResponse,
            "Error trying to fetch OU policy states",
        );
        self.common.call_graphql::<GetPolicyList, _>(
            ctx,
            get_policy_list::Variables {},
            Msg::PoliciesResponse,
            "Error trying to fetch policies",
        );
    }

    fn finish_mutation(&mut self, ctx: &Context<Self>, message: String) {
        self.success_message = Some(message);
        self.mode = Mode::View;
        self.draft = None;
        self.effective.clear();
        self.fetch_effective(ctx, self.selected.clone());
    }

    fn policy_name(&self, id: i64) -> Option<String> {
        self.policies
            .iter()
            .flatten()
            .find(|p| p.id == id)
            .map(|p| p.name.clone())
    }

    fn linked_count(&self, id: i64) -> usize {
        self.direct.values().filter(|(pid, _)| *pid == id).count()
    }

    fn catalog_rows(&self) -> &[CatalogRow] {
        self.catalog.as_deref().unwrap_or_default()
    }

    fn item_label(&self, key: &str) -> String {
        catalog_text(key)
            .map(|t| t.label.to_owned())
            .unwrap_or_else(|| key.to_owned())
    }

    /// Catalog-order (label, formatted value) lines for a policy's items,
    /// unknown keys appended raw.
    fn policy_item_lines(&self, policy: &Policy) -> Vec<(String, String)> {
        let catalog = self.catalog_rows();
        let mut lines = Vec::new();
        for spec in catalog {
            if let Some(item) = policy.items.iter().find(|i| i.key == spec.key) {
                lines.push((
                    self.item_label(&spec.key),
                    format_item_value(&item.key, &item.value),
                ));
            }
        }
        let mut unknown: Vec<_> = policy
            .items
            .iter()
            .filter(|i| !catalog.iter().any(|s| s.key == i.key))
            .collect();
        unknown.sort_by(|a, b| a.key.cmp(&b.key));
        for item in unknown {
            lines.push((item.key.clone(), item.value.clone()));
        }
        lines
    }

    fn start_editor(&mut self, policy_id: Option<i64>, attach_after: bool) {
        let policy = policy_id.and_then(|id| self.policies.iter().flatten().find(|p| p.id == id));
        let mut enabled = HashMap::new();
        let mut values = HashMap::new();
        for spec in self.catalog_rows() {
            let existing = policy.and_then(|p| p.items.iter().find(|i| i.key == spec.key));
            enabled.insert(spec.key.clone(), existing.is_some());
            values.insert(
                spec.key.clone(),
                existing
                    .map(|i| i.value.clone())
                    .unwrap_or_else(|| spec.default_value.clone()),
            );
        }
        if let Some(policy) = policy {
            for item in &policy.items {
                enabled.entry(item.key.clone()).or_insert(true);
                values
                    .entry(item.key.clone())
                    .or_insert_with(|| item.value.clone());
            }
        }
        self.draft = Some(PolicyDraft {
            id: policy.map(|p| p.id),
            orig_name: policy.map(|p| p.name.clone()).unwrap_or_default(),
            name: policy.map(|p| p.name.clone()).unwrap_or_default(),
            description: policy.map(|p| p.description.clone()).unwrap_or_default(),
            enabled,
            values,
            attach_after,
            error: None,
        });
        self.mode = Mode::Edit;
    }

    fn draft_entries(&self) -> Vec<DraftEntry> {
        let Some(draft) = &self.draft else {
            return Vec::new();
        };
        let catalog = self.catalog_rows();
        let mut entries = Vec::new();
        for spec in catalog {
            entries.push(DraftEntry {
                key: spec.key.clone(),
                label: self.item_label(&spec.key),
                enabled: draft.enabled.get(&spec.key).copied().unwrap_or(false),
                value: draft.values.get(&spec.key).cloned().unwrap_or_default(),
                int_range: matches!(spec.value_kind, PolicyValueKind::Int).then(|| {
                    (
                        spec.int_min.unwrap_or(i64::MIN),
                        spec.int_max.unwrap_or(i64::MAX),
                    )
                }),
            });
        }
        let mut unknown: Vec<_> = draft
            .enabled
            .keys()
            .filter(|key| !catalog.iter().any(|s| &&s.key == key))
            .cloned()
            .collect();
        unknown.sort();
        for key in unknown {
            entries.push(DraftEntry {
                label: key.clone(),
                enabled: draft.enabled.get(&key).copied().unwrap_or(false),
                value: draft.values.get(&key).cloned().unwrap_or_default(),
                int_range: None,
                key,
            });
        }
        entries
    }

    fn submit_draft(&mut self, ctx: &Context<Self>) -> Result<bool> {
        let entries = self.draft_entries();
        let Some(draft) = &mut self.draft else {
            return Ok(false);
        };
        let items = match validate_draft_items(&draft.name, &entries) {
            Err(error) => {
                draft.error = Some(error);
                return Ok(true);
            }
            Ok(items) => items,
        };
        let name = draft.name.trim().to_owned();
        let description = draft.description.clone();
        if let Some(id) = draft.id {
            self.pending_update = Some(PendingUpdate {
                id,
                name: name.clone(),
                description: description.clone(),
                items: items.clone(),
            });
            self.common.call_graphql::<UpdatePolicy, _>(
                ctx,
                update_policy::Variables {
                    policy_id: id,
                    name: Some(name),
                    description: Some(description),
                    items: Some(
                        items
                            .into_iter()
                            .map(|(key, value)| update_policy::PolicyItemInput { key, value })
                            .collect(),
                    ),
                },
                move |response| Msg::UpdateResponse(id, response),
                "Error trying to update policy",
            );
        } else {
            self.common.call_graphql::<CreatePolicy, _>(
                ctx,
                create_policy::Variables {
                    name,
                    description: Some(description),
                    items: Some(
                        items
                            .into_iter()
                            .map(|(key, value)| create_policy::PolicyItemInput { key, value })
                            .collect(),
                    ),
                },
                Msg::CreateResponse,
                "Error trying to create policy",
            );
        }
        Ok(true)
    }

    fn breadcrumb(&self, domain: Option<&str>) -> String {
        let mut parts = vec![ou_display_name(ROOT_OU_WIRE, domain)];
        if !self.selected.is_empty() {
            parts.extend(self.selected.split('\\').map(str::to_owned));
        }
        parts.join("  ▸  ")
    }

    fn view_tree_pane(&self, ctx: &Context<Self>) -> Html {
        let rows = flatten_ou_rows(self.ous.as_deref().unwrap_or_default());
        html! {
            <div class="wb-pane-tree border-end py-2 d-flex flex-column">
                <div class="text-muted small text-uppercase px-3 pb-1">
                    {"Organizational Units"}
                </div>
                { for rows.iter().map(|row| self.view_tree_row(ctx, row)) }
                <div class="flex-grow-1"></div>
                <div class="border-top mx-3 pt-2 mt-2 small text-muted d-flex flex-column gap-1">
                    <span>
                        <span class="pol-chip" style={format!("border-color:{DEFAULT_CHIP_COLOR}")}>{"solid"}</span>
                        {" set on that OU"}
                    </span>
                    <span>
                        <span class="pol-chip pol-chip-inherited" style={format!("border-color:{DEFAULT_CHIP_COLOR}")}>{"↓ dashed"}</span>
                        {" inherited from above"}
                    </span>
                    <span>
                        <i class="bi-sign-stop-fill text-danger"></i>
                        {" blocks rule inheritance"}
                    </span>
                </div>
            </div>
        }
    }

    fn view_tree_row(&self, ctx: &Context<Self>, row: &OuRow) -> Html {
        let domain = ctx.props().domain.as_deref();
        let is_root = row.key == ROOT_OU_WIRE;
        let is_selected = row.key == self.selected;
        let label = if is_root {
            ou_display_name(ROOT_OU_WIRE, domain)
        } else {
            row.leaf.clone()
        };
        let own = self.direct.get(&row.key);
        let governing = if own.is_none() {
            governing_policy(&row.key, &self.direct, &self.blocked)
        } else {
            None
        };
        let chip = match (own, governing) {
            (Some((id, name)), _) => {
                let color = policy_color(*id);
                html! {
                    <span
                        class="pol-chip"
                        style={format!("border-color:{color};color:{color}")}
                        title={name.clone()}>
                        {name}
                    </span>
                }
            }
            (None, Some((id, name, _))) => {
                let color = policy_color(id);
                html! {
                    <span
                        class="pol-chip pol-chip-inherited"
                        style={format!("border-color:{color};color:{color}")}
                        title={name.clone()}>
                        {format!("↓ {name}")}
                    </span>
                }
            }
            _ => html! {},
        };
        let key = row.key.clone();
        let row_class = if is_selected {
            "wb-tree-row wb-selected"
        } else {
            "wb-tree-row"
        };
        let name_class = if is_selected || is_root {
            "fw-semibold text-truncate"
        } else {
            "text-truncate"
        };
        html! {
            <div
                class={row_class}
                onclick={ctx.link().callback(move |_| Msg::SelectOu(key.clone()))}>
                <span class="d-flex align-items-center" style="min-width: 0">
                    <span class="wb-glyph">{&row.prefix}</span>
                    <span class={name_class} title={label.clone()}>{&label}</span>
                    { if self.blocked.contains(&row.key) {
                        html! { <i class="bi-sign-stop-fill text-danger ms-1 flex-shrink-0"></i> }
                    } else { html! {} } }
                </span>
                {chip}
            </div>
        }
    }

    fn view_inspector_header(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let domain = ctx.props().domain.as_deref();
        let is_root = self.selected == ROOT_OU_WIRE;
        let blocked = self.blocked.contains(&self.selected);
        html! {
            <div class="d-flex align-items-center flex-wrap gap-3">
                <b>{self.breadcrumb(domain)}</b>
                <span class="flex-grow-1"></span>
                { if !is_root {
                    html! {
                        <div class="form-check form-switch d-flex align-items-center gap-2 mb-0">
                            <input
                                class="form-check-input wb-block-switch"
                                type="checkbox"
                                role="switch"
                                id="wb-block-switch"
                                checked={blocked}
                                disabled={self.common.is_task_running()}
                                onchange={link.callback(|e: Event| Msg::ToggleBlock(input_checked(&e)))}
                            />
                            <label class="form-check-label small" for="wb-block-switch">
                                <i class="bi-sign-stop-fill text-danger me-1"></i>
                                { if blocked { "Rules above blocked" } else { "Rules above inherited" } }
                            </label>
                        </div>
                    }
                } else { html! {} } }
            </div>
        }
    }

    fn view_inspector(&self, ctx: &Context<Self>) -> Html {
        let own = self
            .direct
            .get(&self.selected)
            .and_then(|(id, _)| self.policies.iter().flatten().find(|p| p.id == *id));
        html! {
            <>
            { match own {
                Some(policy) => self.view_own_policy_card(ctx, policy),
                None => self.view_attach_box(ctx),
            } }
            {self.view_effective_table(ctx)}
            </>
        }
    }

    fn view_own_policy_card(&self, ctx: &Context<Self>, policy: &Policy) -> Html {
        let link = ctx.link();
        let task = self.common.is_task_running();
        let color = policy_color(policy.id);
        let policy_id = policy.id;
        let linked_elsewhere = self.linked_count(policy.id).saturating_sub(1);
        html! {
            <div class="pol-card" style={format!("border-color:{color}")}>
                <div
                    class="pol-card-header d-flex align-items-center flex-wrap gap-2 px-3 py-2"
                    style={format!("background-color:{color}14;border-color:{color}")}>
                    <span class="pol-dot" style={format!("background-color:{color}")}></span>
                    <b>{&policy.name}</b>
                    <span class="text-muted small">{"on this OU"}</span>
                    <span class="flex-grow-1"></span>
                    <button
                        class="btn btn-outline-secondary btn-sm"
                        type="button"
                        disabled={task}
                        onclick={link.callback(move |_| Msg::StartEditor { policy_id: Some(policy_id), attach_after: false })}>
                        <i class="bi-pencil me-1"></i>{"Edit"}
                    </button>
                    <button
                        class="btn btn-outline-secondary btn-sm"
                        type="button"
                        disabled={task}
                        onclick={link.callback(|_| Msg::StartPick)}>
                        <i class="bi-arrow-left-right me-1"></i>{"Swap"}
                    </button>
                    <button
                        class="btn btn-outline-danger btn-sm"
                        type="button"
                        disabled={task}
                        onclick={link.callback(|_| Msg::RemovePolicy)}>
                        <i class="bi-x-circle me-1"></i>{"Remove"}
                    </button>
                </div>
                <div class="px-3 py-2 d-flex flex-column gap-1">
                    { if !policy.description.is_empty() {
                        html! { <span class="text-muted small">{&policy.description}</span> }
                    } else { html! {} } }
                    { for self.policy_item_lines(policy).into_iter().map(|(label, value)| html! {
                        <div class="d-flex gap-3">
                            <span class="text-muted" style="min-width: 220px">{label}</span>
                            <b>{value}</b>
                        </div>
                    }) }
                    { if linked_elsewhere > 0 {
                        html! {
                            <span class="small text-warning-emphasis">
                                <i class="bi-info-circle me-1"></i>
                                {format!("Also on {linked_elsewhere} other OU(s) — edits apply everywhere it is linked.")}
                            </span>
                        }
                    } else { html! {} } }
                </div>
            </div>
        }
    }

    fn view_attach_box(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let domain = ctx.props().domain.as_deref();
        let note = match governing_policy(&self.selected, &self.direct, &self.blocked) {
            Some((_, name, origin)) => format!(
                "Inheriting “{name}” from {} — attach one here to override.",
                ou_display_name(&origin, domain)
            ),
            None => "Nothing flows in from above — built-in defaults apply.".to_owned(),
        };
        html! {
            <div class="wb-dashed-box d-flex align-items-center gap-3 p-3">
                <span class="text-muted small flex-grow-1">{note}</span>
                <button
                    class="btn btn-primary btn-sm flex-shrink-0"
                    type="button"
                    disabled={self.common.is_task_running()}
                    onclick={link.callback(|_| Msg::StartPick)}>
                    <i class="bi-link-45deg me-1"></i>{"Attach a policy"}
                </button>
            </div>
        }
    }

    fn view_effective_table(&self, ctx: &Context<Self>) -> Html {
        let domain = ctx.props().domain.as_deref();
        let body = match self.effective.get(&self.selected) {
            None => html! {
                <div class="text-muted small">{"Loading effective items..."}</div>
            },
            Some(rows) => html! {
                <div class="border rounded overflow-hidden">
                { for rows.iter().map(|row| {
                    let label = self.item_label(&row.key);
                    let value = format_item_value(&row.key, &row.value);
                    let chip = match (&row.source_policy_id, &row.source_policy_name) {
                        (Some(id), Some(name)) => {
                            let color = policy_color(*id);
                            let origin = row
                                .source_ou
                                .as_deref()
                                .map(|ou| {
                                    if ou.eq_ignore_ascii_case(&self.selected) {
                                        "this OU".to_owned()
                                    } else {
                                        ou_display_name(ou, domain)
                                    }
                                })
                                .unwrap_or_default();
                            let text = format!("{name} · {origin}");
                            html! {
                                <span
                                    class="pol-chip"
                                    style={format!("border-color:{color};color:{color}")}
                                    title={text.clone()}>
                                    {text}
                                </span>
                            }
                        }
                        _ => html! {
                            <span
                                class="pol-chip pol-chip-inherited"
                                style={format!("border-color:{DEFAULT_CHIP_COLOR};color:{DEFAULT_CHIP_COLOR}")}>
                                {"built-in default"}
                            </span>
                        },
                    };
                    html! {
                        <div class="d-flex align-items-center gap-3 px-3 py-2 border-bottom">
                            <span class="text-truncate" style="flex: 2; min-width: 0" title={label.clone()}>{&label}</span>
                            <b class="text-truncate" style="flex: 1; min-width: 0" title={value.clone()}>{&value}</b>
                            <span class="ms-auto flex-shrink-0">{chip}</span>
                        </div>
                    }
                }) }
                </div>
            },
        };
        let unenforced = self.catalog_rows().iter().any(|row| !row.enforced);
        html! {
            <div class="d-flex flex-column gap-2">
                <div class="text-muted small text-uppercase">{"Current OU policy"}</div>
                {body}
                { if unenforced {
                    html! {
                        <span class="small text-muted">
                            {"Nothing is enforced at login yet in 0.7.6 — values resolve and wait for the enforcement pass."}
                        </span>
                    }
                } else { html! {} } }
            </div>
        }
    }

    fn view_pick(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let domain = ctx.props().domain.as_deref();
        let display = ou_display_name(&self.selected, domain);
        let current = self.direct.get(&self.selected).map(|(id, _)| *id);
        html! {
            <div class="d-flex flex-column gap-2">
                <div class="d-flex align-items-center flex-wrap gap-2">
                    <b>{format!("Pick a policy for {display}")}</b>
                    <span class="text-muted small">
                        {"an OU holds one policy — picking replaces the current one"}
                    </span>
                    <span class="flex-grow-1"></span>
                    <button
                        class="btn btn-outline-secondary btn-sm"
                        type="button"
                        onclick={link.callback(|_| Msg::CancelToView)}>
                        {"Cancel"}
                    </button>
                </div>
                { for self.policies.iter().flatten().map(|policy| {
                    let color = policy_color(policy.id);
                    let is_current = current == Some(policy.id);
                    let summary = self
                        .policy_item_lines(policy)
                        .into_iter()
                        .map(|(label, value)| format!("{label}: {value}"))
                        .collect::<Vec<_>>()
                        .join("  ·  ");
                    let policy_id = policy.id;
                    html! {
                        <div class="pol-card d-flex align-items-center gap-3 px-3 py-2" style={format!("border-color:{color}")}>
                            <span class="pol-dot" style={format!("background-color:{color}")}></span>
                            <div class="flex-grow-1" style="min-width: 0">
                                <div class="d-flex align-items-baseline gap-2">
                                    <b>{&policy.name}</b>
                                    <span class="text-muted small">{format!("on {} OU(s)", self.linked_count(policy.id))}</span>
                                </div>
                                <div class="small text-muted text-truncate" title={summary.clone()}>{&summary}</div>
                            </div>
                            { if is_current {
                                html! { <span class="text-muted small flex-shrink-0"><i class="bi-check me-1"></i>{"current"}</span> }
                            } else { html! {} } }
                            <button
                                class="btn btn-outline-primary btn-sm flex-shrink-0"
                                type="button"
                                disabled={self.common.is_task_running() || is_current}
                                onclick={link.callback(move |_| Msg::UsePolicy(policy_id))}>
                                {"Use this"}
                            </button>
                        </div>
                    }
                }) }
                <div
                    class="wb-dashed-box text-center text-muted p-3"
                    role="button"
                    onclick={link.callback(|_| Msg::StartEditor { policy_id: None, attach_after: true })}>
                    <i class="bi-journal-plus me-1"></i>
                    {"Make a new policy and attach it here"}
                </div>
            </div>
        }
    }

    fn view_editor(&self, ctx: &Context<Self>) -> Html {
        let Some(draft) = &self.draft else {
            return html! {};
        };
        let link = ctx.link();
        let domain = ctx.props().domain.as_deref();
        let task = self.common.is_task_running();
        let title = match draft.id {
            Some(_) => format!("Edit “{}”", draft.orig_name),
            None => "New policy".to_owned(),
        };
        let linked = draft.id.map(|id| self.linked_count(id)).unwrap_or(0);
        html! {
            <div class="d-flex flex-column gap-3">
                <div class="d-flex align-items-center flex-wrap gap-2">
                    <b>{title}</b>
                    { if draft.id.is_none() && draft.attach_after {
                        html! {
                            <span class="small text-primary">
                                <i class="bi-link-45deg me-1"></i>
                                {format!("Saving will also attach it to {}", ou_display_name(&self.selected, domain))}
                            </span>
                        }
                    } else { html! {} } }
                </div>
                { if linked > 1 {
                    html! {
                        <div class="alert alert-warning py-2 mb-0 small">
                            {format!("This policy is on {linked} OUs. Your changes apply to all of them.")}
                        </div>
                    }
                } else { html! {} } }
                <div class="d-flex flex-wrap gap-3">
                    <label class="form-label small mb-0" style="flex: 1; min-width: 180px">
                        {"Name"}
                        <input
                            class="form-control"
                            value={draft.name.clone()}
                            placeholder="e.g. Front Desk"
                            oninput={link.callback(|e: InputEvent| Msg::DraftNameChanged(input_value(&e)))}
                        />
                    </label>
                    <label class="form-label small mb-0" style="flex: 2; min-width: 220px">
                        {"Description (optional)"}
                        <input
                            class="form-control"
                            value={draft.description.clone()}
                            placeholder="What is this policy for?"
                            oninput={link.callback(|e: InputEvent| Msg::DraftDescriptionChanged(input_value(&e)))}
                        />
                    </label>
                </div>
                <div class="d-flex flex-column gap-2">
                    <div class="text-muted small text-uppercase">
                        {"Rules — tick the ones this policy sets"}
                    </div>
                    { for self.draft_entries().iter().map(|entry| self.view_rule_row(ctx, entry)) }
                </div>
                { if let Some(error) = &draft.error {
                    html! { <span class="text-danger small">{error}</span> }
                } else { html! {} } }
                <div class="d-flex align-items-center gap-2">
                    <button
                        class="btn btn-primary"
                        type="button"
                        disabled={task}
                        onclick={link.callback(|_| Msg::SubmitDraft)}>
                        {"Save"}
                    </button>
                    <button
                        class="btn btn-outline-secondary"
                        type="button"
                        disabled={task}
                        onclick={link.callback(|_| Msg::CancelToView)}>
                        {"Cancel"}
                    </button>
                    <span class="flex-grow-1"></span>
                    { if draft.id.is_some() {
                        html! {
                            <button
                                class="btn btn-link btn-sm text-danger text-decoration-none"
                                type="button"
                                disabled={task}
                                onclick={link.callback(|_| Msg::ClickedDeletePolicy)}>
                                <i class="bi-x-circle-fill me-1"></i>
                                {"Delete this policy everywhere"}
                            </button>
                        }
                    } else { html! {} } }
                </div>
            </div>
        }
    }

    fn view_rule_row(&self, ctx: &Context<Self>, entry: &DraftEntry) -> Html {
        let link = ctx.link();
        let spec = self.catalog_rows().iter().find(|s| s.key == entry.key);
        let text = catalog_text(&entry.key);
        let help = text
            .as_ref()
            .map(|t| t.help.to_owned())
            .or_else(|| spec.map(|s| s.description.clone()))
            .unwrap_or_default();
        let placeholder = text.as_ref().map(|t| t.placeholder).unwrap_or_default();
        let off = !entry.enabled;
        let control_disabled = off || self.common.is_task_running();
        let key = entry.key.clone();
        let value_key = entry.key.clone();
        let control = match spec.map(|s| s.value_kind) {
            Some(PolicyValueKind::Enum) => {
                let allowed = spec
                    .and_then(|s| s.allowed_values.clone())
                    .unwrap_or_default();
                html! {
                    <select
                        class="form-select form-select-sm w-auto"
                        disabled={control_disabled}
                        onchange={link.callback(move |e: Event| {
                            Msg::DraftValueChanged(value_key.clone(), select_value(&e))
                        })}>
                        { for allowed.iter().map(|token| html! {
                            <option value={token.clone()} selected={token == &entry.value}>{token}</option>
                        }) }
                    </select>
                }
            }
            Some(PolicyValueKind::Int) => {
                let min = spec.and_then(|s| s.int_min).map(|n| n.to_string());
                let max = spec.and_then(|s| s.int_max).map(|n| n.to_string());
                html! {
                    <input
                        type="number"
                        class="form-control form-control-sm"
                        style="width: 110px"
                        min={min.unwrap_or_default()}
                        max={max.unwrap_or_default()}
                        value={entry.value.clone()}
                        disabled={control_disabled}
                        oninput={link.callback(move |e: InputEvent| {
                            Msg::DraftValueChanged(value_key.clone(), input_value(&e))
                        })}
                    />
                }
            }
            _ => html! {
                <input
                    type="text"
                    class="form-control form-control-sm font-monospace"
                    style="flex: 1; min-width: 140px"
                    placeholder={placeholder}
                    value={entry.value.clone()}
                    disabled={control_disabled}
                    oninput={link.callback(move |e: InputEvent| {
                        Msg::DraftValueChanged(value_key.clone(), input_value(&e))
                    })}
                />
            },
        };
        let row_class = if off {
            "border rounded px-3 py-2 d-flex align-items-center flex-wrap gap-2 wb-rule-row-off"
        } else {
            "border rounded px-3 py-2 d-flex align-items-center flex-wrap gap-2"
        };
        let checkbox_id = format!("wb-rule-{}", entry.key);
        html! {
            <div class={row_class}>
                <input
                    class="form-check-input mt-0 flex-shrink-0"
                    type="checkbox"
                    id={checkbox_id.clone()}
                    checked={entry.enabled}
                    disabled={self.common.is_task_running()}
                    onchange={link.callback(move |_| Msg::DraftRuleToggled(key.clone()))}
                />
                <label class="flex-shrink-0" for={checkbox_id} style="width: 230px; cursor: pointer">
                    <span class="fw-semibold d-block">{&entry.label}</span>
                    <span class="font-monospace small text-muted">{&entry.key}</span>
                </label>
                {control}
                <span class="small text-muted" style="flex: 1; min-width: 150px">{help}</span>
            </div>
        }
    }

    fn view_delete_modal(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let (name, linked) = self
            .draft
            .as_ref()
            .and_then(|d| d.id)
            .map(|id| {
                (
                    self.policy_name(id).unwrap_or_default(),
                    self.linked_count(id),
                )
            })
            .unwrap_or_default();
        html! {
            <div
                class="modal fade"
                id="deletePolicyModal"
                tabindex="-1"
                aria-labelledby="deletePolicyModalLabel"
                aria-hidden="true"
                ref={self.modal.node_ref()}>
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="deletePolicyModalLabel">
                                {format!("Delete “{name}” everywhere?")}
                            </h5>
                            <button
                                type="button"
                                class="btn-close"
                                aria-label="Close"
                                onclick={link.callback(|_| Msg::DismissModal)} />
                        </div>
                        <div class="modal-body">
                            <span>
                                {format!(
                                    "This permanently deletes the policy. It is linked to {linked} OU(s); they fall back to inherited policies."
                                )}
                            </span>
                        </div>
                        <div class="modal-footer">
                            <button
                                type="button"
                                class="btn btn-secondary"
                                onclick={link.callback(|_| Msg::DismissModal)}>
                                <i class="bi-x-circle me-2"></i>
                                {"Cancel"}
                            </button>
                            <button
                                type="button"
                                class="btn btn-danger"
                                disabled={self.common.is_task_running()}
                                onclick={link.callback(|_| Msg::ConfirmDeletePolicy)}>
                                <i class="bi-check-circle me-2"></i>
                                {"Yes, delete it"}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}
