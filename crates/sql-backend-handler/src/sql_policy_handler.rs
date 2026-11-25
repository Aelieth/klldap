use crate::sql_activity_handler::read_activity_on;
use crate::sql_backend_handler::SqlBackendHandler;
use crate::sql_lockout_handler::CountingStart;
use crate::sql_log_handler::to_active_model;
use crate::sql_mfa_windows::read_windows;
use crate::sql_tables::DbConnection;
use async_trait::async_trait;
use lldap_domain::types::{User, UserId};
use lldap_domain_handlers::handler::PolicyBackendHandler;
use lldap_domain_handlers::inactivity::Recorded;
use lldap_domain_handlers::kdc_proof::ProofWindow;
use lldap_domain_handlers::logging::{self, LogEvent, LogKind};
use lldap_domain_handlers::policies::{
    AttachedPolicy, CreatePolicyRequest, OuPolicyState, Policy, PolicyId, PolicyLevel, ROOT_OU_KEY,
    UpdatePolicyRequest, canonical_ou_key, ou_chain, ou_display,
};
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, OuPoliciesColumn, PoliciesColumn},
};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder, Set, TransactionTrait,
    sea_query::{Expr, OnConflict},
};
use std::collections::{BTreeMap, HashMap};
use tracing::instrument;

fn encode_items(items: &BTreeMap<String, String>) -> Result<String> {
    serde_json::to_string(items)
        .map_err(|e| DomainError::InternalError(format!("serializing policy items: {e}")))
}

pub(crate) fn decode_items(raw: &str) -> Result<BTreeMap<String, String>> {
    serde_json::from_str(raw)
        .map_err(|e| DomainError::InternalError(format!("decoding policy items: {e}")))
}

fn to_policy(row: model::policies::Model, linked_ous: Vec<String>) -> Result<Policy> {
    Ok(Policy {
        id: PolicyId(row.id),
        name: row.name,
        description: row.description,
        items: decode_items(&row.items)?,
        linked_ous,
    })
}

impl SqlBackendHandler {
    async fn load_links(&self) -> Result<HashMap<i32, Vec<String>>> {
        let mut links: HashMap<i32, Vec<String>> = HashMap::new();
        for row in model::OuPolicies::find().all(&self.sql_pool).await? {
            if let Some(policy_id) = row.policy_id {
                links.entry(policy_id).or_default().push(row.ou_key);
            }
        }
        for ous in links.values_mut() {
            ous.sort();
        }
        Ok(links)
    }

    async fn normalize_empty_ou_rows(transaction: &sea_orm::DatabaseTransaction) -> Result<u64> {
        Ok(model::OuPolicies::delete_many()
            .filter(OuPoliciesColumn::PolicyId.is_null())
            .filter(OuPoliciesColumn::BlockInheritance.eq(false))
            .exec(transaction)
            .await?
            .rows_affected)
    }
}

pub const UNLINKED_BY_TOOL: &str = "lldap policy-unlink";

/// The host tool's unlink, the link and its row in one transaction; the root is `(root)` or `""`.
pub async fn unlink_ou_policy_on(pool: &DbConnection, ou: &str) -> Result<LogEvent> {
    let ou_key = match ou == ou_display(ROOT_OU_KEY) {
        true => ROOT_OU_KEY.to_owned(),
        false => canonical_ou_key(ou),
    };
    let transaction = pool.begin().await?;
    let existing = model::OuPolicies::find_by_id(&ou_key)
        .one(&transaction)
        .await?;
    let linked = existing.and_then(|row| row.policy_id.map(|id| (row, id)));
    let Some((existing, policy_id)) = linked else {
        return Err(DomainError::EntityNotFound(format!(
            "no policy set on OU {}",
            ou_display(&ou_key)
        )));
    };
    let name = model::Policies::find_by_id(policy_id)
        .one(&transaction)
        .await?
        .map(|p| p.name)
        .unwrap_or_else(|| policy_id.to_string());
    let mut active: model::ou_policies::ActiveModel = existing.into();
    active.policy_id = Set(None);
    active.update(&transaction).await?;
    SqlBackendHandler::normalize_empty_ou_rows(&transaction).await?;
    let detail = format!("policy cleared: {name} ({UNLINKED_BY_TOOL})");
    let target = Some(ou_display(&ou_key));
    let row = logging::event(LogKind::PolicyChange, target, true, Some(&detail));
    model::Logs::insert(to_active_model(row.clone()))
        .exec_without_returning(&transaction)
        .await?;
    transaction.commit().await?;
    Ok(row)
}

async fn attached_by_id_on(
    db: &impl ConnectionTrait,
    ids: &[i32],
) -> Result<HashMap<i32, AttachedPolicy>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut map = HashMap::new();
    for row in model::Policies::find()
        .filter(PoliciesColumn::Id.is_in(ids.iter().copied()))
        .all(db)
        .await?
    {
        map.insert(
            row.id,
            AttachedPolicy {
                id: PolicyId(row.id),
                name: row.name,
                items: decode_items(&row.items)?,
            },
        );
    }
    Ok(map)
}

/// Root-first levels for `ou`, every read on `db`.
pub(crate) async fn policy_levels_on(
    db: &impl ConnectionTrait,
    ou: &str,
) -> Result<Vec<PolicyLevel>> {
    let keys = ou_chain(ou);
    let rows = model::OuPolicies::find()
        .filter(OuPoliciesColumn::OuKey.is_in(keys.clone()))
        .all(db)
        .await?;
    let by_key: HashMap<_, _> = rows.into_iter().map(|r| (r.ou_key.clone(), r)).collect();
    let ids: Vec<i32> = by_key.values().filter_map(|r| r.policy_id).collect();
    let attached = attached_by_id_on(db, &ids).await?;
    Ok(keys
        .into_iter()
        .map(|key| {
            let row = by_key.get(&key);
            PolicyLevel {
                blocked: row.is_some_and(|r| r.block_inheritance),
                policy: row.and_then(|r| r.policy_id.and_then(|id| attached.get(&id).cloned())),
                ou_key: key,
            }
        })
        .collect())
}

#[async_trait]
impl PolicyBackendHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn list_policies(&self) -> Result<Vec<Policy>> {
        let links = self.load_links().await?;
        let rows = model::Policies::find()
            .order_by_asc(PoliciesColumn::LowercaseName)
            .all(&self.sql_pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                let linked = links.get(&row.id).cloned().unwrap_or_default();
                to_policy(row, linked)
            })
            .collect()
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn get_policy(&self, policy_id: PolicyId) -> Result<Policy> {
        let row = model::Policies::find_by_id(policy_id.0)
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| {
                DomainError::EntityNotFound(format!("No such policy: {}", policy_id.0))
            })?;
        let mut linked: Vec<String> = model::OuPolicies::find()
            .filter(OuPoliciesColumn::PolicyId.eq(policy_id.0))
            .all(&self.sql_pool)
            .await?
            .into_iter()
            .map(|r| r.ou_key)
            .collect();
        linked.sort();
        to_policy(row, linked)
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn create_policy(&self, request: CreatePolicyRequest) -> Result<PolicyId> {
        let lowercase_name = request.name.to_lowercase();
        let inserted = model::policies::ActiveModel {
            name: Set(request.name.clone()),
            lowercase_name: Set(lowercase_name),
            description: Set(request.description),
            items: Set(encode_items(&request.items)?),
            ..Default::default()
        }
        .insert(&self.sql_pool)
        .await?;
        logging::record(LogKind::PolicyChange, Some(&request.name), Some("created"));
        Ok(PolicyId(inserted.id))
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn update_policy(&self, request: UpdatePolicyRequest) -> Result<()> {
        let existing = model::Policies::find_by_id(request.id.0)
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| {
                DomainError::EntityNotFound(format!("No such policy: {}", request.id.0))
            })?;
        let mut active: model::policies::ActiveModel = existing.clone().into();
        let mut changed = Vec::new();
        if let Some(name) = &request.name {
            active.name = Set(name.clone());
            active.lowercase_name = Set(name.to_lowercase());
            changed.push("name");
        }
        if let Some(description) = request.description {
            active.description = Set(description);
            changed.push("description");
        }
        if let Some(items) = request.items {
            active.items = Set(encode_items(&items)?);
            changed.push("items");
        }
        if changed.is_empty() {
            return Ok(());
        }
        let transaction = self.sql_pool.begin().await?;
        let start = CountingStart::before(&transaction).await?;
        active.update(&transaction).await?;
        start.after(&transaction).await?;
        transaction.commit().await?;
        self.policy_changed().await;
        let name = request.name.as_deref().unwrap_or(existing.name.as_str());
        logging::record(
            LogKind::PolicyChange,
            Some(name),
            Some(&format!("updated: {}", changed.join(", "))),
        );
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn delete_policy(&self, policy_id: PolicyId) -> Result<()> {
        let existing = model::Policies::find_by_id(policy_id.0)
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| {
                DomainError::EntityNotFound(format!("No such policy: {}", policy_id.0))
            })?;
        let transaction = self.sql_pool.begin().await?;
        model::OuPolicies::update_many()
            .col_expr(OuPoliciesColumn::PolicyId, Expr::cust("NULL"))
            .filter(OuPoliciesColumn::PolicyId.eq(policy_id.0))
            .exec(&transaction)
            .await?;
        Self::normalize_empty_ou_rows(&transaction).await?;
        model::Policies::delete_by_id(policy_id.0)
            .exec(&transaction)
            .await?;
        transaction.commit().await?;
        self.policy_changed().await;
        logging::record(LogKind::PolicyChange, Some(&existing.name), Some("deleted"));
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn set_ou_policy(&self, ou: &str, policy_id: PolicyId) -> Result<()> {
        let ou_key = canonical_ou_key(ou);
        let policy = self.get_policy(policy_id).await?;
        let row = model::ou_policies::ActiveModel {
            ou_key: Set(ou_key.clone()),
            policy_id: Set(Some(policy_id.0)),
            block_inheritance: ActiveValue::NotSet,
        };
        let transaction = self.sql_pool.begin().await?;
        let start = CountingStart::before(&transaction).await?;
        model::OuPolicies::insert(row)
            .on_conflict(
                OnConflict::column(OuPoliciesColumn::OuKey)
                    .update_column(OuPoliciesColumn::PolicyId)
                    .to_owned(),
            )
            .exec(&transaction)
            .await?;
        start.after(&transaction).await?;
        transaction.commit().await?;
        self.policy_changed().await;
        logging::record(
            LogKind::PolicyChange,
            Some(ou_display(&ou_key)),
            Some(&format!("policy set: {}", policy.name)),
        );
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn clear_ou_policy(&self, ou: &str) -> Result<()> {
        let ou_key = canonical_ou_key(ou);
        let existing = model::OuPolicies::find_by_id(&ou_key)
            .one(&self.sql_pool)
            .await?;
        let Some(existing) = existing else {
            return Err(DomainError::EntityNotFound(format!(
                "no policy set on OU {}",
                ou_display(&ou_key)
            )));
        };
        let Some(policy_id) = existing.policy_id else {
            return Err(DomainError::EntityNotFound(format!(
                "no policy set on OU {}",
                ou_display(&ou_key)
            )));
        };
        let name = model::Policies::find_by_id(policy_id)
            .one(&self.sql_pool)
            .await?
            .map(|p| p.name)
            .unwrap_or_else(|| policy_id.to_string());
        let transaction = self.sql_pool.begin().await?;
        let mut active: model::ou_policies::ActiveModel = existing.into();
        active.policy_id = Set(None);
        active.update(&transaction).await?;
        Self::normalize_empty_ou_rows(&transaction).await?;
        transaction.commit().await?;
        self.policy_changed().await;
        logging::record(
            LogKind::PolicyChange,
            Some(ou_display(&ou_key)),
            Some(&format!("policy cleared: {name}")),
        );
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn set_ou_policy_inheritance(&self, ou: &str, blocked: bool) -> Result<()> {
        let ou_key = canonical_ou_key(ou);
        let existing = model::OuPolicies::find_by_id(&ou_key)
            .one(&self.sql_pool)
            .await?;
        if existing
            .as_ref()
            .is_some_and(|row| row.block_inheritance == blocked)
        {
            return Ok(());
        }
        let transaction = self.sql_pool.begin().await?;
        if let Some(existing) = existing {
            let mut active: model::ou_policies::ActiveModel = existing.into();
            active.block_inheritance = Set(blocked);
            active.update(&transaction).await?;
        } else {
            model::ou_policies::ActiveModel {
                ou_key: Set(ou_key.clone()),
                policy_id: Set(None),
                block_inheritance: Set(blocked),
            }
            .insert(&transaction)
            .await?;
        }
        Self::normalize_empty_ou_rows(&transaction).await?;
        transaction.commit().await?;
        self.policy_changed().await;
        logging::record(
            LogKind::PolicyChange,
            Some(ou_display(&ou_key)),
            Some(if blocked {
                "inheritance blocked"
            } else {
                "inheritance unblocked"
            }),
        );
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn list_ou_policy_states(&self) -> Result<Vec<OuPolicyState>> {
        let rows = model::OuPolicies::find()
            .order_by_asc(OuPoliciesColumn::OuKey)
            .all(&self.sql_pool)
            .await?;
        let ids: Vec<i32> = rows.iter().filter_map(|r| r.policy_id).collect();
        let attached = attached_by_id_on(&self.sql_pool, &ids).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let policy = row.policy_id.and_then(|id| attached.get(&id));
                OuPolicyState {
                    ou_key: row.ou_key,
                    policy_id: policy.map(|p| p.id),
                    policy_name: policy.map(|p| p.name.clone()),
                    block_inheritance: row.block_inheritance,
                }
            })
            .collect())
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn get_policy_levels(&self, ou: &str) -> Result<Vec<PolicyLevel>> {
        policy_levels_on(&self.sql_pool, ou).await
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn delete_ou_policy_state(&self, ou: &str) -> Result<()> {
        let ou_key = canonical_ou_key(ou);
        let result = model::OuPolicies::delete_by_id(&ou_key)
            .exec(&self.sql_pool)
            .await?;
        if result.rows_affected > 0 {
            self.policy_changed().await;
            logging::record(
                LogKind::PolicyChange,
                Some(ou_display(&ou_key)),
                Some("ou removed"),
            );
        }
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn bounded_policy_entry(&self, user: &UserId) -> Result<(User, Vec<PolicyLevel>)> {
        self.bounded_entry(user).await
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn bounded_policy_levels(&self, ou: &str) -> Result<Vec<PolicyLevel>> {
        self.bounded_levels(ou).await
    }

    async fn read_proof_windows(
        &self,
        user: Option<&UserId>,
    ) -> Result<Vec<(UserId, ProofWindow)>> {
        read_windows(&self.sql_pool, user).await
    }

    async fn read_activity(&self, user: Option<&UserId>) -> Result<Vec<(UserId, Recorded)>> {
        read_activity_on(&self.sql_pool, user).await
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn bounded_activity_entry(
        &self,
        user: &UserId,
    ) -> Result<(User, Vec<PolicyLevel>, Recorded)> {
        self.bounded_active_entry(user).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::get_initialized_db;
    use crate::sql_lockout_handler::tests as doors;
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain::requests::{CreateUserRequest, UpdateUserRequest};
    use lldap_domain::types::{Attribute, LoginOutcome, UserId};
    use lldap_domain_handlers::enforcement::{
        Attempt, Door, PolicyCache, Refusal, UNREADABLE, admit, admit_at_kdc, fill_policy_cache,
        follow_commit, item_checks, user_written,
    };
    use lldap_domain_handlers::handler::UserBackendHandler;
    use lldap_domain_handlers::kerberos::CommitError;
    use lldap_domain_handlers::logging::{LogKind, RequestMeta, with_request};
    use lldap_domain_handlers::password::{
        PASSWORD_MIN_LENGTH, PASSWORD_MIN_LENGTH_ITEM, PasswordChangeError, PasswordSync,
        change_password_everywhere, min_length_for_user, min_length_of,
    };
    use lldap_test_utils::enforcement::EnforcementGuard;
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn items(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    async fn handler() -> SqlBackendHandler {
        SqlBackendHandler::new(generate_random_private_key(), get_initialized_db().await)
    }

    fn own_cache() -> &'static PolicyCache {
        Box::leak(Box::new(PolicyCache::new()))
    }

    fn ou(value: &str) -> Attribute {
        Attribute {
            name: "ou".into(),
            value: value.to_owned().into(),
        }
    }

    async fn user_in(handler: &SqlBackendHandler, name: &str, at: &str) {
        handler
            .create_user(CreateUserRequest {
                user_id: UserId::new(name),
                email: format!("{name}@example.com").into(),
                attributes: vec![ou(at)],
                ..Default::default()
            })
            .await
            .unwrap();
    }

    async fn move_to(handler: &SqlBackendHandler, name: &str, at: &str) {
        handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new(name),
                insert_attributes: vec![ou(at)],
                ..Default::default()
            })
            .await
            .unwrap();
    }

    async fn policy(handler: &SqlBackendHandler, name: &str, pairs: &[(&str, &str)]) -> PolicyId {
        handler
            .create_policy(CreatePolicyRequest {
                name: name.to_owned(),
                description: String::new(),
                items: items(pairs),
            })
            .await
            .unwrap()
    }

    async fn set_items(handler: &SqlBackendHandler, id: PolicyId, pairs: &[(&str, &str)]) {
        handler
            .update_policy(UpdatePolicyRequest {
                id,
                name: None,
                description: None,
                items: Some(items(pairs)),
            })
            .await
            .unwrap();
    }

    // Behind the handler's back, so no cache follows it.
    async fn store_items(handler: &SqlBackendHandler, id: PolicyId, raw: &str) {
        model::Policies::update_many()
            .col_expr(PoliciesColumn::Items, Expr::value(raw))
            .filter(PoliciesColumn::Id.eq(id.0))
            .exec(&handler.sql_pool)
            .await
            .unwrap();
    }

    fn held_item(cache: &PolicyCache, user: &str, key: &str) -> Option<String> {
        let entries = cache.get();
        let items = entries.items_of(&UserId::new(user))?;
        let item = items.iter().find(|item| item.key == key)?;
        Some(item.value.clone())
    }

    fn mfa_of(cache: &PolicyCache, user: &str) -> Option<String> {
        held_item(cache, user, "enable-mfa")
    }

    #[tokio::test]
    async fn test_policy_lifecycle() {
        let handler = handler().await.with_policy_cache(own_cache());
        let id = handler
            .create_policy(CreatePolicyRequest {
                name: "Base".to_owned(),
                description: "d".to_owned(),
                items: items(&[("enable-mfa", "off")]),
            })
            .await
            .unwrap();
        let got = handler.get_policy(id).await.unwrap();
        assert_eq!(got.name, "Base");
        assert_eq!(got.items.get("enable-mfa").map(String::as_str), Some("off"));
        let listed = handler.list_policies().await.unwrap();
        assert_eq!(listed.len(), 1);

        handler
            .update_policy(UpdatePolicyRequest {
                id,
                name: Some("Base Policy".to_owned()),
                description: None,
                items: Some(items(&[("enable-mfa", "always")])),
            })
            .await
            .unwrap();
        handler.set_ou_policy("", id).await.unwrap();
        handler.set_ou_policy("people\\labs", id).await.unwrap();
        let levels = handler.get_policy_levels("people\\labs").await.unwrap();
        assert_eq!(
            levels.iter().map(|l| l.ou_key.as_str()).collect::<Vec<_>>(),
            ["", "people", "people\\labs"]
        );
        assert!(levels[0].policy.is_some());
        assert!(levels[1].policy.is_none());
        assert!(levels[2].policy.is_some());

        handler.clear_ou_policy("people\\labs").await.unwrap();
        let err = handler.clear_ou_policy("people\\labs").await.unwrap_err();
        assert!(err.to_string().contains("no policy set"), "{err}");

        handler
            .set_ou_policy_inheritance("people\\labs", true)
            .await
            .unwrap();
        handler
            .set_ou_policy_inheritance("people\\labs", true)
            .await
            .unwrap();
        let levels = handler.get_policy_levels("people\\labs").await.unwrap();
        assert!(levels[2].blocked, "stored block flag reaches the levels");
        assert!(!levels[0].blocked && !levels[1].blocked);
        handler.set_ou_policy("people\\labs", id).await.unwrap();
        handler.delete_policy(id).await.unwrap();
        let states = handler.list_ou_policy_states().await.unwrap();
        let blocked = states
            .iter()
            .find(|s| s.ou_key == "people\\labs")
            .expect("block flag survives unlink");
        assert!(blocked.block_inheritance);
        assert!(blocked.policy_id.is_none());
        let root_gone = states.iter().all(|s| !s.ou_key.is_empty());
        assert!(
            root_gone,
            "NULL,false root row is normalized away: {states:?}"
        );

        handler
            .delete_ou_policy_state("people\\labs")
            .await
            .unwrap();
        assert!(handler.list_ou_policy_states().await.unwrap().is_empty());
    }

    #[tokio::test]
    #[serial]
    async fn test_policy_log_rows() {
        let guard = LogGuard::install_on_this_thread();
        let peer = "10.88.0.1";
        with_request(
            RequestMeta::http(Some(peer.parse().unwrap()), None),
            async {
                let handler = handler().await;
                let id = handler
                    .create_policy(CreatePolicyRequest {
                        name: "Hours".to_owned(),
                        description: String::new(),
                        items: BTreeMap::new(),
                    })
                    .await
                    .unwrap();
                handler
                    .update_policy(UpdatePolicyRequest {
                        id,
                        name: None,
                        description: Some("n".to_owned()),
                        items: None,
                    })
                    .await
                    .unwrap();
                handler.set_ou_policy("people", id).await.unwrap();
                handler
                    .set_ou_policy_inheritance("people", true)
                    .await
                    .unwrap();
                handler.clear_ou_policy("people").await.unwrap();
                handler.delete_ou_policy_state("people").await.unwrap();
                handler.delete_policy(id).await.unwrap();
            },
        )
        .await;
        let rows: Vec<(LogKind, Option<String>, Option<String>)> = guard
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.peer.as_deref() == Some(peer))
            .filter(|e| e.kind == LogKind::PolicyChange)
            .map(|e| (e.kind, e.target, e.detail))
            .collect();
        assert_eq!(
            rows,
            vec![
                (
                    LogKind::PolicyChange,
                    Some("Hours".into()),
                    Some("created".into())
                ),
                (
                    LogKind::PolicyChange,
                    Some("Hours".into()),
                    Some("updated: description".into())
                ),
                (
                    LogKind::PolicyChange,
                    Some("people".into()),
                    Some("policy set: Hours".into())
                ),
                (
                    LogKind::PolicyChange,
                    Some("people".into()),
                    Some("inheritance blocked".into())
                ),
                (
                    LogKind::PolicyChange,
                    Some("people".into()),
                    Some("policy cleared: Hours".into())
                ),
                (
                    LogKind::PolicyChange,
                    Some("people".into()),
                    Some("ou removed".into())
                ),
                (
                    LogKind::PolicyChange,
                    Some("Hours".into()),
                    Some("deleted".into())
                ),
            ]
        );
    }

    async fn policy_rows(pool: &DbConnection) -> Vec<(Option<String>, Option<String>, bool)> {
        let rows = model::Logs::find()
            .filter(model::LogsColumn::Kind.eq("policy_change"))
            .order_by_asc(model::LogsColumn::Id)
            .all(pool)
            .await
            .unwrap();
        let row = |row: model::logs::Model| (row.target, row.detail, row.success);
        rows.into_iter().map(row).collect()
    }

    #[tokio::test]
    async fn test_the_host_tool_unlinks_one_ou_with_its_one_row() {
        let handler = handler().await;
        let id = policy(&handler, "Hours", &[]).await;
        let pool = handler.pool().clone();
        let detail = "policy cleared: Hours (lldap policy-unlink)";
        type Row = (&'static str, Option<&'static str>, Option<&'static str>);
        let rows: [Row; 5] = [
            ("people", Some("people"), Some("people")),
            ("People", Some("people"), Some("people")),
            ("(root)", Some(""), Some("(root)")),
            ("", Some(""), Some("(root)")),
            ("people", None, None),
        ];
        for (named, link, target) in rows {
            if let Some(ou) = link {
                handler.set_ou_policy(ou, id).await.unwrap();
            }
            let before = policy_rows(&pool).await.len();
            let unlinked = unlink_ou_policy_on(&pool, named).await;
            let written = policy_rows(&pool).await.split_off(before);
            let states = handler.list_ou_policy_states().await.unwrap();
            let linked = states.iter().any(|state| state.policy_id.is_some());
            let Some(target) = target else {
                assert!(unlinked.is_err(), "{named:?}: an OU with no link");
                assert!(written.is_empty(), "{named:?}: no row, {written:?}");
                continue;
            };
            let one = (Some(target.to_owned()), Some(detail.to_owned()), true);
            let row = unlinked.unwrap();
            assert_eq!(
                ((row.target, row.detail, row.success), written, linked),
                (one.clone(), vec![one], false),
                "{named:?}: the link gone, its one row in the table and printed"
            );
        }
    }

    #[tokio::test]
    async fn test_each_policy_write_swaps_the_cache() {
        let handler = handler().await.with_policy_cache(own_cache());
        let mut seen = handler.policy_changes();
        let mut swapped = |handler: &SqlBackendHandler| {
            let now = handler.policy_changes();
            let changed = now - seen;
            seen = now;
            changed
        };
        let id = policy(&handler, "Hours", &[]).await;
        assert_eq!(swapped(&handler), 0, "create");
        set_items(&handler, id, &[("login-hours", "mon 08:00-09:00")]).await;
        assert_eq!(swapped(&handler), 1, "update");
        handler.set_ou_policy("people", id).await.unwrap();
        assert_eq!(swapped(&handler), 1, "set");
        handler
            .set_ou_policy_inheritance("people", true)
            .await
            .unwrap();
        assert_eq!(swapped(&handler), 1, "block");
        handler
            .set_ou_policy_inheritance("people", true)
            .await
            .unwrap();
        assert_eq!(swapped(&handler), 0, "block again");
        handler.clear_ou_policy("people").await.unwrap();
        assert_eq!(swapped(&handler), 1, "clear");
        handler.delete_ou_policy_state("people").await.unwrap();
        assert_eq!(swapped(&handler), 1, "ou removed");
        handler.delete_ou_policy_state("people").await.unwrap();
        assert_eq!(swapped(&handler), 0, "nothing to remove");
        handler.delete_policy(id).await.unwrap();
        assert_eq!(swapped(&handler), 1, "delete");
    }

    #[tokio::test]
    #[serial]
    async fn test_the_minimum_is_the_users_ou_value_else_eight() {
        let h = doors::handler().await;
        doors::user_in(&h, "e3long", "e3ou").await;
        doors::user_in(&h, "e3east", "e3ou\\east").await;
        doors::user_in(&h, "e3plain", "e3other").await;
        doors::policy_on(&h, "e3ou", &[(PASSWORD_MIN_LENGTH_ITEM, "12")]).await;
        let mut got = Vec::new();
        for user in ["e3long", "e3east", "e3plain", "e3nobody"] {
            got.push(min_length_for_user(&h, &UserId::new(user)).await.unwrap());
        }
        h.set_ou_policy_inheritance("e3ou\\east", true)
            .await
            .unwrap();
        let blocked = min_length_for_user(&h, &UserId::new("e3east")).await;
        assert_eq!(
            (got, blocked.unwrap()),
            (vec![12, 12, 8, 8], 8),
            "the OU's 12, inherited below it; 8 elsewhere, for no user, and below a block"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_change_is_held_to_the_minimum_it_is_given_with_one_row() {
        let log = LogGuard::install_on_this_thread();
        let h = doors::handler().await;
        doors::user_in(&h, "e3change", "e3ou").await;
        let user = UserId::new("e3change");
        let plain = PasswordSync::Off;
        let _ = doors::rows(&log, &[]);
        let short = change_password_everywhere(&h, &user, "Eleven-11ch", plain, 12).await;
        let short_rows = doors::rows(&log, &[LogKind::PasswordChange]);
        let long = change_password_everywhere(&h, &user, "Twelve-12chr", plain, 12).await;
        let long_rows = doors::rows(&log, &[LogKind::PasswordChange]);
        let target = || Some("e3change".to_owned());
        assert_eq!(
            (short, short_rows),
            (
                Err(PasswordChangeError::TooShort(12)),
                vec![(
                    LogKind::PasswordChange,
                    target(),
                    Some("the password must be at least 12 characters".to_owned())
                )]
            ),
            "an 11-character password is refused with one row"
        );
        assert_eq!(
            (
                long,
                long_rows,
                doors::bind(&h, "e3change", "Twelve-12chr").await
            ),
            (
                Ok(()),
                vec![(LogKind::PasswordChange, target(), None)],
                true
            ),
            "a 12-character one is stored and binds"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_the_bytes_judged_are_the_bytes_stored() {
        const TYPED: &str = "  Cafe\u{301}-Pass-12  ";
        const TRIMMED: &str = "Cafe\u{301}-Pass-12";
        const COMPOSED: &str = "  Caf\u{e9}-Pass-12  ";
        const LOWERED: &str = "  cafe\u{301}-pass-12  ";
        let h = doors::handler().await;
        doors::user_in(&h, "e3bytes", "e3ou").await;
        let user = UserId::new("e3bytes");
        let floor = PASSWORD_MIN_LENGTH;
        let set = change_password_everywhere(&h, &user, TYPED, PasswordSync::Off, floor).await;
        let mut tried = Vec::new();
        for typed in [TYPED, TRIMMED, COMPOSED, LOWERED] {
            let web = doors::web(&h, "e3bytes", typed, None).await;
            let web = web.map(|outcome| matches!(outcome, LoginOutcome::Authenticated { .. }));
            tried.push((typed, doors::bind(&h, "e3bytes", typed).await, web));
        }
        assert_eq!(
            (set, tried),
            (
                Ok(()),
                vec![
                    (TYPED, true, Ok(true)),
                    (TRIMMED, false, Err("client")),
                    (COMPOSED, false, Err("client")),
                    (LOWERED, false, Err("client")),
                ]
            ),
            "the record is made of the bytes as typed: not trimmed, not composed, not lowered"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_password_set_before_the_minimum_rose_still_signs_in() {
        let h = doors::handler().await;
        doors::user_in(&h, "e3old", "e3ou").await;
        let user = UserId::new("e3old");
        let floor = PASSWORD_MIN_LENGTH;
        let set = change_password_everywhere(&h, &user, "Nine-99ch", PasswordSync::Off, floor);
        set.await.unwrap();
        doors::policy_on(&h, "e3ou", &[(PASSWORD_MIN_LENGTH_ITEM, "12")]).await;
        let web = doors::web(&h, "e3old", "Nine-99ch", None).await;
        assert_eq!(
            (
                "Nine-99ch".chars().count(),
                min_length_for_user(&h, &user).await.unwrap(),
                doors::bind(&h, "e3old", "Nine-99ch").await,
                matches!(web, Ok(LoginOutcome::Authenticated { .. }))
            ),
            (9, 12, true, true),
            "a 9-character password set under 8 still binds and logs in under 12"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_unreadable_minimum_refuses_the_change_never_eight() {
        let log = LogGuard::install_on_this_thread();
        let h = doors::handler().await;
        doors::user_in(&h, "e3unread", "e3bad").await;
        let id = doors::policy_on(&h, "e3bad", &[(PASSWORD_MIN_LENGTH_ITEM, "12")]).await;
        store_items(&h, id, "not json").await;
        let user = UserId::new("e3unread");
        let _ = doors::rows(&log, &[]);
        let read = min_length_for_user(&h, &user).await;
        let refused = min_length_of(&h, &user).await;
        assert_eq!(
            (
                read.is_err(),
                refused,
                doors::rows(&log, &[LogKind::PasswordChange])
            ),
            (
                true,
                Err(PasswordChangeError::PolicyUnreadable),
                vec![(
                    LogKind::PasswordChange,
                    Some("e3unread".to_owned()),
                    Some("the password policy could not be read; try again".to_owned())
                )]
            )
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_stored_minimum_that_is_not_a_number_refuses_the_change_never_eight() {
        const NAN: &str = "Internal error: `the stored password-min-length is not a number`";
        const UNREADABLE: &str = "the password policy could not be read; try again";
        type Row = (
            &'static str,
            std::result::Result<usize, &'static str>,
            std::result::Result<usize, PasswordChangeError>,
            bool,
        );
        let rows: [Row; 6] = [
            (
                "x",
                Err(NAN),
                Err(PasswordChangeError::PolicyUnreadable),
                true,
            ),
            (
                "",
                Err(NAN),
                Err(PasswordChangeError::PolicyUnreadable),
                true,
            ),
            (
                "12.5",
                Err(NAN),
                Err(PasswordChangeError::PolicyUnreadable),
                true,
            ),
            ("500", Ok(128), Ok(128), false),
            ("-1", Ok(8), Ok(8), false),
            ("12", Ok(12), Ok(12), false),
        ];
        let log = LogGuard::install_on_this_thread();
        let h = doors::handler().await;
        doors::user_in(&h, "e3nan", "e3nan").await;
        let id = doors::policy_on(&h, "e3nan", &[(PASSWORD_MIN_LENGTH_ITEM, "12")]).await;
        let user = UserId::new("e3nan");
        let mut got = Vec::new();
        for (value, ..) in rows.clone() {
            let stored = format!("{{\"{PASSWORD_MIN_LENGTH_ITEM}\":\"{value}\"}}");
            store_items(&h, id, &stored).await;
            let _ = doors::rows(&log, &[]);
            let read = min_length_for_user(&h, &user)
                .await
                .map_err(|e| e.to_string());
            let refused = min_length_of(&h, &user).await;
            let written = doors::rows(&log, &[LogKind::PasswordChange]);
            got.push((value, read, refused, written));
        }
        let want: Vec<_> = rows
            .into_iter()
            .map(|(value, read, refused, row)| {
                let written = match row {
                    true => vec![(
                        LogKind::PasswordChange,
                        Some("e3nan".to_owned()),
                        Some(UNREADABLE.to_owned()),
                    )],
                    false => Vec::new(),
                };
                (value, read.map_err(str::to_owned), refused, written)
            })
            .collect();
        assert_eq!(
            got, want,
            "a stored value that is not a number is unreadable, never 8"
        );
    }

    const FIFTEEN: &str = "Fifteen-15chars";

    type Raised = (
        usize,
        usize,
        std::result::Result<(), PasswordChangeError>,
        Vec<(LogKind, Option<String>, Option<String>)>,
    );

    async fn change_at_fifteen(log: &LogGuard, h: &SqlBackendHandler, user: &str) -> Raised {
        let user = UserId::new(user);
        let _ = doors::rows(log, &[]);
        let read = min_length_for_user(h, &user).await.unwrap();
        let min = min_length_of(h, &user).await.unwrap();
        let changed = change_password_everywhere(h, &user, FIFTEEN, PasswordSync::Off, min).await;
        (
            read,
            min,
            changed,
            doors::rows(log, &[LogKind::PasswordChange]),
        )
    }

    fn refused_at_sixteen(user: &str) -> Raised {
        let row = (
            LogKind::PasswordChange,
            Some(user.to_owned()),
            Some("the password must be at least 16 characters".to_owned()),
        );
        (16, 16, Err(PasswordChangeError::TooShort(16)), vec![row])
    }

    #[tokio::test]
    #[serial]
    async fn test_a_raised_minimum_holds_at_the_next_change_though_the_cache_holds_the_old_one() {
        let log = LogGuard::install_on_this_thread();
        let h = doors::handler().await;
        doors::user_in(&h, "e3stale", "e3ou").await;
        let with_lockout = [
            (PASSWORD_MIN_LENGTH_ITEM, "12"),
            ("lockout-threshold", "5"),
            ("lockout-duration-seconds", "0"),
        ];
        let id = doors::policy_on(&h, "e3ou", &with_lockout).await;
        let held = || held_item(h.policy_cache, "e3stale", PASSWORD_MIN_LENGTH_ITEM);
        let filled = (h.policy_cache.lockout_live(), held());
        set_items(&h, id, &[(PASSWORD_MIN_LENGTH_ITEM, "12")]).await;
        set_items(&h, id, &[(PASSWORD_MIN_LENGTH_ITEM, "16")]).await;
        let raised = change_at_fifteen(&log, &h, "e3stale").await;
        assert_eq!(
            (
                FIFTEEN.chars().count(),
                filled,
                (h.policy_cache.lockout_live(), held()),
                raised
            ),
            (
                15,
                (true, Some("12".to_owned())),
                (false, Some("12".to_owned())),
                refused_at_sixteen("e3stale")
            ),
            "filled at 12 while a threshold was live; with nothing live no fill follows the raise, \
             and the doors read 16"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_another_server_reads_a_raised_minimum_at_once_with_no_fill_between() {
        let log = LogGuard::install_on_this_thread();
        let (pool, key) = (get_initialized_db().await, generate_random_private_key());
        let h = doors::own(SqlBackendHandler::new(key.clone(), pool.clone()));
        let other = doors::own(SqlBackendHandler::new(key, pool));
        doors::user_in(&h, "e3there", "e3ou").await;
        let id = doors::policy_on(&h, "e3ou", &[(PASSWORD_MIN_LENGTH_ITEM, "12")]).await;
        fill_policy_cache(&other, other.policy_cache).await.unwrap();
        let held = || held_item(other.policy_cache, "e3there", PASSWORD_MIN_LENGTH_ITEM);
        let filled = held();
        set_items(&h, id, &[(PASSWORD_MIN_LENGTH_ITEM, "16")]).await;
        let raised = change_at_fifteen(&log, &other, "e3there").await;
        assert_eq!(
            (filled, raised, held()),
            (
                Some("12".to_owned()),
                refused_at_sixteen("e3there"),
                Some("12".to_owned())
            ),
            "the other server's cache, filled at 12, is never refilled; its doors read 16 at once"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_unreadable_policy_refuses_once_a_check_exists() {
        let log = LogGuard::install_on_this_thread();
        let handler = handler().await;
        user_in(&handler, "e0unreadable", "people").await;
        let id = policy(&handler, "Hours", &[]).await;
        handler.set_ou_policy("people", id).await.unwrap();
        store_items(&handler, id, "not json").await;
        let user = UserId::new("e0unreadable");
        let peer = "10.88.0.9";
        let unreadable = Refusal {
            item: UNREADABLE,
            door: Door::WebLogin,
            reason: None,
        };
        for (row, check, expected) in [
            ("no check", false, Ok(())),
            ("a check", true, Err(unreadable)),
        ] {
            let _guard = if check {
                EnforcementGuard::allowing(&["e0unreadable"], "login-hours")
            } else {
                EnforcementGuard::none()
            };
            let meta = RequestMeta::http(Some(peer.parse().unwrap()), None);
            let got = with_request(meta, async {
                admit(&handler, &Attempt::new(&user, Door::WebLogin)).await
            })
            .await;
            assert_eq!(got, expected, "{row}");
            let rows: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.peer.as_deref() == Some(peer) && e.kind == LogKind::Login)
                .map(|e| e.detail)
                .collect();
            let want: Vec<_> = expected
                .err()
                .map(|refusal| Some(refusal.detail()))
                .into_iter()
                .collect();
            assert_eq!(rows, want, "{row}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_the_cache_is_filled_from_the_directory_and_follows_each_write_at_once() {
        let cache = own_cache();
        let handler = handler().await.with_policy_cache(cache);
        user_in(&handler, "e0rook", "people").await;
        user_in(&handler, "e0sable", "People\\Labs").await;
        let root = policy(&handler, "Root", &[("enable-mfa", "enabled")]).await;
        let labs = policy(&handler, "Labs", &[("enable-mfa", "always")]).await;
        assert_eq!(
            cache.get().ous_of_users().len(),
            0,
            "while no OU sets an enforced item the writes fill nothing"
        );
        handler.set_ou_policy("", root).await.unwrap();
        handler.set_ou_policy("people\\labs", labs).await.unwrap();
        assert_eq!(
            cache.get().ous_of_users().len(),
            2,
            "the first OU to set enable-mfa fills the cache at once"
        );

        let _guard = EnforcementGuard::allowing(&["e0rook", "e0sable", "e0tarn"], "enable-mfa");
        fill_policy_cache(&handler, cache).await.unwrap();
        let ous: BTreeMap<_, _> = cache
            .get()
            .ous_of_users()
            .iter()
            .map(|(user, ou)| (user.as_str().to_owned(), ou.clone()))
            .collect();
        assert_eq!(
            ous,
            BTreeMap::from([
                ("e0rook".to_owned(), "people".to_owned()),
                ("e0sable".to_owned(), "people\\labs".to_owned()),
            ])
        );
        let mfa = |user| mfa_of(cache, user);
        assert_eq!(
            (mfa("e0rook"), mfa("e0sable"), mfa("e0tarn")),
            (Some("enabled".to_owned()), Some("always".to_owned()), None),
            "filled"
        );
        let rows = [
            ("a policy edit", "e0sable", Some("off")),
            ("a user created here", "e0tarn", Some("off")),
            ("an OU move", "e0rook", Some("off")),
            ("an OU's policy cleared", "e0sable", Some("enabled")),
            ("a user deleted", "e0tarn", None),
        ];
        for (row, user, expected) in rows {
            match row {
                "a policy edit" => set_items(&handler, labs, &[("enable-mfa", "off")]).await,
                "a user created here" => user_in(&handler, "e0tarn", "people\\labs").await,
                "an OU move" => move_to(&handler, "e0rook", "people\\labs").await,
                "an OU's policy cleared" => handler.clear_ou_policy("people\\labs").await.unwrap(),
                _ => handler.delete_user(&UserId::new("e0tarn")).await.unwrap(),
            }
            assert_eq!(mfa_of(cache, user).as_deref(), expected, "{row}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_edits_and_moves_under_load_never_leave_the_kdc_without_the_user() {
        let cache = own_cache();
        let handler = handler().await.with_policy_cache(cache);
        user_in(&handler, "e0wren", "people").await;
        let base = policy(&handler, "Base", &[("enable-mfa", "off")]).await;
        handler.set_ou_policy("people", base).await.unwrap();
        handler.set_ou_policy("people\\labs", base).await.unwrap();
        let _guard =
            EnforcementGuard::deciding(&["e0wren"], "enable-mfa", |value| value != "always");
        fill_policy_cache(&handler, cache).await.unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let user = UserId::new("e0wren");
                let checks = item_checks();
                let (mut asked, mut refused) = (0_u64, Vec::new());
                while !stop.load(Ordering::Relaxed) {
                    let attempt = Attempt::at_kdc(&user, Door::KerberosAs, None, 1_700_000_000);
                    if let Err(refusal) = admit_at_kdc(cache, &attempt, &checks) {
                        refused.push(refusal);
                    }
                    asked += 1;
                }
                (asked, refused)
            })
        };
        for turn in 0..50 {
            let (value, at) = match turn % 2 {
                0 => ("enabled", "people\\labs"),
                _ => ("off", "people"),
            };
            set_items(&handler, base, &[("enable-mfa", value)]).await;
            move_to(&handler, "e0wren", at).await;
        }
        stop.store(true, Ordering::Relaxed);
        let (asked, refused) = reader.join().unwrap();
        assert!(asked > 0, "the reader ran");
        assert_eq!(refused, Vec::<Refusal>::new(), "{asked} verdicts");
        assert_eq!(mfa_of(cache, "e0wren").as_deref(), Some("off"));
    }

    #[tokio::test]
    #[serial]
    async fn test_a_commit_follower_rereads_its_users_and_pokes_on_an_answer_that_may_have_landed()
    {
        let cache = own_cache();
        let handler = handler().await;
        user_in(&handler, "e0kept", "people\\labs").await;
        let _guard = EnforcementGuard::allowing(&["e0kept", "e0gone"], "enable-mfa");
        let (kept, gone) = (UserId::new("e0kept"), UserId::new("e0gone"));
        let held = || {
            let entries = cache.get();
            let ou = |user: &UserId| entries.ou_of(user).map(str::to_owned);
            (ou(&kept), ou(&gone))
        };
        let stale = || (None, Some("people".to_owned()));
        let rows = [
            (
                "refused",
                Err(CommitError::Refused("no".to_owned())),
                stale(),
                false,
            ),
            ("busy", Err(CommitError::Busy), stale(), false),
            (
                "unknown",
                Err(CommitError::Unknown("lost".to_owned())),
                stale(),
                true,
            ),
            (
                "unsettled",
                Err(CommitError::Unsettled("lost".to_owned())),
                stale(),
                true,
            ),
            (
                "committed",
                Ok(()),
                (Some("people\\labs".to_owned()), None),
                false,
            ),
        ];
        for (row, answer, expected, poke) in rows {
            cache.put_user(&gone, "people", Vec::new().into());
            follow_commit(&handler, cache, &[kept.clone(), gone.clone()], &answer).await;
            let poked = tokio::time::timeout(std::time::Duration::from_millis(20), cache.poked());
            assert_eq!((held(), poked.await.is_ok()), (expected, poke), "{row}");
        }
        let unknown = Err(CommitError::Unknown("lost".to_owned()));
        follow_commit(&handler, cache, &[UserId::new("e0other")], &unknown).await;
        let poked = tokio::time::timeout(std::time::Duration::from_millis(20), cache.poked());
        assert!(poked.await.is_err(), "a user no check judges pokes nothing");
    }

    #[tokio::test]
    #[serial]
    async fn test_a_late_delete_hook_keeps_a_user_created_again_under_its_name() {
        let cache = own_cache();
        let handler = handler().await.with_policy_cache(cache);
        let _guard = EnforcementGuard::allowing(&["e0again"], "enable-mfa");
        let user = UserId::new("e0again");
        user_in(&handler, "e0again", "people").await;
        handler.delete_user(&user).await.unwrap();
        user_in(&handler, "e0again", "people\\labs").await;
        user_written(&handler, cache, &user).await;
        let entries = cache.get();
        assert_eq!(
            entries.ou_of(&user),
            Some("people\\labs"),
            "the delete's hook, run last, re-reads and keeps the user that exists again"
        );
    }
}
