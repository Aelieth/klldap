use crate::sql_backend_handler::SqlBackendHandler;
use async_trait::async_trait;
use lldap_domain_handlers::handler::PolicyBackendHandler;
use lldap_domain_handlers::logging::{self, LogKind};
use lldap_domain_handlers::policies::{
    AttachedPolicy, CreatePolicyRequest, OuPolicyState, Policy, PolicyId, PolicyLevel,
    UpdatePolicyRequest, canonical_ou_key, ou_chain, ou_display,
};
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, OuPoliciesColumn, PoliciesColumn},
};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
    sea_query::{Expr, OnConflict},
};
use std::collections::{BTreeMap, HashMap};
use tracing::instrument;

fn encode_items(items: &BTreeMap<String, String>) -> Result<String> {
    serde_json::to_string(items)
        .map_err(|e| DomainError::InternalError(format!("serializing policy items: {e}")))
}

fn decode_items(raw: &str) -> Result<BTreeMap<String, String>> {
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

    async fn attached_by_id(&self, ids: &[i32]) -> Result<HashMap<i32, AttachedPolicy>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let mut map = HashMap::new();
        for row in model::Policies::find()
            .filter(PoliciesColumn::Id.is_in(ids.iter().copied()))
            .all(&self.sql_pool)
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
        logging::record(LogKind::PolicyChange, Some(&request.name), None);
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
        active.update(&self.sql_pool).await?;
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
        logging::record(LogKind::PolicyChange, Some(&existing.name), None);
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
        model::OuPolicies::insert(row)
            .on_conflict(
                OnConflict::column(OuPoliciesColumn::OuKey)
                    .update_column(OuPoliciesColumn::PolicyId)
                    .to_owned(),
            )
            .exec(&self.sql_pool)
            .await?;
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
        let attached = self.attached_by_id(&ids).await?;
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
        let keys = ou_chain(ou);
        let rows = model::OuPolicies::find()
            .filter(OuPoliciesColumn::OuKey.is_in(keys.clone()))
            .all(&self.sql_pool)
            .await?;
        let by_key: HashMap<_, _> = rows.into_iter().map(|r| (r.ou_key.clone(), r)).collect();
        let ids: Vec<i32> = by_key.values().filter_map(|r| r.policy_id).collect();
        let attached = self.attached_by_id(&ids).await?;
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

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn delete_ou_policy_state(&self, ou: &str) -> Result<()> {
        let ou_key = canonical_ou_key(ou);
        let result = model::OuPolicies::delete_by_id(&ou_key)
            .exec(&self.sql_pool)
            .await?;
        if result.rows_affected > 0 {
            logging::record(
                LogKind::PolicyChange,
                Some(ou_display(&ou_key)),
                Some("ou removed"),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::get_initialized_db;
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain_handlers::logging::{LogKind, RequestMeta, with_request};
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::collections::BTreeMap;

    fn items(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    async fn handler() -> SqlBackendHandler {
        SqlBackendHandler::new(generate_random_private_key(), get_initialized_db().await)
    }

    #[tokio::test]
    async fn test_policy_lifecycle() {
        let handler = handler().await;
        let id = handler
            .create_policy(CreatePolicyRequest {
                name: "Base".to_owned(),
                description: "d".to_owned(),
                items: items(&[("require-mfa", "off")]),
            })
            .await
            .unwrap();
        let got = handler.get_policy(id).await.unwrap();
        assert_eq!(got.name, "Base");
        assert_eq!(
            got.items.get("require-mfa").map(String::as_str),
            Some("off")
        );
        let listed = handler.list_policies().await.unwrap();
        assert_eq!(listed.len(), 1);

        handler
            .update_policy(UpdatePolicyRequest {
                id,
                name: Some("Base Policy".to_owned()),
                description: None,
                items: Some(items(&[("require-mfa", "always")])),
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
        let guard = LogGuard::install();
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
                (LogKind::PolicyChange, Some("Hours".into()), None),
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
                (LogKind::PolicyChange, Some("Hours".into()), None),
            ]
        );
    }
}
