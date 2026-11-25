use crate::enforcement::UserFacts;
use crate::inactivity::Recorded;
use crate::instant::Timestamp;
use crate::kdc_proof::ProofWindow;
use crate::logging::{
    LogActivity, LogBucket, LogCursor, LogDimension, LogFilter, LogKind, LogRecord,
};
use crate::mfa::{MfaPolicy, MfaRequirement, MfaResetReason};
use crate::policies::{
    CreatePolicyRequest, OuPolicyState, Policy, PolicyId, PolicyLevel, UpdatePolicyRequest,
    canonical_ou_key,
};
use async_trait::async_trait;
use ldap3_proto::proto::LdapSubstringFilter;
use lldap_domain::{
    requests::{
        CreateAttributeRequest, CreateGroupRequest, CreateUserRequest, UpdateGroupRequest,
        UpdateUserRequest,
    },
    types::{
        AttributeName, AttributeValue, Group, GroupDetails, GroupId, GroupName, LdapObjectClass,
        TotpEnrollmentStart, User, UserAndGroups, UserId, Uuid, user_ou,
    },
};
use lldap_domain_model::{error::Result, model::UserColumn};
use lldap_schema::PublicSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct BindRequest {
    pub name: UserId,
    pub password: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct SubStringFilter {
    pub initial: Option<String>,
    pub any: Vec<String>,
    pub final_: Option<String>,
}

impl SubStringFilter {
    pub fn to_sql_filter(&self) -> String {
        let mut filter = String::with_capacity(
            self.initial.as_ref().map(String::len).unwrap_or_default()
                + 1
                + self.any.iter().map(String::len).sum::<usize>()
                + self.any.len()
                + self.final_.as_ref().map(String::len).unwrap_or_default(),
        );
        if let Some(f) = &self.initial {
            filter.push_str(&f.to_ascii_lowercase());
        }
        filter.push('%');
        for part in self.any.iter() {
            filter.push_str(&part.to_ascii_lowercase());
            filter.push('%');
        }
        if let Some(f) = &self.final_ {
            filter.push_str(&f.to_ascii_lowercase());
        }
        filter
    }
}

impl From<LdapSubstringFilter> for SubStringFilter {
    fn from(
        LdapSubstringFilter {
            initial,
            any,
            final_,
        }: LdapSubstringFilter,
    ) -> Self {
        Self {
            initial,
            any,
            final_,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub enum UserRequestFilter {
    True,
    False,
    And(Vec<UserRequestFilter>),
    Or(Vec<UserRequestFilter>),
    Not(Box<UserRequestFilter>),
    UserId(UserId),
    UserIdSubString(SubStringFilter),
    Equality(UserColumn, String),
    AttributeEquality(AttributeName, AttributeValue),
    SubString(UserColumn, SubStringFilter),
    MemberOf(GroupName),
    MemberOfId(GroupId),
    CustomAttributePresent(AttributeName),
    GreaterOrEqual(UserColumn, String),
    LessOrEqual(UserColumn, String),
    AttributeGreaterOrEqual(AttributeName, String),
    AttributeLessOrEqual(AttributeName, String),
    // Lets clients that filter by DN under admin searches (Keycloak among them) work.
    AttributeSubString(AttributeName, SubStringFilter),
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub enum GroupRequestFilter {
    True,
    False,
    And(Vec<GroupRequestFilter>),
    Or(Vec<GroupRequestFilter>),
    Not(Box<GroupRequestFilter>),
    DisplayName(GroupName),
    DisplayNameSubString(SubStringFilter),
    Uuid(Uuid),
    GroupId(GroupId),
    Member(UserId),
    AttributeEquality(AttributeName, AttributeValue),
    CustomAttributePresent(AttributeName),
    GreaterOrEqual(String, String),
    LessOrEqual(String, String),
    AttributeGreaterOrEqual(AttributeName, String),
    AttributeLessOrEqual(AttributeName, String),
    AttributeSubString(AttributeName, SubStringFilter),
}

impl From<bool> for GroupRequestFilter {
    fn from(val: bool) -> Self {
        if val { Self::True } else { Self::False }
    }
}

#[async_trait]
pub trait LoginHandler: Send + Sync {
    async fn bind(&self, request: BindRequest) -> Result<()>;
}

#[async_trait]
pub trait GroupListerBackendHandler: ReadSchemaBackendHandler {
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>>;
}

#[async_trait]
pub trait GroupBackendHandler: ReadSchemaBackendHandler {
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails>;
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
    async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId>;
    async fn delete_group(&self, group_id: GroupId) -> Result<()>;
}

/// What a fill of the policy cache reads of one user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedUser {
    pub user_id: UserId,
    pub ou_key: String,
    pub facts: UserFacts,
}

impl ListedUser {
    pub fn of<'a>(user: &User, groups: impl Iterator<Item = &'a GroupDetails>) -> Self {
        Self {
            user_id: user.user_id.clone(),
            ou_key: canonical_ou_key(&user_ou(&user.attributes)),
            facts: UserFacts::of(user, groups),
        }
    }
}

#[async_trait]
pub trait UserListerBackendHandler: ReadSchemaBackendHandler {
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>>;

    /// In user-id order; a page shorter than `limit` is the last. Without paging: all, per page.
    async fn list_users_after(
        &self,
        after: Option<&UserId>,
        limit: usize,
    ) -> Result<Vec<ListedUser>> {
        let mut users = self.list_users(None, true).await?;
        users.sort_by_key(|entry| entry.user.user_id.clone());
        let later = |entry: &UserAndGroups| after.is_none_or(|after| entry.user.user_id > *after);
        let page = users.iter().filter(|entry| later(entry)).take(limit);
        let listed =
            |entry: &UserAndGroups| ListedUser::of(&entry.user, entry.groups.iter().flatten());
        Ok(page.map(listed).collect())
    }
}

#[async_trait]
pub trait UserBackendHandler: ReadSchemaBackendHandler {
    async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
    async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
    async fn delete_user(&self, user_id: &UserId) -> Result<()>;
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>>;
    async fn ensure_kerberos_principal_consistency(
        &self,
        user_id: &UserId,
        enabled: bool,
    ) -> Result<()>;
}

#[async_trait]
pub trait ReadSchemaBackendHandler {
    async fn get_schema(&self) -> Result<PublicSchema>;
}

#[async_trait]
pub trait SchemaBackendHandler: ReadSchemaBackendHandler {
    async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<()>;
    async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<()>;
    async fn delete_user_attribute(&self, name: &AttributeName) -> Result<()>;
    async fn delete_group_attribute(&self, name: &AttributeName) -> Result<()>;

    async fn add_user_object_class(&self, name: &LdapObjectClass) -> Result<()>;
    async fn add_group_object_class(&self, name: &LdapObjectClass) -> Result<()>;
    async fn delete_user_object_class(&self, name: &LdapObjectClass) -> Result<()>;
    async fn delete_group_object_class(&self, name: &LdapObjectClass) -> Result<()>;
}

#[async_trait]
pub trait SystemConfigBackendHandler: Send + Sync {
    async fn get_allowed_ous(&self) -> Result<Vec<String>>;
    async fn set_system_config(&self, key: &str, value: String) -> Result<()>;
}

#[async_trait]
pub trait LogBackendHandler: Send + Sync {
    async fn list_log_events(
        &self,
        filter: LogFilter,
        limit: u32,
        cursor: LogCursor,
    ) -> Result<Vec<LogRecord>>;
    /// One bucket per distinct `group_by` combination, most frequent then newest; none: one total.
    async fn summarize_log_events(
        &self,
        filter: LogFilter,
        group_by: Vec<LogDimension>,
        limit: u32,
    ) -> Result<Vec<LogBucket>>;
    /// Last success and failure among `kinds` (bounded by `since`), and the failures after it.
    async fn log_activity(
        &self,
        actor: &UserId,
        kinds: Vec<LogKind>,
        since: Option<Timestamp>,
    ) -> Result<LogActivity>;
}

#[async_trait]
pub trait MfaBackendHandler: Send + Sync {
    /// What a login must present under the user's resolved `enable_mfa`.
    async fn mfa_requirement(&self, user_id: &UserId) -> Result<MfaRequirement>;
    /// Whether a session is confined to reading itself and enrolling.
    async fn enrollment_pending(&self, user_id: &UserId) -> Result<bool>;
    /// The user's resolved `enable_mfa`: the explicit server-wide value, else the OU's.
    async fn mfa_mode(&self, user_id: &UserId) -> Result<MfaPolicy>;
    async fn start_totp_enrollment(
        &self,
        user_id: &UserId,
        current_code: Option<String>,
        enrollment_proof: Option<String>,
    ) -> Result<TotpEnrollmentStart>;
    /// Seals a first-enrollment proof. `None` when the user already has a factor.
    async fn seal_enrollment_proof(&self, user_id: &UserId) -> Result<Option<String>>;
    async fn finish_totp_enrollment(&self, user_id: &UserId, state: &str, code: &str)
    -> Result<()>;
    async fn reset_user_mfa(&self, user_id: &UserId, reason: MfaResetReason) -> Result<()>;
    async fn reset_own_mfa(&self, user_id: &UserId, code: &str) -> Result<()>;
}

#[async_trait]
pub trait PolicyBackendHandler: Send + Sync {
    async fn list_policies(&self) -> Result<Vec<Policy>>;
    async fn get_policy(&self, policy_id: PolicyId) -> Result<Policy>;
    async fn create_policy(&self, request: CreatePolicyRequest) -> Result<PolicyId>;
    async fn update_policy(&self, request: UpdatePolicyRequest) -> Result<()>;
    async fn delete_policy(&self, policy_id: PolicyId) -> Result<()>;
    async fn set_ou_policy(&self, ou: &str, policy_id: PolicyId) -> Result<()>;
    async fn clear_ou_policy(&self, ou: &str) -> Result<()>;
    async fn set_ou_policy_inheritance(&self, ou: &str, blocked: bool) -> Result<()>;
    async fn list_ou_policy_states(&self) -> Result<Vec<OuPolicyState>>;
    /// Root-first levels for `ou`, including keys with no row. Enforcement consumes this.
    async fn get_policy_levels(&self, ou: &str) -> Result<Vec<PolicyLevel>>;
    async fn delete_ou_policy_state(&self, ou: &str) -> Result<()>;
    /// The user and the levels of the user's OU, in one read the database bounds.
    async fn bounded_policy_entry(&self, user: &UserId) -> Result<(User, Vec<PolicyLevel>)>;
    /// The levels of `ou`, in one read the database bounds.
    async fn bounded_policy_levels(&self, ou: &str) -> Result<Vec<PolicyLevel>>;
    /// Kerberos's windows opened by a second factor, the user's or everyone's.
    async fn read_proof_windows(
        &self,
        _user: Option<&UserId>,
    ) -> Result<Vec<(UserId, ProofWindow)>> {
        Ok(Vec::new())
    }
    /// inactivity-days' rows, the user's or everyone's.
    async fn read_activity(&self, _user: Option<&UserId>) -> Result<Vec<(UserId, Recorded)>> {
        Ok(Vec::new())
    }
    /// Everyone's windows in the order of their key: the user, the address, the opening. A page
    /// shorter than `limit` is the last. Without paging: all, per page.
    async fn read_proof_windows_after(
        &self,
        after: Option<&(UserId, ProofWindow)>,
        limit: usize,
    ) -> Result<Vec<(UserId, ProofWindow)>> {
        let key = |(user, window): &(UserId, ProofWindow)| {
            (user.clone(), window.peer.clone(), window.opened_at)
        };
        let mut rows = self.read_proof_windows(None).await?;
        rows.sort_by_cached_key(key);
        let after = after.map(key);
        let later =
            |row: &(UserId, ProofWindow)| after.as_ref().is_none_or(|after| key(row) > *after);
        Ok(rows.into_iter().filter(later).take(limit).collect())
    }
    /// Everyone's inactivity-days rows in user-id order; a page shorter than `limit` is the last.
    /// Without paging: all, per page.
    async fn read_activity_after(
        &self,
        after: Option<&UserId>,
        limit: usize,
    ) -> Result<Vec<(UserId, Recorded)>> {
        let mut rows = self.read_activity(None).await?;
        rows.sort_by_key(|(user, _)| user.clone());
        let later = |(user, _): &(UserId, Recorded)| after.is_none_or(|after| user > after);
        Ok(rows.into_iter().filter(later).take(limit).collect())
    }
    /// `bounded_policy_entry` with the user's activity row, in the same bounded read.
    async fn bounded_activity_entry(
        &self,
        user: &UserId,
    ) -> Result<(User, Vec<PolicyLevel>, Recorded)> {
        let (details, levels) = self.bounded_policy_entry(user).await?;
        Ok((details, levels, Recorded::default()))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignInState {
    pub locked: bool,
    pub locked_until: Option<Timestamp>,
    pub inactive_since: Option<Timestamp>,
}

#[async_trait]
pub trait LockoutBackendHandler: Send + Sync {
    /// Clears the user's count; the next failure counts from 1. Unknown users are an error.
    async fn unlock_user(&self, user_id: &UserId) -> Result<()>;
    /// Restarts the user's inactivity count now. Unknown users are an error.
    async fn reenable_user(&self, user_id: &UserId) -> Result<()>;
    /// The lock and inactivity as the doors judge them now; an error when either is unread.
    async fn sign_in_state(&self, user_id: &UserId) -> Result<SignInState>;
    /// A sign-in at a door outside the handler, kept for inactivity-days.
    async fn note_sign_in(&self, _user_id: &UserId) {}
}

#[async_trait]
pub trait BackendHandler:
    Send
    + Sync
    + GroupBackendHandler
    + UserBackendHandler
    + UserListerBackendHandler
    + GroupListerBackendHandler
    + ReadSchemaBackendHandler
    + SchemaBackendHandler
    + SystemConfigBackendHandler
    + PosixBackendHandler
    + LogBackendHandler
    + MfaBackendHandler
    + PolicyBackendHandler
    + LockoutBackendHandler
{
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PosixSettings {
    pub user_uidnumber_assign: bool,
    pub user_uidnumber_start: i64,
    pub user_uidnumber_max: i64,

    pub user_gidnumber_assign: bool,
    pub user_gidnumber_start: i64,

    pub user_loginshell_assign: bool,
    pub user_loginshell_default: String,

    pub user_homedirectory_assign: bool,
    pub user_homedirectory_prefix: String,

    pub group_gidnumber_assign: bool,
    pub group_gidnumber_start: i64,
    pub group_gidnumber_max: i64,
}

#[async_trait]
pub trait PosixBackendHandler: Send + Sync {
    async fn get_posix_settings(&self) -> Result<PosixSettings>;
    async fn set_posix_settings(&self, settings: PosixSettings) -> Result<()>;
    async fn reassign_gid_numbers(&self) -> Result<()>;
    async fn reassign_user_uid_numbers(&self) -> Result<()>;
    async fn reassign_user_gid_numbers(&self) -> Result<()>;
    async fn reassign_user_homedirectories(&self) -> Result<()>;
    async fn reassign_user_loginshells(&self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_ne;

    #[test]
    fn test_uuid_time() {
        use chrono::prelude::*;
        let user_id = "bob";
        let date1 = Utc
            .with_ymd_and_hms(2014, 7, 8, 9, 10, 11)
            .unwrap()
            .naive_utc();
        let date2 = Utc
            .with_ymd_and_hms(2014, 7, 8, 9, 10, 12)
            .unwrap()
            .naive_utc();
        assert_ne!(
            Uuid::from_name_and_date(user_id, &date1),
            Uuid::from_name_and_date(user_id, &date2)
        );
    }
}
