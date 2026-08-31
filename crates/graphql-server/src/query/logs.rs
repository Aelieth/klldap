use crate::api::{Context, FullHandler, field_error_callback};
use anyhow::anyhow;
use chrono::{DateTime, TimeZone, Utc};
use juniper::{FieldResult, GraphQLInputObject, GraphQLObject, ID};
use lldap_domain::types::{GroupId, UserId};
use lldap_domain_handlers::handler::LogBackendHandler;
use lldap_domain_handlers::logging::{self, LOGIN_KINDS, LogCursor, LogRecord};
use lldap_opaque_handler::OpaqueHandler;
use std::str::FromStr;
use tracing::{Instrument, debug_span};

const DEFAULT_PAGE: i32 = 100;
const MAX_PAGE: i32 = 1000;

// GraphQL-facing mirrors of the logging enums. Same strum names on both sides, so the
// conversions need no per-variant match and the round-trip test catches drift.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    juniper::GraphQLEnum,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[graphql(name = "LogKind")]
#[strum(serialize_all = "snake_case")]
pub enum GraphQLLogKind {
    Bind,
    Login,
    Logout,
    TokenRefresh,
    PasswordResetRequest,
    PasswordResetComplete,
    PasswordChange,
    UserCreate,
    UserUpdate,
    UserDelete,
    GroupCreate,
    GroupUpdate,
    GroupDelete,
    MembershipAdd,
    MembershipRemove,
    SchemaChange,
    SystemConfigChange,
    PosixChange,
    KerberosSync,
    KeytabExport,
    KeycloakChange,
    AccessDenied,
    ServerStart,
    AdminBootstrap,
    LogGap,
    BindFlood,
    AccessDeniedFlood,
    MfaEnroll,
    MfaReset,
    PolicyChange,
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    juniper::GraphQLEnum,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[graphql(name = "LogProtocol")]
#[strum(serialize_all = "snake_case")]
pub enum GraphQLLogProtocol {
    Ldap,
    Http,
    Graphql,
    System,
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    juniper::GraphQLEnum,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[graphql(name = "LogDimension")]
#[strum(serialize_all = "snake_case")]
pub enum GraphQLLogDimension {
    Actor,
    Target,
    Kind,
    Protocol,
    Peer,
    Success,
    Day,
    Hour,
}

impl From<logging::LogKind> for GraphQLLogKind {
    fn from(kind: logging::LogKind) -> Self {
        Self::from_str(<&'static str>::from(kind)).expect("LogKind mirror")
    }
}

impl From<GraphQLLogKind> for logging::LogKind {
    fn from(kind: GraphQLLogKind) -> Self {
        Self::from_str(<&'static str>::from(kind)).expect("LogKind mirror")
    }
}

impl From<logging::Protocol> for GraphQLLogProtocol {
    fn from(protocol: logging::Protocol) -> Self {
        Self::from_str(<&'static str>::from(protocol)).expect("Protocol mirror")
    }
}

impl From<GraphQLLogProtocol> for logging::Protocol {
    fn from(protocol: GraphQLLogProtocol) -> Self {
        Self::from_str(<&'static str>::from(protocol)).expect("Protocol mirror")
    }
}

impl From<logging::LogDimension> for GraphQLLogDimension {
    fn from(dimension: logging::LogDimension) -> Self {
        Self::from_str(<&'static str>::from(dimension)).expect("LogDimension mirror")
    }
}

impl From<GraphQLLogDimension> for logging::LogDimension {
    fn from(dimension: GraphQLLogDimension) -> Self {
        Self::from_str(<&'static str>::from(dimension)).expect("LogDimension mirror")
    }
}

#[derive(PartialEq, Eq, Debug, GraphQLObject)]
pub struct LogEntry {
    id: ID,
    timestamp: DateTime<Utc>,
    kind: GraphQLLogKind,
    success: bool,
    protocol: GraphQLLogProtocol,
    actor: Option<String>,
    target: Option<String>,
    peer: Option<String>,
    forwarded_for: Option<String>,
    detail: Option<String>,
}

impl From<LogRecord> for LogEntry {
    fn from(record: LogRecord) -> Self {
        let event = record.event;
        Self {
            id: ID::new(record.id.to_string()),
            timestamp: Utc.from_utc_datetime(&event.timestamp),
            kind: event.kind.into(),
            success: event.success,
            protocol: event.protocol.into(),
            actor: event.actor,
            target: event.target,
            peer: event.peer,
            forwarded_for: event.forwarded_for,
            detail: event.detail,
        }
    }
}

/// One row of `logSummary`: only the grouped dimensions are set (`day` is `YYYY-MM-DD`,
/// `hour` 0-23, both UTC).
#[derive(PartialEq, Eq, Debug, GraphQLObject)]
pub struct LogBucket {
    actor: Option<String>,
    target: Option<String>,
    kind: Option<GraphQLLogKind>,
    protocol: Option<GraphQLLogProtocol>,
    peer: Option<String>,
    success: Option<bool>,
    day: Option<String>,
    hour: Option<i32>,
    count: i32,
    first: DateTime<Utc>,
    last: DateTime<Utc>,
}

impl From<logging::LogBucket> for LogBucket {
    fn from(bucket: logging::LogBucket) -> Self {
        Self {
            actor: bucket.actor,
            target: bucket.target,
            kind: bucket.kind.map(Into::into),
            protocol: bucket.protocol.map(Into::into),
            peer: bucket.peer,
            success: bucket.success,
            day: bucket.day,
            hour: bucket.hour.and_then(|h| i32::try_from(h).ok()),
            count: i32::try_from(bucket.count).unwrap_or(i32::MAX),
            first: Utc.from_utc_datetime(&bucket.first),
            last: Utc.from_utc_datetime(&bucket.last),
        }
    }
}

/// `failuresSinceLastSuccess` counts the failures recorded after `lastSuccess` (all of
/// them when there is none), within `since` when given.
#[derive(PartialEq, Eq, Debug, GraphQLObject)]
pub struct LogActivity {
    actor: String,
    last_success: Option<LogEntry>,
    last_failure: Option<LogEntry>,
    failures_since_last_success: i32,
}

impl From<logging::LogActivity> for LogActivity {
    fn from(activity: logging::LogActivity) -> Self {
        Self {
            actor: activity.actor.into_string(),
            last_success: activity.last_success.map(Into::into),
            last_failure: activity.last_failure.map(Into::into),
            failures_since_last_success: i32::try_from(activity.failures_since_last_success)
                .unwrap_or(i32::MAX),
        }
    }
}

/// Every field narrows the result; `since`/`until` are inclusive, `kinds` empty means any,
/// `memberOf`/`memberOfId` keep the events of the current members of a group.
#[derive(PartialEq, Eq, Debug, Default, GraphQLInputObject)]
#[graphql(name = "LogFilter")]
pub struct LogFilterInput {
    actor: Option<String>,
    target: Option<String>,
    kinds: Option<Vec<GraphQLLogKind>>,
    success: Option<bool>,
    protocol: Option<GraphQLLogProtocol>,
    peer: Option<String>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    member_of: Option<String>,
    member_of_id: Option<i32>,
}

impl From<LogFilterInput> for logging::LogFilter {
    fn from(filter: LogFilterInput) -> Self {
        Self {
            actor: filter.actor.as_deref().map(UserId::new),
            target: filter.target,
            kinds: filter
                .kinds
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect(),
            success: filter.success,
            protocol: filter.protocol.map(Into::into),
            peer: filter.peer,
            since: filter.since.map(|t| t.naive_utc()),
            until: filter.until.map(|t| t.naive_utc()),
            member_of: filter.member_of,
            member_of_id: filter.member_of_id.map(GroupId),
        }
    }
}

fn parse_id(id: Option<ID>) -> FieldResult<Option<i64>> {
    id.map(|id| {
        id.parse::<i64>()
            .map_err(|_| format!("Invalid log id: {}", &*id).into())
    })
    .transpose()
}

fn page_size(limit: Option<i32>) -> u32 {
    limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE) as u32
}

pub(super) async fn list_logs<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    filter: Option<LogFilterInput>,
    limit: Option<i32>,
    before_id: Option<ID>,
    after_id: Option<ID>,
) -> FieldResult<Vec<LogEntry>> {
    let span = debug_span!("[GraphQL query] logs");
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized to read the logs"))?;
    let cursor = match (parse_id(before_id)?, parse_id(after_id)?) {
        (None, None) => LogCursor::Newest,
        (Some(id), None) => LogCursor::Before(id),
        (None, Some(id)) => LogCursor::After(id),
        (Some(_), Some(_)) => return Err("logs takes either beforeId or afterId".into()),
    };
    let records = handler
        .list_log_events(
            filter.map(Into::into).unwrap_or_default(),
            page_size(limit),
            cursor,
        )
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to load the logs: {e}"))?;
    Ok(records.into_iter().map(LogEntry::from).collect())
}

pub(super) async fn log_summary<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    filter: Option<LogFilterInput>,
    group_by: Option<Vec<GraphQLLogDimension>>,
    limit: Option<i32>,
) -> FieldResult<Vec<LogBucket>> {
    let span = debug_span!("[GraphQL query] logSummary");
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized to read the logs"))?;
    let buckets = handler
        .summarize_log_events(
            filter.map(Into::into).unwrap_or_default(),
            group_by
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect(),
            page_size(limit),
        )
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to summarize the logs: {e}"))?;
    Ok(buckets.into_iter().map(LogBucket::from).collect())
}

pub(super) async fn log_activity<Handler: FullHandler + OpaqueHandler>(
    context: &Context<Handler>,
    actor: String,
    kinds: Option<Vec<GraphQLLogKind>>,
    since: Option<DateTime<Utc>>,
) -> FieldResult<LogActivity> {
    let span = debug_span!("[GraphQL query] logActivity");
    let handler = context
        .get_admin_handler()
        .ok_or_else(field_error_callback(&span, "Unauthorized to read the logs"))?;
    let kinds = kinds.map_or_else(
        || LOGIN_KINDS.to_vec(),
        |kinds| kinds.into_iter().map(Into::into).collect(),
    );
    let activity = handler
        .log_activity(&UserId::new(&actor), kinds, since.map(|t| t.naive_utc()))
        .instrument(span)
        .await
        .map_err(|e| anyhow!("Failed to load the log activity: {e}"))?;
    Ok(activity.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use strum::IntoEnumIterator;

    #[test]
    fn test_log_enum_mirrors_round_trip() {
        for kind in logging::LogKind::iter() {
            assert_eq!(logging::LogKind::from(GraphQLLogKind::from(kind)), kind);
        }
        assert_eq!(
            GraphQLLogKind::iter().count(),
            logging::LogKind::iter().count()
        );
        for protocol in logging::Protocol::iter() {
            assert_eq!(
                logging::Protocol::from(GraphQLLogProtocol::from(protocol)),
                protocol
            );
        }
        assert_eq!(
            GraphQLLogProtocol::iter().count(),
            logging::Protocol::iter().count()
        );
        for dimension in logging::LogDimension::iter() {
            assert_eq!(
                logging::LogDimension::from(GraphQLLogDimension::from(dimension)),
                dimension
            );
        }
        assert_eq!(
            GraphQLLogDimension::iter().count(),
            logging::LogDimension::iter().count()
        );
    }
}
