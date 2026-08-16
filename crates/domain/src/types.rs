use base64::Engine;
use base64::engine::general_purpose;
use bytes::Bytes;
use chrono::{NaiveDateTime, TimeZone};
use lldap_auth::types::CaseInsensitiveString;
pub use lldap_auth::types::UserId;
pub use lldap_schema::AttributeType;
use sea_orm::{
    DbErr, DeriveValueType, TryFromU64, Value,
    entity::IntoActiveValue,
    sea_query::{SeaRc, StringLen, extension::mysql::MySqlType},
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::images;
pub use crate::images::{
    AvatarError, JPEG_QUALITY, MAX_AVATAR_JPEG_SIZE, TARGET_AVATAR_SIZE, avatar_to_graphql_base64,
    process_avatar_input, validate_stored_avatar_bytes,
};

#[derive(
    PartialEq,
    Hash,
    Eq,
    Clone,
    Default,
    Serialize,
    Deserialize,
    DeriveValueType,
    derive_more::Debug,
    derive_more::Display,
)]
#[serde(try_from = "&str")]
#[sea_orm(column_type = "String(StringLen::N(36))")]
#[debug(r#""{_0}""#)]
#[display("{_0}")]
pub struct Uuid(String);

impl Uuid {
    pub fn from_name_and_date(name: &str, creation_date: &NaiveDateTime) -> Self {
        Uuid(
            uuid::Uuid::new_v3(
                &uuid::Uuid::NAMESPACE_X500,
                &[
                    name.as_bytes(),
                    chrono::Utc
                        .from_utc_datetime(creation_date)
                        .to_rfc3339()
                        .as_bytes(),
                ]
                .concat(),
            )
            .to_string(),
        )
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl<'a> std::convert::TryFrom<&'a str> for Uuid {
    type Error = anyhow::Error;
    fn try_from(s: &'a str) -> anyhow::Result<Self> {
        Ok(Uuid(uuid::Uuid::parse_str(s)?.to_string()))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, DeriveValueType)]
#[sea_orm(
    column_type = "Custom(SeaRc::new(MySqlType::LongBlob))",
    array_type = "Bytes"
)]
pub struct Serialized(pub Vec<u8>);

impl std::fmt::Debug for Serialized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            f.debug_tuple("Serialized").field(&"empty").finish()
        } else if let Ok(s) = String::from_utf8(self.0.clone()) {
            if let Ok(i) = s.parse::<i64>() {
                f.debug_tuple("Serialized").field(&i).finish()
            } else {
                f.debug_tuple("Serialized").field(&s).finish()
            }
        } else {
            f.debug_tuple("Serialized")
                .field(&format!("raw[{} bytes]", self.0.len()))
                .finish()
        }
    }
}

fn compare_str_case_insensitive(s1: &str, s2: &str) -> Ordering {
    let mut it_1 = s1.chars().flat_map(|c| c.to_lowercase());
    let mut it_2 = s2.chars().flat_map(|c| c.to_lowercase());
    loop {
        match (it_1.next(), it_2.next()) {
            (Some(c1), Some(c2)) => {
                let o = c1.cmp(&c2);
                if o != Ordering::Equal {
                    return o;
                }
            }
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

macro_rules! make_case_insensitive_comparable_string {
    ($c:ident) => {
        #[derive(
            Clone,
            Default,
            Serialize,
            Deserialize,
            DeriveValueType,
            derive_more::Debug,
            derive_more::Display,
        )]
        #[debug(r#""{_0}""#)]
        #[display("{_0}")]
        pub struct $c(String);

        impl PartialEq for $c {
            fn eq(&self, other: &Self) -> bool {
                compare_str_case_insensitive(&self.0, &other.0) == Ordering::Equal
            }
        }
        impl Eq for $c {}
        impl PartialOrd for $c {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }
        impl Ord for $c {
            fn cmp(&self, other: &Self) -> Ordering {
                compare_str_case_insensitive(&self.0, &other.0)
            }
        }
        impl std::hash::Hash for $c {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.0.to_lowercase().hash(state)
            }
        }
        impl $c {
            pub fn new(raw: &str) -> Self {
                Self(raw.to_owned())
            }
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
            pub fn into_string(self) -> String {
                self.0
            }
        }
        impl From<String> for $c {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
        impl From<&str> for $c {
            fn from(s: &str) -> Self {
                Self::new(s)
            }
        }
        impl From<&$c> for Value {
            fn from(v: &$c) -> Self {
                v.as_str().into()
            }
        }
        impl TryFromU64 for $c {
            fn try_from_u64(_n: u64) -> Result<Self, DbErr> {
                Err(DbErr::ConvertFromU64(concat!(
                    stringify!($c),
                    " cannot be constructed from u64"
                )))
            }
        }
    };
}

make_case_insensitive_comparable_string!(LdapObjectClass);
make_case_insensitive_comparable_string!(Email);
make_case_insensitive_comparable_string!(GroupName);

impl AsRef<GroupName> for GroupName {
    fn as_ref(&self) -> &GroupName {
        self
    }
}

#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Debug,
    Default,
    Hash,
    Serialize,
    Deserialize,
    DeriveValueType,
)]
#[serde(from = "CaseInsensitiveString")]
pub struct AttributeName(CaseInsensitiveString);

impl AttributeName {
    pub fn new(s: &str) -> Self {
        s.into()
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    pub fn into_string(self) -> String {
        self.0.into_string()
    }
}
impl<T> From<T> for AttributeName
where
    T: Into<CaseInsensitiveString>,
{
    fn from(s: T) -> Self {
        Self(s.into())
    }
}
impl std::fmt::Display for AttributeName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0.as_str())
    }
}
impl From<&AttributeName> for Value {
    fn from(v: &AttributeName) -> Self {
        v.as_str().into()
    }
}
impl TryFromU64 for AttributeName {
    fn try_from_u64(_n: u64) -> Result<Self, DbErr> {
        Err(DbErr::ConvertFromU64(
            "AttributeName cannot be constructed from u64",
        ))
    }
}

#[derive(PartialEq, Eq, Clone, Serialize, Deserialize, DeriveValueType, Hash)]
#[sea_orm(column_type = "Blob", array_type = "Bytes")]
pub struct Avatar(pub Vec<u8>);

impl Avatar {
    /// Converts PNG/BMP to JPEG; unprocessable input yields an empty avatar.
    pub fn new(bytes: Vec<u8>) -> Self {
        match images::process_avatar_input(&bytes) {
            Ok(jpeg) => Self(jpeg),
            Err(e) => {
                tracing::error!(
                    target: "avatar_critical",
                    "Avatar processing failed, rejecting the upload: {}",
                    e
                );
                Self(vec![])
            }
        }
    }

    pub fn from_bytes(bytes: Bytes) -> Self {
        let _ = images::validate_stored_avatar_bytes(&bytes);
        Self::new(bytes.into())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn null() -> Self {
        Self(vec![])
    }
    pub fn into_bytes(self) -> Bytes {
        Bytes::from(self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[cfg(any(feature = "test", test))]
    pub fn for_tests() -> Self {
        use image::{ImageFormat, Rgb, RgbImage};
        let img = RgbImage::from_fn(TARGET_AVATAR_SIZE, TARGET_AVATAR_SIZE, |x, y| {
            if (x + y) % 2 == 0 {
                Rgb([0, 0, 0])
            } else {
                Rgb([255, 255, 255])
            }
        });
        let mut buf = Vec::new();
        img.write_to(&mut std::io::Cursor::new(&mut buf), ImageFormat::Jpeg)
            .unwrap();
        Self::new(buf)
    }
}

impl From<&Avatar> for Value {
    fn from(photo: &Avatar) -> Self {
        photo.0.as_slice().into()
    }
}

impl TryFrom<&[u8]> for Avatar {
    type Error = anyhow::Error;
    fn try_from(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.is_empty() {
            return Ok(Self::null());
        }

        // Any bytes entering the struct are validated and processed.
        images::validate_stored_avatar_bytes(bytes).map_err(|e| anyhow::anyhow!("{}", e))?;

        let jpeg_bytes =
            images::process_avatar_input(bytes).map_err(|e| anyhow::anyhow!("{}", e))?;

        Ok(Self::new(jpeg_bytes))
    }
}

impl TryFrom<Bytes> for Avatar {
    type Error = anyhow::Error;
    fn try_from(bytes: Bytes) -> anyhow::Result<Self> {
        Self::try_from(bytes.as_ref())
    }
}

impl TryFrom<&str> for Avatar {
    type Error = anyhow::Error;
    fn try_from(string: &str) -> anyhow::Result<Self> {
        let bytes = general_purpose::STANDARD.decode(string)?;
        Self::try_from(Bytes::from(bytes))
    }
}

impl From<&Avatar> for String {
    fn from(val: &Avatar) -> Self {
        images::avatar_to_graphql_base64(&val.0)
    }
}

impl std::fmt::Debug for Avatar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut encoded = general_purpose::STANDARD.encode(&self.0);
        if encoded.len() > 100 {
            encoded.truncate(100);
            encoded.push_str(" ...");
        }
        f.debug_tuple("Avatar")
            .field(&format!("b64[{} bytes]", self.0.len()))
            .finish()
    }
}

impl Default for Avatar {
    fn default() -> Self {
        Self::null()
    }
}

impl IntoActiveValue<Avatar> for Avatar {
    fn into_active_value(self) -> sea_orm::ActiveValue<Avatar> {
        if self.is_empty() {
            sea_orm::ActiveValue::NotSet
        } else {
            sea_orm::ActiveValue::Set(self)
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Hash)]
pub enum Cardinality<T: Clone> {
    Singleton(T),
    Unbounded(Vec<T>),
}

impl<T: Clone> Cardinality<T> {
    pub fn into_vec(self) -> Vec<T> {
        match self {
            Self::Singleton(v) => vec![v],
            Self::Unbounded(l) => l,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Hash)]
pub enum AttributeValue {
    String(Cardinality<String>),
    Integer(Cardinality<i64>),
    Avatar(Cardinality<Avatar>),
    DateTime(Cardinality<NaiveDateTime>),
}

impl AttributeValue {
    pub fn get_attribute_type(&self) -> AttributeType {
        match self {
            Self::String(_) => AttributeType::String,
            Self::Integer(_) => AttributeType::Integer,
            Self::Avatar(_) => AttributeType::Avatar,
            Self::DateTime(_) => AttributeType::DateTime,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        if let AttributeValue::String(Cardinality::Singleton(s)) = self {
            Some(s.as_str())
        } else {
            None
        }
    }
    pub fn into_string(self) -> Option<String> {
        if let AttributeValue::String(Cardinality::Singleton(s)) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_avatar(&self) -> Option<&Avatar> {
        if let AttributeValue::Avatar(Cardinality::Singleton(p)) = self {
            Some(p)
        } else {
            None
        }
    }
}

impl From<String> for AttributeValue {
    fn from(s: String) -> Self {
        AttributeValue::String(Cardinality::Singleton(s))
    }
}
impl From<Vec<String>> for AttributeValue {
    fn from(l: Vec<String>) -> Self {
        AttributeValue::String(Cardinality::Unbounded(l))
    }
}
impl From<i64> for AttributeValue {
    fn from(i: i64) -> Self {
        AttributeValue::Integer(Cardinality::Singleton(i))
    }
}
impl From<Vec<i64>> for AttributeValue {
    fn from(l: Vec<i64>) -> Self {
        AttributeValue::Integer(Cardinality::Unbounded(l))
    }
}
impl From<Avatar> for AttributeValue {
    fn from(j: Avatar) -> Self {
        AttributeValue::Avatar(Cardinality::Singleton(j))
    }
}
impl From<Vec<Avatar>> for AttributeValue {
    fn from(l: Vec<Avatar>) -> Self {
        AttributeValue::Avatar(Cardinality::Unbounded(l))
    }
}
impl From<NaiveDateTime> for AttributeValue {
    fn from(dt: NaiveDateTime) -> Self {
        AttributeValue::DateTime(Cardinality::Singleton(dt))
    }
}
impl From<Vec<NaiveDateTime>> for AttributeValue {
    fn from(l: Vec<NaiveDateTime>) -> Self {
        AttributeValue::DateTime(Cardinality::Unbounded(l))
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Hash)]
pub struct Attribute {
    pub name: AttributeName,
    pub value: AttributeValue,
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: UserId,
    pub email: Email,
    pub display_name: Option<String>,
    pub creation_date: NaiveDateTime,
    pub uuid: Uuid,
    pub attributes: Vec<Attribute>,
    pub modified_date: NaiveDateTime,
    pub password_modified_date: NaiveDateTime,
    pub krb_principal_name: Option<String>,
}

impl User {
    pub fn materialize_protected_fields(&mut self) {
        if let Some(principal) = &self.krb_principal_name
            && !principal.is_empty()
        {
            self.attributes.push(Attribute {
                name: AttributeName::from("krbprincipalname"),
                value: vec![principal.clone()].into(),
            });
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub user_id: UserId,
    pub ou: String,
}

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub display_name: GroupName,
    pub creation_date: NaiveDateTime,
    pub uuid: Uuid,
    pub users: Vec<GroupMember>,
    pub attributes: Vec<Attribute>,
    pub modified_date: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupDetails {
    pub group_id: GroupId,
    pub display_name: GroupName,
    pub creation_date: NaiveDateTime,
    pub uuid: Uuid,
    pub attributes: Vec<Attribute>,
    pub modified_date: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAndGroups {
    pub user: User,
    pub groups: Option<Vec<GroupDetails>>,
}

#[cfg(feature = "test")]
impl Default for User {
    fn default() -> Self {
        let epoch = chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc();
        User {
            user_id: UserId::default(),
            email: Email::default(),
            display_name: None,
            creation_date: epoch,
            uuid: Uuid::from_name_and_date("", &epoch),
            attributes: Vec::new(),
            modified_date: epoch,
            password_modified_date: epoch,
            krb_principal_name: None,
        }
    }
}

#[derive(
    Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, DeriveValueType, derive_more::Debug,
)]
#[debug("{_0}")]
pub struct GroupId(pub i32);

impl TryFromU64 for GroupId {
    fn try_from_u64(n: u64) -> Result<Self, DbErr> {
        Ok(GroupId(i32::try_from_u64(n)?))
    }
}
impl From<&GroupId> for Value {
    fn from(id: &GroupId) -> Self {
        (*id).into()
    }
}

/// Integer(1) or the string forms "1"/"true" enable sync; aliases resolve through the schema.
pub fn kerberos_sync_enabled(attrs: &[Attribute]) -> bool {
    let schema = lldap_schema::PublicSchema::shared();
    attrs
        .iter()
        .find(|a| {
            schema.resolve_user_canonical_name(a.name.as_str()) == Some(lldap_schema::KERBEROS_SYNC)
        })
        .map(|a| match &a.value {
            AttributeValue::Integer(Cardinality::Singleton(i)) => *i == 1,
            AttributeValue::String(Cardinality::Singleton(s)) => {
                s == "1" || s.to_lowercase() == "true"
            }
            _ => false,
        })
        .unwrap_or(false)
}

/// Built-in groups whose exact names are load-bearing; never renamed or deleted.
pub const BUILTIN_GROUPS: &[&str] = &[
    "lldap_admin",
    "lldap_password_manager",
    "lldap_strict_readonly",
    "lldap_disabled",
    "lldap_sudohost",
];

pub fn is_builtin_group(name: &str) -> bool {
    BUILTIN_GROUPS
        .iter()
        .any(|builtin| builtin.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::is_builtin_group;

    #[test]
    fn test_is_builtin_group_is_case_insensitive() {
        assert!(is_builtin_group("lldap_admin"));
        assert!(is_builtin_group("LLDAP_ADMIN"));
        assert!(is_builtin_group("Lldap_Disabled"));
        assert!(!is_builtin_group("family"));
    }
}
