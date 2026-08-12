//! Shared GraphQL query declarations used by more than one component.
//! Declaring each once avoids regenerating identical response-type modules
//! into the wasm bundle. Derives are the superset needed across consumers.

use crate::infra::schema::AttributeType;
use graphql_client::GraphQLQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_kerberos_info.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetKerberosInfo;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/sync_kerberos.graphql",
    response_derives = "Debug,Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct SyncKerberosPassword;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/list_ous.graphql",
    response_derives = "Debug, Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct ListOusQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_posix_config.graphql",
    response_derives = "Debug",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetPosixConfig;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_group_list.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    variables_derives = "Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct GetGroupList;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/add_user_to_group.graphql",
    response_derives = "Debug",
    variables_derives = "Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct AddUserToGroup;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/remove_user_from_group.graphql",
    response_derives = "Debug",
    variables_derives = "Clone",
    custom_scalars_module = "crate::infra::graphql"
)]
pub struct RemoveUserFromGroup;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_attributes_schema.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql",
    extern_enums("AttributeType")
)]
pub struct GetUserAttributesSchema;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_group_attributes_schema.graphql",
    response_derives = "Debug,Clone,PartialEq,Eq",
    custom_scalars_module = "crate::infra::graphql",
    extern_enums("AttributeType")
)]
pub struct GetGroupAttributesSchema;
