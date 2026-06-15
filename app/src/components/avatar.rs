use crate::infra::functional::{LoadableResult, use_graphql_call};
use crate::infra::schema::AttributeType;
use graphql_client::GraphQLQuery;
use yew::{Properties, function_component, html, virtual_dom::AttrValue};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "../schema.graphql",
    query_path = "queries/get_user_details.graphql",
    variables_derives = "Clone,PartialEq,Eq",
    response_derives = "Debug, Hash, PartialEq, Eq, Clone",
    custom_scalars_module = "crate::infra::graphql",
    extern_enums("AttributeType")
)]
pub struct GetUserDetails;

/// Converts base64 avatar data to a data URL.
/// Since the backend now always returns valid JPEG (≤512×512, ≤512KiB),
/// we simplify the logic and assume JPEG unless we detect otherwise.
fn get_avatar_data_url(base64_data: &str) -> String {
    let trimmed = base64_data.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Backend guarantee: always JPEG
    format!("data:image/jpeg;base64,{}", trimmed)
}

#[derive(Properties, PartialEq)]
pub struct Props {
    #[prop_or_default]
    pub user: Option<AttrValue>,
    #[prop_or_default]
    pub avatar_base64: Option<AttrValue>,
    #[prop_or(128)]
    pub width: i32,
    #[prop_or(128)]
    pub height: i32,
}

#[function_component(Avatar)]
pub fn avatar(props: &Props) -> Html {
    // Always call GraphQL hook if user prop present (Yew rules of hooks: hooks must be unconditional).
    // We only *use* the result for fallback if no valid direct base64 provided.
    let user_details = props.user.as_ref().map(|user_id| {
        use_graphql_call::<GetUserDetails>(get_user_details::Variables {
            id: user_id.to_string(),
        })
    });

    // Priority 1: Direct base64 (form) — takes precedence, even if user provided
    if let Some(base64) = &props.avatar_base64 {
        let src = get_avatar_data_url(base64);
        if !src.is_empty() {
            return html! {
                <img
                    src={src}
                    width={props.width.to_string()}
                    height={props.height.to_string()}
                    style="border-radius:50%; object-fit:cover; background-color:#f0f0f0;"
                    alt="User avatar"
                />
            };
        }
        // If base64 provided but invalid/empty, fall through to GraphQL (if user) or blank
    }

    // Priority 2: GraphQL fallback (banner / static readonly avatar)
    if let Some(ud) = &user_details {
        match &**ud {
            LoadableResult::Loaded(Ok(response)) => {
                if let Some(data) = &response.user.avatar {
                    let src = get_avatar_data_url(data);
                    if !src.is_empty() {
                        return html! {
                            <img
                                src={src}
                                width={props.width.to_string()}
                                height={props.height.to_string()}
                                style="border-radius:50%; object-fit:cover; background-color:#f0f0f0;"
                                alt="User avatar"
                            />
                        };
                    }
                }
                html! { <BlankAvatarDisplay width={props.width} height={props.height} /> }
            }
            _ => html! { <BlankAvatarDisplay width={props.width} height={props.height} /> },
        }
    } else {
        html! { <BlankAvatarDisplay width={props.width} height={props.height} /> }
    }
}

pub fn validate_avatar_input(bytes: &[u8]) -> anyhow::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }

    // Fast magic-byte format check (no decode needed)
    let is_jpeg = bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8;
    let is_png = bytes.len() >= 4 && bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]);
    let is_bmp = bytes.len() >= 2 && bytes.starts_with(&[0x42, 0x4D]);

    if !(is_jpeg || is_png || is_bmp) {
        anyhow::bail!("Only JPEG, PNG, or BMP images are allowed");
    }

    // Size limits (match backend leniency for BMP)
    let max_size = if is_bmp {
        2 * 1024 * 1024 // 2 MB for BMP
    } else {
        512 * 1024 // 512 KB for JPEG/PNG
    };

    if bytes.len() > max_size {
        anyhow::bail!(
            "Image must be {} or smaller (got {} bytes). {}",
            if is_bmp { "2 MB (for BMP)" } else { "512 KiB" },
            bytes.len(),
            if is_bmp {
                "BMPs are allowed larger because they will be compressed."
            } else {
                "Only JPEG/PNG up to 512 KiB."
            }
        );
    }

    Ok(())
}

// Keep your BlankAvatarDisplay as-is
#[derive(Properties, PartialEq)]
struct BlankAvatarDisplayProps {
    #[prop_or(None)]
    pub error: Option<AttrValue>,
    pub width: i32,
    pub height: i32,
}

#[function_component(BlankAvatarDisplay)]
fn blank_avatar_display(props: &BlankAvatarDisplayProps) -> Html {
    let fill = if props.error.is_some() {
        "red"
    } else {
        "currentColor"
    };
    html! {
        <svg xmlns="http://www.w3.org/2000/svg" width={props.width.to_string()} height={props.height.to_string()} fill={fill} class="bi bi-person-circle" viewBox="0 0 16 16">
            <title>{props.error.clone().unwrap_or(AttrValue::Static("Avatar"))}</title>
            <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
            <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1z"/>
        </svg>
    }
}
