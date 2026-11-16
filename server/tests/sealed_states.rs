use crate::common::{
    auth::{get_token, opaque_login, register_password_over_http},
    fixture::{LLDAPFixture, User},
};
use lldap_auth::{login, opaque, registration, types::UserId};
use reqwest::blocking::{Client, ClientBuilder};
mod common;

const USER: &str = "sealbob";
const OWN: &str = "SealBobOwn2026!";
const OTHER: &str = "SealBobOther2026!";

fn client() -> Client {
    ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("http client")
}

#[test]
fn test_each_kind_of_state_opens_only_as_its_own_kind_at_the_routes() {
    let mut fixture = LLDAPFixture::new();
    fixture.load_state(&vec![User::new(USER, vec![])]);
    let client = client();
    let url = fixture.http_url();
    let admin = get_token(&client, &url);
    register_password_over_http(&client, &url, &admin, USER, OWN);

    let mut rng = rand::rngs::OsRng;
    let login = opaque::client::login::start_login("anything", &mut rng).expect("login start");
    let login_state = client
        .post(format!("{url}/auth/opaque/login/start"))
        .json(&login::ClientLoginStartRequest {
            username: UserId::new(USER),
            login_start_request: login.message,
        })
        .send()
        .expect("login start send")
        .error_for_status()
        .expect("login start status")
        .json::<login::ServerLoginStartResponse>()
        .expect("login start json")
        .server_data;

    let start = opaque::client::registration::start_registration(OTHER.as_bytes(), &mut rng)
        .expect("registration start");
    let started: registration::ServerRegistrationStartResponse = client
        .post(format!("{url}/auth/opaque/register/start"))
        .bearer_auth(&admin)
        .json(&registration::ClientRegistrationStartRequest {
            username: UserId::new(USER),
            registration_start_request: start.message,
        })
        .send()
        .expect("register start send")
        .error_for_status()
        .expect("register start status")
        .json()
        .expect("register start json");
    let upload = opaque::client::registration::finish_registration(
        start.state,
        OTHER.as_bytes(),
        started.registration_response,
        &mut rng,
    )
    .expect("registration finish")
    .message;

    let finished = client
        .post(format!("{url}/auth/opaque/register/finish"))
        .json(&registration::ClientRegistrationFinishRequest {
            server_data: login_state,
            registration_upload: upload,
        })
        .send()
        .expect("register finish send");
    assert!(
        !finished.status().is_success(),
        "register/finish answered {}",
        finished.status()
    );
    let (status, body) = opaque_login(&client, &url, USER, OWN, None);
    assert!(
        status.is_success() && body["token"].is_string(),
        "sign-in with the user's password: {status} {body}"
    );
}
