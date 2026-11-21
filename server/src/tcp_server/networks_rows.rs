use super::*;
use actix_web::test::{TestRequest, call_service, init_service, read_body};
use lldap_domain_handlers::logging::current_request;
use lldap_domain_handlers::networks::parse_list;
use pretty_assertions::assert_eq;

async fn seen() -> HttpResponse {
    let meta = current_request();
    HttpResponse::Ok().body(format!(
        "{:?} {:?} {:?}",
        meta.peer, meta.forwarded_for, meta.client_address
    ))
}

#[actix_web::test]
async fn test_the_request_scope_takes_the_forwarded_address_only_from_a_listed_proxy() {
    let _backend = crate::auth_service::tests::ONE_BACKEND.lock().await;
    let app = App::new()
        .wrap(from_fn(log_request_scope))
        .route("/", web::get().to(seen));
    let app = init_service(app).await;
    let peer: std::net::SocketAddr = "10.9.0.1:40000".parse().unwrap();
    let rows: [(&str, &str, &[&[u8]], &str); 7] = [
        (
            "no trusted proxy: the socket peer",
            "",
            &[b"203.0.113.9"],
            r#"Some(10.9.0.1) Some("203.0.113.9") Some(10.9.0.1)"#,
        ),
        (
            "a listed proxy: the forwarded address",
            "10.9.0.1/32",
            &[b"203.0.113.9"],
            r#"Some(10.9.0.1) Some("203.0.113.9") Some(203.0.113.9)"#,
        ),
        (
            "two header lines are one list, read from the last",
            "10.9.0.1/32",
            &[b"198.51.100.4", b"203.0.113.9, 10.9.0.1"],
            r#"Some(10.9.0.1) Some("198.51.100.4, 203.0.113.9, 10.9.0.1") Some(203.0.113.9)"#,
        ),
        (
            "an unreadable line on the way: unknown",
            "10.9.0.1/32",
            &[b"10.9.9.9", b"\xff"],
            r#"Some(10.9.0.1) Some("10.9.9.9") None"#,
        ),
        (
            "a port on the way: unknown",
            "10.9.0.1/32",
            &[b"203.0.113.9:443"],
            r#"Some(10.9.0.1) Some("203.0.113.9:443") None"#,
        ),
        (
            "a listed proxy with no header is itself the client",
            "10.9.0.1/32",
            &[],
            "Some(10.9.0.1) None Some(10.9.0.1)",
        ),
        (
            "an unlisted peer's header is ignored",
            "10.9.0.2/32",
            &[b"203.0.113.9"],
            r#"Some(10.9.0.1) Some("203.0.113.9") Some(10.9.0.1)"#,
        ),
    ];
    let mut answers = Vec::new();
    for (_, trusted, lines, _) in rows {
        policy_cache().set_trusted_proxies(parse_list(trusted).unwrap());
        let mut request = TestRequest::get().uri("/").peer_addr(peer);
        for line in lines {
            let value = header::HeaderValue::from_bytes(line).unwrap();
            request = request.append_header(("x-forwarded-for", value));
        }
        let response = call_service(&app, request.to_request()).await;
        answers.push(String::from_utf8_lossy(&read_body(response).await).into_owned());
    }
    policy_cache().set_trusted_proxies(Vec::new());
    for ((label, _, _, expected), got) in rows.into_iter().zip(answers) {
        assert_eq!(
            got, expected,
            "{label}: the row's peer and header as they came"
        );
    }
}
