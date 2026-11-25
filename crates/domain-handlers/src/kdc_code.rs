use async_trait::async_trait;
use lldap_domain::types::UserId;
use std::sync::{Arc, LazyLock, PoisonError, RwLock};

pub const CODE_DIGITS: usize = 6;
pub const NO_SIX_DIGITS: &str = "no six-digit code";

/// Exactly six ASCII digits, borrowed from the KDC's request: nothing else is ever read.
pub struct KdcCode<'a>(&'a str);

impl<'a> KdcCode<'a> {
    pub fn read(value: &'a [u8]) -> Option<Self> {
        if value.len() != CODE_DIGITS || !value.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(value).ok().map(Self)
    }

    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl std::fmt::Debug for KdcCode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KdcCode(..)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeVerdict {
    Accepted,
    /// The one refusal that counts toward the lockout, as at the doors.
    Wrong,
    Refused(&'static str),
}

/// The doors' check of one code: the same attempt limit and the same used-once mark.
#[async_trait]
pub trait KdcCodeStore: Send + Sync {
    async fn check_kdc_code(&self, user: &UserId, code: KdcCode<'_>) -> CodeVerdict;
}

pub async fn check_code(store: &dyn KdcCodeStore, user: &UserId, value: &[u8]) -> CodeVerdict {
    match KdcCode::read(value) {
        Some(code) => store.check_kdc_code(user, code).await,
        None => CodeVerdict::Refused(NO_SIX_DIGITS),
    }
}

#[derive(Clone)]
pub struct CodeReader {
    pub store: Arc<dyn KdcCodeStore>,
    pub runtime: tokio::runtime::Handle,
}

#[derive(Default)]
pub struct KdcCodes {
    reader: RwLock<Option<CodeReader>>,
}

static KDC_CODES: LazyLock<KdcCodes> = LazyLock::new(KdcCodes::default);

pub fn kdc_codes() -> &'static KdcCodes {
    &KDC_CODES
}

impl KdcCodes {
    pub fn serve(&self, store: Arc<dyn KdcCodeStore>, runtime: tokio::runtime::Handle) {
        let reader = CodeReader { store, runtime };
        *self.reader.write().unwrap_or_else(PoisonError::into_inner) = Some(reader);
    }

    pub fn reader(&self) -> Option<CodeReader> {
        self.reader
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::capture::Lines;
    use pretty_assertions::assert_eq;
    use std::sync::Mutex;

    struct Asked {
        calls: Mutex<Vec<(String, String)>>,
        answer: CodeVerdict,
    }

    impl Asked {
        fn answering(answer: CodeVerdict) -> Self {
            Self {
                calls: Mutex::default(),
                answer,
            }
        }
    }

    #[async_trait]
    impl KdcCodeStore for Asked {
        async fn check_kdc_code(&self, user: &UserId, code: KdcCode<'_>) -> CodeVerdict {
            let call = (user.as_str().to_owned(), code.as_str().to_owned());
            self.calls.lock().unwrap().push(call);
            self.answer
        }
    }

    #[tokio::test]
    async fn test_only_six_ascii_digits_reach_the_store_and_nothing_else_is_logged() {
        let (lines, _guard) = Lines::capture();
        let user = UserId::new("e8kcode");
        let long = "1".repeat(128);
        let not_utf8: &[u8] = &[0xff, 0xfe, 0x31, 0x32, 0x33, 0x34];
        type Row<'a> = (&'a str, &'a [u8], Option<&'a str>);
        let rows: [Row; 15] = [
            ("six digits", b"123456", Some("123456")),
            ("leading zeros", b"000042", Some("000042")),
            ("five", b"12345", None),
            ("seven", b"1234567", None),
            ("the password and the code", b"pw:123456", None),
            ("empty", b"", None),
            ("a letter", b"12345a", None),
            ("a sign", b"+12345", None),
            ("a space", b" 12345", None),
            ("a newline after six", b"123456\n", None),
            ("full-width digits", "１２３４５６".as_bytes(), None),
            ("Arabic-Indic digits, six bytes", "١٢٣".as_bytes(), None),
            ("not UTF-8", not_utf8, None),
            ("128 digits", long.as_bytes(), None),
            ("six digits and a NUL", b"123456\0", None),
        ];
        for (label, value, reaches) in rows {
            let store = Asked::answering(CodeVerdict::Wrong);
            let verdict = check_code(&store, &user, value).await;
            let calls = store.calls.into_inner().unwrap();
            let expected = match reaches {
                Some(code) => {
                    let call = (user.as_str().to_owned(), code.to_owned());
                    (CodeVerdict::Wrong, vec![call])
                }
                None => (CodeVerdict::Refused(NO_SIX_DIGITS), vec![]),
            };
            assert_eq!(
                (verdict, calls, lines.take()),
                (expected.0, expected.1, vec![]),
                "{label}: the store's answer only for six ASCII digits; no line either way"
            );
        }
    }

    #[test]
    fn test_a_code_never_prints_its_digits() {
        let code = KdcCode::read(b"123456").unwrap();
        assert_eq!(
            (format!("{code:?}"), code.as_str()),
            ("KdcCode(..)".to_owned(), "123456")
        );
    }

    #[tokio::test]
    async fn test_the_store_is_handed_over_by_the_start() {
        let codes = KdcCodes::default();
        let before = codes.reader().is_none();
        let store = Arc::new(Asked::answering(CodeVerdict::Accepted));
        codes.serve(store, tokio::runtime::Handle::current());
        let reader = codes.reader().expect("served");
        let user = UserId::new("e8kcode");
        let verdict = check_code(&*reader.store, &user, b"654321").await;
        assert_eq!((before, verdict), (true, CodeVerdict::Accepted));
    }
}
