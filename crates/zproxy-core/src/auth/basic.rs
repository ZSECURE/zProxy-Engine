use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Encode credentials as an HTTP Basic auth header value.
/// Returns `"Basic <base64(username:password)>"`.
pub fn encode(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    format!("Basic {}", STANDARD.encode(credentials.as_bytes()))
}

/// Decode an HTTP Basic auth header value.
/// Accepts `"Basic <base64>"` and returns `(username, password)`.
pub fn decode(header: &str) -> Option<(String, String)> {
    let b64 = header.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let mut parts = s.splitn(2, ':');
    let username = parts.next()?.to_string();
    let password = parts.next()?.to_string();
    Some((username, password))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        let encoded = encode("user", "pass");
        assert!(encoded.starts_with("Basic "));
        let (u, p) = decode(&encoded).unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass");
    }

    #[test]
    fn test_encode_special_chars() {
        let encoded = encode("user@domain", "p@ss:word!");
        let (u, p) = decode(&encoded).unwrap();
        assert_eq!(u, "user@domain");
        assert_eq!(p, "p@ss:word!");
    }

    #[test]
    fn test_decode_invalid() {
        assert!(decode("NotBasic xxx").is_none());
        assert!(decode("Basic !@#invalid").is_none());
    }

    #[test]
    fn test_known_value() {
        // RFC 7617 example: Aladdin:open sesame -> QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        let encoded = encode("Aladdin", "open sesame");
        assert_eq!(encoded, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }
}
