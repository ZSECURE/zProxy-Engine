pub mod basic;
pub mod ntlm;

#[derive(Clone, Debug)]
pub enum ProxyAuth {
    Basic { username: String, password: String },
    Ntlm { username: String, password: String, domain: String },
}

impl ProxyAuth {
    /// Returns the value of the `Proxy-Authorization` header.
    pub fn to_header_value(&self) -> String {
        match self {
            ProxyAuth::Basic { username, password } => {
                basic::encode(username, password)
            }
            ProxyAuth::Ntlm { .. } => {
                // Type 1 (negotiate) message; full auth is handled in http.rs
                ntlm::create_negotiate_header()
            }
        }
    }
}
