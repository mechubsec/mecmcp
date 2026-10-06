//! HTTPS enforcement for every URL this CLI dereferences: `--server-url`,
//! `--oidc-issuer`, and every endpoint read back out of OIDC discovery.
//! Bearer tokens, the approver assertion, the authorization code, and any
//! OIDC client secret all travel over these connections, so plain `http`
//! would send them in cleartext. Loopback hosts are the one exception --
//! required for local IdPs and this crate's own tests -- and
//! `--allow-insecure-http` is the explicit, named escape hatch for lab use.

use crate::error::ApproveError;

const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "::1", "localhost"];

/// Require `url` to be `https`, or `http` to a loopback host, unless
/// `allow_insecure` opts out.
pub(crate) fn require_secure(
    label: &'static str,
    url: &str,
    allow_insecure: bool,
) -> Result<(), ApproveError> {
    if allow_insecure {
        return Ok(());
    }

    let insecure_url = || ApproveError::InsecureUrl {
        label,
        url: url.to_owned(),
    };

    let parsed = url::Url::parse(url).map_err(|_source| insecure_url())?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http"
            if parsed
                .host_str()
                .is_some_and(|host| LOOPBACK_HOSTS.contains(&host)) =>
        {
            Ok(())
        }
        _ => Err(insecure_url()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https() {
        assert!(require_secure("x", "https://idp.example", false).is_ok());
    }

    #[test]
    fn accepts_loopback_http() {
        assert!(require_secure("x", "http://127.0.0.1:8080/callback", false).is_ok());
        assert!(require_secure("x", "http://localhost:8080/callback", false).is_ok());
    }

    #[test]
    fn rejects_plain_http_to_a_real_host() {
        assert!(require_secure("x", "http://idp.example", false).is_err());
    }

    #[test]
    fn allow_insecure_http_opts_out() {
        assert!(require_secure("x", "http://idp.example", true).is_ok());
    }

    #[test]
    fn rejects_unparseable_urls() {
        assert!(require_secure("x", "not a url", false).is_err());
    }
}
