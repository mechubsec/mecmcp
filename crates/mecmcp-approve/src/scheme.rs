//! HTTPS enforcement for the URLs this CLI dereferences. `--oidc-issuer` and
//! every endpoint read back out of OIDC discovery go through
//! [`require_secure`]: loopback `http` is allowed (local IdPs, this crate's
//! tests) and `--allow-insecure-http` is the named lab escape hatch.
//! `--server-url` carries the bearer token and the approver assertion and has
//! no exception at all ([`require_https_server_url`]): `mecmcp-client` is
//! https-only, so it is refused up front, before the interactive login.

use crate::error::ApproveError;

const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "::1", "localhost"];

/// Require `--server-url` to be `https` with no userinfo or fragment, the
/// same rule `mecmcp-client` enforces, so a bad value fails before login.
pub(crate) fn require_https_server_url(url: &str) -> Result<(), ApproveError> {
    let parsed = url::Url::parse(url).map_err(|_source| ApproveError::ServerUrlNotHttps)?;
    if parsed.scheme() == "https"
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.fragment().is_none()
    {
        return Ok(());
    }
    Err(ApproveError::ServerUrlNotHttps)
}

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
    fn server_url_must_be_plain_https() {
        assert!(require_https_server_url("https://mcp.example/mcp").is_ok());
        for bad in [
            "http://127.0.0.1:1/mcp",
            "http://mcp.example/mcp",
            "https://u:p@mcp.example/mcp",
            "https://mcp.example/mcp#f",
            "not a url",
        ] {
            assert!(
                matches!(
                    require_https_server_url(bad),
                    Err(ApproveError::ServerUrlNotHttps)
                ),
                "{bad}"
            );
        }
    }

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
