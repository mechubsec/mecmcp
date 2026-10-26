//! The canonical identifier a resource server presents as its OAuth resource
//! (RFC 8707 s2) and protected-resource metadata `resource` (RFC 9728 s2).

use url::{Host, Url};

/// The RFC 9728 well-known path for a resource with no path component.
pub const ROOT_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// Why a string is not an acceptable resource URI.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResourceUriError {
    /// Contains a non-ASCII-graphic byte, a quote, or a backslash.
    #[error("resource URI must be printable ASCII without quotes or backslashes")]
    UnsafeCharacters,
    /// Not parseable as an absolute URI.
    #[error("resource URI is not an absolute URI: {0}")]
    NotAbsolute(String),
    /// Not `https`, and not `http` to a loopback host.
    #[error("resource URI must use https (http is allowed only for a loopback host)")]
    InsecureScheme,
    /// Carries userinfo, a query, or a fragment (RFC 8707 s2).
    #[error("resource URI must not carry userinfo, a query, or a fragment")]
    ForbiddenComponent,
    /// Path contains something other than letters, digits and `. _ ~ - /`.
    #[error("resource URI path may contain only letters, digits and . _ ~ - /")]
    PathCharacters,
    /// Differs from its own normalised form; the field is the form to use.
    #[error("resource URI is not canonical; use {0:?}")]
    NotCanonical(String),
}

/// A validated, canonical resource URI. See the module docs for why each rule exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceUri {
    canonical: String,
    origin: String,
    path: String,
}

impl ResourceUri {
    /// Parse and validate `input`.
    ///
    /// # Errors
    /// Returns the first [`ResourceUriError`] that applies.
    pub fn parse(input: &str) -> Result<Self, ResourceUriError> {
        if !input.bytes().all(|byte| byte.is_ascii_graphic()) || input.contains(['"', '\\']) {
            return Err(ResourceUriError::UnsafeCharacters);
        }
        let url =
            Url::parse(input).map_err(|error| ResourceUriError::NotAbsolute(error.to_string()))?;
        if url.host().is_none() {
            return Err(ResourceUriError::NotAbsolute("no host".to_owned()));
        }
        let loopback = match url.host() {
            Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        };
        let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && loopback);
        if !scheme_ok {
            return Err(ResourceUriError::InsecureScheme);
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ResourceUriError::ForbiddenComponent);
        }
        let path_ok = url.path().bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-' | b'/')
        });
        if !path_ok {
            return Err(ResourceUriError::PathCharacters);
        }
        if url.as_str() != input {
            return Err(ResourceUriError::NotCanonical(url.as_str().to_owned()));
        }
        Ok(Self {
            canonical: input.to_owned(),
            origin: url.origin().ascii_serialization(),
            path: url.path().to_owned(),
        })
    }

    /// The exact string used as the audience and as the metadata `resource`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// The RFC 9728 s3.1 route: the well-known prefix with the resource path inserted.
    #[must_use]
    pub fn metadata_path(&self) -> String {
        if self.path == "/" {
            return ROOT_METADATA_PATH.to_owned();
        }
        format!("{ROOT_METADATA_PATH}{}", self.path)
    }

    /// The absolute URL of [`Self::metadata_path`], for the `resource_metadata` challenge parameter.
    #[must_use]
    pub fn metadata_url(&self) -> String {
        format!("{}{}", self.origin, self.metadata_path())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_resources_and_derives_rfc_9728_urls() {
        let resource = ResourceUri::parse("https://junos.lab.example/mcp").expect("valid");
        assert_eq!(resource.as_str(), "https://junos.lab.example/mcp");
        assert_eq!(
            resource.metadata_path(),
            "/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            resource.metadata_url(),
            "https://junos.lab.example/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn a_bare_origin_uses_the_root_metadata_path() {
        let resource = ResourceUri::parse("https://junos.lab.example/").expect("valid");
        assert_eq!(resource.metadata_path(), ROOT_METADATA_PATH);
    }

    #[test]
    fn a_non_default_port_is_part_of_the_origin() {
        let resource = ResourceUri::parse("https://h.example:8443/mcp").expect("valid");
        assert_eq!(
            resource.metadata_url(),
            "https://h.example:8443/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn loopback_may_use_plain_http_and_nothing_else_may() {
        assert!(ResourceUri::parse("http://127.0.0.1:8080/mcp").is_ok());
        assert!(ResourceUri::parse("http://localhost:8080/mcp").is_ok());
        assert!(ResourceUri::parse("http://[::1]:8080/mcp").is_ok());
        for bad in [
            "http://junos.lab.example/mcp",
            "http://10.0.0.5/mcp",
            "http://localhost.evil.example/mcp",
            "ftp://junos.lab.example/mcp",
        ] {
            assert_eq!(
                ResourceUri::parse(bad).unwrap_err(),
                ResourceUriError::InsecureScheme,
                "{bad}"
            );
        }
    }

    #[test]
    fn forbidden_components_are_refused() {
        for bad in [
            concat!("https://user", ":pw@h.example/mcp"),
            "https://user@h.example/mcp",
            "https://h.example/mcp?x=1",
            "https://h.example/mcp?",
            "https://h.example/mcp#frag",
        ] {
            assert_eq!(
                ResourceUri::parse(bad).unwrap_err(),
                ResourceUriError::ForbiddenComponent,
                "{bad}"
            );
        }
    }

    #[test]
    fn unsafe_characters_are_refused_before_parsing() {
        for bad in [
            "https://h.example/m cp",
            "https://h.example/mcp\r\nX-Evil: 1",
            "https://h.example/\"mcp",
            "https://h.example/m\\cp",
            "https://b\u{fc}cher.example/mcp",
        ] {
            assert_eq!(
                ResourceUri::parse(bad).unwrap_err(),
                ResourceUriError::UnsafeCharacters,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn route_metacharacters_in_the_path_are_refused() {
        for bad in [
            "https://h.example/{id}",
            "https://h.example/a/*",
            "https://h.example/a%2Fb",
            "https://h.example/a:b",
        ] {
            assert_eq!(
                ResourceUri::parse(bad).unwrap_err(),
                ResourceUriError::PathCharacters,
                "{bad}"
            );
        }
    }

    #[test]
    fn a_non_canonical_spelling_is_refused_with_the_canonical_form() {
        assert_eq!(
            ResourceUri::parse("https://H.Example/mcp").unwrap_err(),
            ResourceUriError::NotCanonical("https://h.example/mcp".to_owned())
        );
        assert_eq!(
            ResourceUri::parse("https://h.example").unwrap_err(),
            ResourceUriError::NotCanonical("https://h.example/".to_owned())
        );
        assert_eq!(
            ResourceUri::parse("https://h.example:443/mcp").unwrap_err(),
            ResourceUriError::NotCanonical("https://h.example/mcp".to_owned())
        );
    }

    #[test]
    fn a_relative_reference_is_not_absolute() {
        assert!(matches!(
            ResourceUri::parse("/mcp").unwrap_err(),
            ResourceUriError::NotAbsolute(_)
        ));
    }
}
