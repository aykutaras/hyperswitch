//! A white-label organisation's own domain, and the hosts under it: the
//! dashboard its users' email links open (`app.`), the host its payment links
//! are served on (`pay.`), its API (`api.`) and its checkout SDK (`sdk.`).

use std::{collections::HashMap, str::FromStr};

use serde::{Deserialize, Deserializer};

use crate::id_type;

/// Each white-label organisation's own domain, by organisation.
///
/// Configured as one string, so that it can come from a single environment
/// variable: space-separated entries of `<org_id>:<domain>`, such as
/// `org_abc:engine.example.com`. The organisation's hosts are `app.`, `pay.`,
/// `api.` and `sdk.` in front of its domain. Organisations not listed use the
/// platform's own hosts. Only the deployment sets it, never a user, because
/// email links carry one-time tokens.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrganizationHosts(HashMap<id_type::OrganizationId, String>);

impl OrganizationHosts {
    /// The organisation's dashboard as a base URL, if it has one of its own.
    pub fn dashboard_url(&self, org_id: &id_type::OrganizationId) -> Option<String> {
        self.0
            .get(org_id)
            .map(|domain| format!("https://app.{domain}"))
    }

    /// The organisation's payment link host as a base URL, if it has one of its own.
    pub fn payment_link_url(&self, org_id: &id_type::OrganizationId) -> Option<String> {
        self.0
            .get(org_id)
            .map(|domain| format!("https://pay.{domain}"))
    }

    /// The API base URL of the brand whose API or payment link host a request
    /// arrived on, given the request's `Host` header (its port and case are
    /// ignored). `None` for any other host, the platform's included.
    pub fn api_url_for_host(&self, host: &str) -> Option<String> {
        let name = host
            .split(':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let domain = name
            .strip_prefix("api.")
            .or_else(|| name.strip_prefix("pay."))?;
        self.is_listed(domain)
            .then(|| format!("https://api.{domain}"))
    }

    /// `sdk_url` moved onto the SDK host of the brand whose API base URL is
    /// `api_url`, keeping its path. `None` when `api_url` is not a brand's.
    pub fn sdk_url_for_api_url(&self, api_url: &str, sdk_url: &url::Url) -> Option<url::Url> {
        let domain = api_url.strip_prefix("https://api.")?;
        if !self.is_listed(domain) {
            return None;
        }
        let mut brand_sdk_url = sdk_url.clone();
        brand_sdk_url
            .set_host(Some(&format!("sdk.{domain}")))
            .ok()?;
        Some(brand_sdk_url)
    }

    /// Whether no organisation has hosts of its own.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn is_listed(&self, domain: &str) -> bool {
        self.0.values().any(|listed| listed == domain)
    }
}

/// A host name as the setting takes it: lowercase labels, at least two, no
/// scheme, port or path.
fn is_host_name(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

impl FromStr for OrganizationHosts {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut domains = HashMap::new();
        for entry in value.split_whitespace() {
            let Some((org_id, domain)) = entry.split_once(':') else {
                return Err(format!("`{entry}` is not <org_id>:<domain>"));
            };
            let org_id = id_type::OrganizationId::try_from_string(org_id.to_owned())
                .map_err(|_| format!("`{org_id}` in `{entry}` is not an organisation id"))?;
            if !is_host_name(domain) {
                return Err(format!(
                    "`{domain}` in `{entry}` is not a domain (no scheme, port or path)"
                ));
            }
            if domains.values().any(|listed: &String| listed == domain) {
                return Err(format!("`{domain}` is listed twice"));
            }
            if domains.insert(org_id.clone(), domain.to_owned()).is_some() {
                return Err(format!("`{}` is listed twice", org_id.get_string_repr()));
            }
        }
        Ok(Self(domains))
    }
}

impl<'de> Deserialize<'de> for OrganizationHosts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org(id: &str) -> id_type::OrganizationId {
        id_type::OrganizationId::try_from_string(id.to_owned()).expect("a valid id")
    }

    fn brand() -> OrganizationHosts {
        "org_brand:checkout.brand.example".parse().expect("parses")
    }

    fn platform_sdk_url() -> url::Url {
        url::Url::parse("https://sdk.platform.example/web/0.134.0/v1/HyperLoader.js")
            .expect("a valid url")
    }

    #[test]
    fn an_empty_setting_has_no_organisations() {
        let hosts: OrganizationHosts = "".parse().expect("parses");
        assert!(hosts.is_empty());
    }

    #[test]
    fn a_listed_organisation_has_its_own_dashboard_and_payment_link_urls() {
        let hosts = brand();
        assert_eq!(
            (
                hosts.dashboard_url(&org("org_brand")),
                hosts.payment_link_url(&org("org_brand"))
            ),
            (
                Some("https://app.checkout.brand.example".to_owned()),
                Some("https://pay.checkout.brand.example".to_owned())
            )
        );
    }

    #[test]
    fn an_organisation_not_listed_has_none() {
        assert_eq!(brand().dashboard_url(&org("org_other")), None);
    }

    #[test]
    fn a_request_on_a_brands_api_host_gets_the_brands_api() {
        assert_eq!(
            brand().api_url_for_host("api.checkout.brand.example"),
            Some("https://api.checkout.brand.example".to_owned())
        );
    }

    #[test]
    fn a_request_on_a_brands_payment_link_host_gets_the_brands_api() {
        assert_eq!(
            brand().api_url_for_host("pay.checkout.brand.example"),
            Some("https://api.checkout.brand.example".to_owned())
        );
    }

    #[test]
    fn a_hosts_port_and_case_are_ignored() {
        assert_eq!(
            brand().api_url_for_host("API.Checkout.Brand.Example:443"),
            Some("https://api.checkout.brand.example".to_owned())
        );
    }

    #[test]
    fn a_brands_other_hosts_keep_the_platforms_api() {
        let hosts = brand();
        assert_eq!(
            (
                hosts.api_url_for_host("app.checkout.brand.example"),
                hosts.api_url_for_host("sdk.checkout.brand.example")
            ),
            (None, None)
        );
    }

    #[test]
    fn a_host_not_listed_keeps_the_platforms_api() {
        let hosts = brand();
        assert_eq!(
            (
                hosts.api_url_for_host("api.platform.example"),
                hosts.api_url_for_host("api.brand.example"),
                hosts.api_url_for_host("api.x.checkout.brand.example"),
                hosts.api_url_for_host("")
            ),
            (None, None, None, None)
        );
    }

    #[test]
    fn a_brands_api_gets_the_sdk_on_the_brands_sdk_host() {
        assert_eq!(
            brand()
                .sdk_url_for_api_url("https://api.checkout.brand.example", &platform_sdk_url())
                .map(|url| url.to_string()),
            Some("https://sdk.checkout.brand.example/web/0.134.0/v1/HyperLoader.js".to_owned())
        );
    }

    #[test]
    fn the_platforms_api_keeps_the_platforms_sdk() {
        assert_eq!(
            brand().sdk_url_for_api_url("https://api.platform.example", &platform_sdk_url()),
            None
        );
    }

    #[test]
    fn entries_are_separated_by_any_whitespace() {
        let hosts: OrganizationHosts = "  org_a:a.com \n org_b:b.com ".parse().expect("parses");
        assert_eq!(
            hosts.dashboard_url(&org("org_b")),
            Some("https://app.b.com".to_owned())
        );
    }

    #[test]
    fn a_domain_with_a_scheme_is_refused() {
        assert!("org_a:https://a.com".parse::<OrganizationHosts>().is_err());
    }

    #[test]
    fn a_domain_with_a_path_a_port_or_capitals_is_refused() {
        assert!("org_a:a.com/x".parse::<OrganizationHosts>().is_err());
        assert!("org_a:a.com:443".parse::<OrganizationHosts>().is_err());
        assert!("org_a:A.com".parse::<OrganizationHosts>().is_err());
    }

    #[test]
    fn a_single_label_domain_is_refused() {
        assert!("org_a:localhost".parse::<OrganizationHosts>().is_err());
    }

    #[test]
    fn an_entry_without_a_domain_is_refused() {
        assert!("org_a".parse::<OrganizationHosts>().is_err());
    }

    #[test]
    fn the_old_three_part_form_is_refused() {
        assert!("org_a:app.a.com:pay.a.com"
            .parse::<OrganizationHosts>()
            .is_err());
    }

    #[test]
    fn an_organisation_listed_twice_is_refused() {
        assert!("org_a:a.com org_a:b.com"
            .parse::<OrganizationHosts>()
            .is_err());
    }

    #[test]
    fn a_domain_listed_twice_is_refused() {
        assert!("org_a:a.com org_b:a.com"
            .parse::<OrganizationHosts>()
            .is_err());
    }

    #[test]
    fn it_deserializes_from_a_string() {
        let hosts: OrganizationHosts =
            serde_json::from_str("\"org_a:a.com\"").expect("deserializes");
        assert_eq!(
            hosts.payment_link_url(&org("org_a")),
            Some("https://pay.a.com".to_owned())
        );
    }
}
