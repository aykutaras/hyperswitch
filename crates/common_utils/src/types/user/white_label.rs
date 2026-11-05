//! A white-label organisation's own hosts: the dashboard its users' email links
//! open, and the host its payment links are served on.

use std::{collections::HashMap, str::FromStr};

use serde::{Deserialize, Deserializer};

use crate::id_type;

/// One organisation's own hosts, without a scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationHost {
    /// The host its dashboard answers on, such as `app.example.com`
    pub dashboard: String,
    /// The host its payment links are served on, such as `pay.example.com`
    pub payment_link: String,
}

/// Each white-label organisation's own hosts, by organisation.
///
/// Configured as one string, so that it can come from a single environment
/// variable: space-separated entries of `<org_id>:<dashboard host>:<payment link host>`.
/// Organisations not listed use the platform's own hosts. Only the deployment
/// sets it, never a user, because email links carry one-time tokens.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrganizationHosts(HashMap<id_type::OrganizationId, OrganizationHost>);

impl OrganizationHosts {
    /// The organisation's dashboard as a base URL, if it has one of its own.
    pub fn dashboard_url(&self, org_id: &id_type::OrganizationId) -> Option<String> {
        self.0
            .get(org_id)
            .map(|host| format!("https://{}", host.dashboard))
    }

    /// The organisation's payment link host as a base URL, if it has one of its own.
    pub fn payment_link_url(&self, org_id: &id_type::OrganizationId) -> Option<String> {
        self.0
            .get(org_id)
            .map(|host| format!("https://{}", host.payment_link))
    }

    /// Whether no organisation has hosts of its own.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
        let mut hosts = HashMap::new();
        for entry in value.split_whitespace() {
            let parts: Vec<&str> = entry.split(':').collect();
            let [org_id, dashboard, payment_link] = parts.as_slice() else {
                return Err(format!(
                    "`{entry}` is not <org_id>:<dashboard host>:<payment link host>"
                ));
            };
            let org_id = id_type::OrganizationId::try_from_string((*org_id).to_owned())
                .map_err(|_| format!("`{org_id}` in `{entry}` is not an organisation id"))?;
            for host in [dashboard, payment_link] {
                if !is_host_name(host) {
                    return Err(format!(
                        "`{host}` in `{entry}` is not a host name (no scheme, port or path)"
                    ));
                }
            }
            let host = OrganizationHost {
                dashboard: (*dashboard).to_owned(),
                payment_link: (*payment_link).to_owned(),
            };
            if hosts.insert(org_id.clone(), host).is_some() {
                return Err(format!("`{}` is listed twice", org_id.get_string_repr()));
            }
        }
        Ok(Self(hosts))
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

    #[test]
    fn an_empty_setting_has_no_organisations() {
        let hosts: OrganizationHosts = "".parse().expect("parses");
        assert!(hosts.is_empty());
    }

    #[test]
    fn a_listed_organisation_has_its_own_dashboard_and_payment_link_urls() {
        let hosts: OrganizationHosts = "org_brand:app.brand.example:pay.brand.example"
            .parse()
            .expect("parses");
        assert_eq!(
            (
                hosts.dashboard_url(&org("org_brand")),
                hosts.payment_link_url(&org("org_brand"))
            ),
            (
                Some("https://app.brand.example".to_owned()),
                Some("https://pay.brand.example".to_owned())
            )
        );
    }

    #[test]
    fn an_organisation_not_listed_has_none() {
        let hosts: OrganizationHosts = "org_brand:app.brand.example:pay.brand.example"
            .parse()
            .expect("parses");
        assert_eq!(hosts.dashboard_url(&org("org_other")), None);
    }

    #[test]
    fn entries_are_separated_by_any_whitespace() {
        let hosts: OrganizationHosts = "  org_a:app.a.com:pay.a.com \n org_b:app.b.com:pay.b.com "
            .parse()
            .expect("parses");
        assert_eq!(
            hosts.dashboard_url(&org("org_b")),
            Some("https://app.b.com".to_owned())
        );
    }

    #[test]
    fn a_host_with_a_scheme_is_refused() {
        assert!("org_a:https://app.a.com:pay.a.com"
            .parse::<OrganizationHosts>()
            .is_err());
    }

    #[test]
    fn a_host_with_a_path_or_capitals_is_refused() {
        assert!("org_a:app.a.com/x:pay.a.com"
            .parse::<OrganizationHosts>()
            .is_err());
        assert!("org_a:App.a.com:pay.a.com"
            .parse::<OrganizationHosts>()
            .is_err());
    }

    #[test]
    fn an_entry_without_three_parts_is_refused() {
        assert!("org_a:app.a.com".parse::<OrganizationHosts>().is_err());
    }

    #[test]
    fn an_organisation_listed_twice_is_refused() {
        assert!("org_a:app.a.com:pay.a.com org_a:app.b.com:pay.b.com"
            .parse::<OrganizationHosts>()
            .is_err());
    }

    #[test]
    fn it_deserializes_from_a_string() {
        let hosts: OrganizationHosts =
            serde_json::from_str("\"org_a:app.a.com:pay.a.com\"").expect("deserializes");
        assert_eq!(
            hosts.payment_link_url(&org("org_a")),
            Some("https://pay.a.com".to_owned())
        );
    }
}
