//! Task 1.2: destinations are catalog capability names; every decision is recorded before the
//! call is forwarded; the report signs the record. `egress_hosts` stays Mediated throughout.

use std::collections::BTreeSet;

use warrantor_warrant::catalog::{
    check_capability_name, Capability, CapabilityCatalog, CATALOG_FORMAT,
};

#[test]
fn egress_hosts_sugar_compiles_into_host_named_capabilities() {
    let hosts: BTreeSet<String> = ["api.github.com".to_string()].into_iter().collect();
    let catalog = CapabilityCatalog::from_hosts(&hosts);
    assert_eq!(catalog.format, CATALOG_FORMAT);
    assert_eq!(catalog.capabilities.len(), 1);
    assert_eq!(catalog.capabilities[0].name, "host:api.github.com");
    assert_eq!(catalog.capabilities[0].host, "api.github.com");
    assert_eq!(catalog.hosts(), hosts);
}

#[test]
fn a_capability_name_can_never_be_an_address() {
    assert!(check_capability_name("publish-artifacts").is_ok());
    assert!(check_capability_name("host:api.github.com").is_ok());
    assert!(check_capability_name("https://evil.example").is_err());
    assert!(check_capability_name("203.0.113.9").is_err());
    assert!(check_capability_name("a/b").is_err());
    assert!(check_capability_name("").is_err());
}

#[test]
fn selecting_an_unknown_capability_is_refused_by_name() {
    let catalog = CapabilityCatalog {
        format: CATALOG_FORMAT.to_string(),
        warrant_id: None,
        capabilities: vec![Capability {
            name: "publish-artifacts".to_string(),
            host: "artifacts.example.internal".to_string(),
            purpose: "push build outputs".to_string(),
            permitted_methods: vec!["PUT".to_string()],
        }],
        signature: None,
    };
    let err = catalog
        .select(&["fetch-packages".to_string()].into_iter().collect())
        .expect_err("unknown name");
    assert!(err.contains("fetch-packages"), "{err}");
    let picked = catalog
        .select(&["publish-artifacts".to_string()].into_iter().collect())
        .expect("known name");
    assert_eq!(picked[0].host, "artifacts.example.internal");
}
