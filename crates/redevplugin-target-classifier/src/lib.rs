use std::net::{IpAddr, Ipv4Addr};

pub const TARGET_CLASSIFIER_VERSION: &str = "target-classifier-v1";
pub const BLOCKED_IP_RANGES: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];
pub const SPECIAL_HOSTS: &[&str] = &["localhost", "metadata.google.internal", "169.254.169.254"];

pub fn is_special_host(host: &str) -> bool {
    let normalized = normalize_host(host);
    SPECIAL_HOSTS.contains(&normalized.as_str())
}

pub fn is_blocked_host_literal(host: &str) -> bool {
    let normalized = normalize_host(host);
    normalized
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok_and(is_blocked_address)
}

pub fn is_blocked_address(addr: IpAddr) -> bool {
    match unmap_ipv4_mapped(addr) {
        IpAddr::V4(addr) => is_blocked_ipv4(addr),
        IpAddr::V6(addr) => {
            addr.is_loopback()
                || (addr.segments()[0] & 0xfe00) == 0xfc00
                || (addr.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn unmap_ipv4_mapped(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(addr) => addr
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(addr)),
        IpAddr::V4(addr) => IpAddr::V4(addr),
    }
}

fn is_blocked_ipv4(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    match octets {
        [0, _, _, _] => true,
        [10, _, _, _] => true,
        [127, _, _, _] => true,
        [169, 254, _, _] => true,
        [172, second, _, _] if (16..=31).contains(&second) => true,
        [192, 168, _, _] => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const CONTRACT: &str = include_str!("../../../spec/plugin/target-classifier-v1.json");

    #[derive(Deserialize)]
    struct TargetClassifierContract {
        version: String,
        blocked_ip_ranges: Vec<String>,
        special_hosts: Vec<String>,
        fixtures: Vec<TargetClassifierFixture>,
    }

    #[derive(Deserialize)]
    struct TargetClassifierFixture {
        name: String,
        destination: String,
        resolved_address: Option<String>,
        decision: String,
    }

    #[test]
    fn constants_match_target_classifier_contract() {
        let contract = read_contract();
        assert_eq!(contract.version, TARGET_CLASSIFIER_VERSION);
        let ranges = contract
            .blocked_ip_ranges
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let hosts = contract
            .special_hosts
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(ranges, BLOCKED_IP_RANGES);
        assert_eq!(hosts, SPECIAL_HOSTS);
    }

    #[test]
    fn classifier_matches_target_classifier_fixtures() {
        let contract = read_contract();
        assert!(!contract.fixtures.is_empty());
        for fixture in contract.fixtures {
            let host = host_from_destination(&fixture.destination);
            let mut denied = is_special_host(host) || is_blocked_host_literal(host);
            if let Some(resolved_address) = fixture.resolved_address.as_deref() {
                let addr = resolved_address.parse::<IpAddr>().unwrap_or_else(|err| {
                    panic!("{} resolved address parse error: {err}", fixture.name)
                });
                denied = denied || is_blocked_address(addr);
            }
            match fixture.decision.as_str() {
                "allow" => assert!(!denied, "{} should be allowed", fixture.name),
                "deny" => assert!(denied, "{} should be denied", fixture.name),
                other => panic!("{} has unsupported decision {other}", fixture.name),
            }
        }
    }

    fn read_contract() -> TargetClassifierContract {
        serde_json::from_str(CONTRACT).expect("target classifier contract must decode")
    }

    fn host_from_destination(destination: &str) -> &str {
        let authority = destination
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(destination);
        if let Some(without_bracket) = authority.strip_prefix('[') {
            return without_bracket
                .split_once(']')
                .map(|(host, _)| host)
                .unwrap_or(without_bracket);
        }
        authority
            .split_once(':')
            .map(|(host, _)| host)
            .unwrap_or(authority)
    }
}
