use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TARGET_CLASSIFIER_VERSION: &str = "target-classifier-v2";
pub const BLOCKED_IP_RANGES: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "192.175.48.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/96",
    "::1/128",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
    "5f00::/16",
    "2620:4f:8000::/48",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
];
pub const SPECIAL_HOSTS: &[&str] = &[
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
    "metadata.azure.internal",
    "169.254.169.254",
];

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
        IpAddr::V6(addr) => is_blocked_ipv6(addr),
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
        [100, second, _, _] if (64..=127).contains(&second) => true,
        [127, _, _, _] => true,
        [169, 254, _, _] => true,
        [172, second, _, _] if (16..=31).contains(&second) => true,
        [192, 0, 0, _] => true,
        [192, 0, 2, _] => true,
        [192, 31, 196, _] => true,
        [192, 52, 193, _] => true,
        [192, 88, 99, _] => true,
        [192, 168, _, _] => true,
        [192, 175, 48, _] => true,
        [198, second, _, _] if (18..=19).contains(&second) => true,
        [198, 51, 100, _] => true,
        [203, 0, 113, _] => true,
        [first, _, _, _] if first >= 224 => true,
        _ => false,
    }
}

fn is_blocked_ipv6(addr: Ipv6Addr) -> bool {
    let segments = addr.segments();
    let ipv4_compatible = segments[..6].iter().all(|segment| *segment == 0);
    let nat64_well_known = segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2..6].iter().all(|segment| *segment == 0);
    let nat64_local = segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1;
    let discard_only = segments[0] == 0x0100 && segments[1..4].iter().all(|segment| *segment == 0);
    ipv4_compatible
        || addr.is_loopback()
        || nat64_well_known
        || nat64_local
        || discard_only
        || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
        || segments[0] == 0x5f00
        || (segments[0] == 0x2620 && segments[1] == 0x004f && segments[2] == 0x8000)
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || addr.is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn contract() -> &'static str {
        std::str::from_utf8(
            redevplugin_contracts::get(
                redevplugin_contracts::ContractId::TARGET_CLASSIFIER_FIXTURE,
            )
            .bytes(),
        )
        .expect("target classifier contract is valid UTF-8")
    }

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

    #[test]
    fn classifier_matches_3fff_documentation_prefix_boundaries() {
        for denied in ["3fff::", "3fff:0fff:ffff::"] {
            assert!(
                is_blocked_address(denied.parse().expect("blocked IPv6 address must parse")),
                "{denied} must be blocked by 3fff::/20"
            );
        }
        for allowed in ["3ffe:ffff::", "3fff:1000::", "3ff0::"] {
            assert!(
                !is_blocked_address(allowed.parse().expect("allowed IPv6 address must parse")),
                "{allowed} must remain outside 3fff::/20"
            );
        }
    }

    fn read_contract() -> TargetClassifierContract {
        serde_json::from_str(contract()).expect("target classifier contract must decode")
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
