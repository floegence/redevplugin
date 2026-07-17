use proptest::prelude::*;
use redevplugin_target_classifier::{
    SPECIAL_HOSTS, is_blocked_address, is_blocked_host_literal, is_special_host,
};
use std::net::{IpAddr, Ipv4Addr};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn ipv4_literal_and_resolved_address_make_the_same_decision(
        octets in any::<[u8; 4]>(),
    ) {
        let address = IpAddr::V4(Ipv4Addr::from(octets));
        prop_assert_eq!(is_blocked_host_literal(&address.to_string()), is_blocked_address(address));
    }

    #[test]
    fn special_host_matching_is_case_and_dot_insensitive(index in 0usize..SPECIAL_HOSTS.len()) {
        let host = SPECIAL_HOSTS[index];
        prop_assert!(is_special_host(&host.to_ascii_uppercase()));
        let dotted = format!("{}.", host);
        let dotted_matches = is_special_host(&dotted);
        prop_assert!(dotted_matches);
    }
}
