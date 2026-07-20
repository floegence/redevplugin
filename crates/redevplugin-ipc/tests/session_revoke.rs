use redevplugin_ipc::{
    RUST_IPC_VERSION, SessionRevokeAckCounts, SessionRevokeState, parse_session_revoke_request,
    session_revoke_ack_frame,
};

#[test]
fn ipc_v5_parses_closed_session_revoke_and_builds_terminal_ack() {
    assert_eq!(RUST_IPC_VERSION, "rust-ipc-v5");
    let raw = r#"{"ipc_version":"rust-ipc-v5","frame_type":"session_revoke","request_id":"revoke_1","runtime_generation_id":"generation_1","payload":{"session_revoke_sequence":1,"owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash"}}"#;
    let request = parse_session_revoke_request(raw).expect("session revoke frame");
    assert_eq!(request.request_id, "revoke_1");
    assert_eq!(request.session_revoke_sequence, 1);
    assert_eq!(request.owner_session_hash, "session_hash");
    let ack = session_revoke_ack_frame(
        &request.request_id,
        "generation_1",
        request.session_revoke_sequence,
        SessionRevokeState::Complete,
        SessionRevokeAckCounts {
            queued_invocations: 2,
            running_invocations: 3,
            storage_hostcalls: 4,
            active_network_requests: 5,
            sockets: 6,
            network_streams: 7,
        },
    )
    .expect("session revoke ack");
    let ack: serde_json::Value = serde_json::from_str(&ack).expect("closed ack JSON");
    assert_eq!(ack["frame_type"], "session_revoke_ack");
    assert_eq!(ack["payload"]["result"]["state"], "complete");
    assert_eq!(ack["payload"]["result"]["counts"]["network_streams"], 7);
}

#[test]
fn session_revoke_rejects_non_positive_or_unsafe_sequence_and_wrong_generation_shape() {
    for sequence in [0, 9_007_199_254_740_992_u64] {
        let raw = format!(
            r#"{{"ipc_version":"rust-ipc-v5","frame_type":"session_revoke","request_id":"revoke_1","runtime_generation_id":"generation_1","payload":{{"session_revoke_sequence":{sequence},"owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash"}}}}"#
        );
        assert!(parse_session_revoke_request(&raw).is_err());
    }
    let unknown_top_level = r#"{"ipc_version":"rust-ipc-v5","frame_type":"session_revoke","request_id":"revoke_1","runtime_generation_id":"generation_1","future":true,"payload":{"session_revoke_sequence":1,"owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash"}}"#;
    assert!(parse_session_revoke_request(unknown_top_level).is_err());
}

#[test]
fn session_revoke_rejects_payload_owner_omission_and_unknown_fields() {
    for raw in [
        r#"{"ipc_version":"rust-ipc-v5","frame_type":"session_revoke","request_id":"revoke_1","runtime_generation_id":"generation_1","payload":{"session_revoke_sequence":1,"owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash"}}"#,
        r#"{"ipc_version":"rust-ipc-v5","frame_type":"session_revoke","request_id":"revoke_1","runtime_generation_id":"generation_1","payload":{"session_revoke_sequence":1,"owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash","future":true}}"#,
    ] {
        assert!(parse_session_revoke_request(raw).is_err(), "accepted {raw}");
    }
}
