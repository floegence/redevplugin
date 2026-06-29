pub const TARGET_CLASSIFIER_VERSION: &str = "target-classifier-v1";

pub fn is_special_host(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "metadata.google.internal" | "169.254.169.254"
    )
}

