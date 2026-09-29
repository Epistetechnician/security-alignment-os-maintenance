//! Static guard for the Confidential Space image's sensitive-output policy.
//!
//! State slice: `security-alignment-os-foundation-v1`.

const DOCKERFILE: &str = include_str!("../infra/confidential-space/Dockerfile");

#[test]
fn confidential_space_image_forbids_stdout_and_stderr_redirection() {
    let policies = DOCKERFILE
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(r#"LABEL "tee.launch_policy.log_redirect""#))
        .collect::<Vec<_>>();
    assert_eq!(
        policies,
        [r#"LABEL "tee.launch_policy.log_redirect"="never""#]
    );
}
