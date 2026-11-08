use ahu_harness_native::call;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::{fs, path::PathBuf};

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    exe: PathBuf,
}
impl Fixture {
    fn new(body: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let home = root.join("home");
        fs::create_dir(&home).unwrap();
        let exe = root.join("native");
        fs::write(&exe, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _tmp: tmp,
            root,
            home,
            exe,
        }
    }
    fn probe(&self) -> Value {
        json!({"project":self.root,"home":self.home,"native_executable":self.exe,"environment":{}})
    }
    fn setup(&self) -> Value {
        json!({"project":self.root,"home":self.home,"ahu_executable":self.exe,"skills":[]})
    }
}
#[test]
fn probe_returns_only_version_and_bounded_evidence() {
    let f = Fixture::new("printf 'private-sentinel codex-cli 0.160.0\\n'");
    let result = call("codex", "probe", &f.probe()).unwrap();
    assert_eq!(result["version"], "0.160.0");
    assert_eq!(result["reviewed_version"], true);
    assert!(!result.to_string().contains("private-sentinel"));
    assert!(
        call(
            "codex",
            "probe",
            &json!({"project":f.root,"home":f.home,"native_executable":"native","environment":{}})
        )
        .is_err()
    );
    let mut p = f.probe();
    p["unexpected"] = json!(true);
    assert!(call("codex", "probe", &p).is_err());
    assert!(call("unknown", "probe", &f.probe()).is_err());
    assert!(call("codex", "shell", &f.probe()).is_err());
}

#[test]
fn native_probe_mutations_are_detected_without_rollback_or_replay() {
    let f = Fixture::new(
        "mkdir -p .agents; printf 'changed' > .agents/config; printf 'codex-cli 0.160.0\\n'",
    );
    let e = call("codex", "probe", &f.probe()).unwrap_err();
    assert!(e.effects_unknown);
    assert_eq!(
        fs::read_to_string(f.root.join(".agents/config")).unwrap(),
        "changed"
    );
}
#[test]
fn setup_proposes_all_provider_formats_and_never_writes() {
    let f = Fixture::new("exit 99");
    for h in ["codex"] {
        let mut p = f.setup();
        p["skills"] = json!([{"name":"test-skill","text":"# synthetic\n"}]);
        let result = call(h, "setup", &p).unwrap();
        let changes = result["changes"].as_array().unwrap();
        assert!(changes.len() >= 2);
        for change in changes {
            assert!(change["expected_before_sha256"].is_null());
            assert!(!PathBuf::from(change["path"].as_str().unwrap()).exists());
        }
        let text = changes[0]["text"].as_str().unwrap();
        if h == "codex" {
            let v: toml::Value = toml::from_str(text).unwrap();
            assert_eq!(
                v["mcp_servers"]["ahu"]["tools"]["ahu_agents_list"]["approval_mode"].as_str(),
                Some("approve")
            );
        } else {
            let v: Value = serde_json::from_str(text).unwrap();
            let key = if h == "opencode" { "mcp" } else { "mcpServers" };
            assert!(v[key]["ahu"].is_object());
            if h == "kiro" {
                assert_eq!(v[key]["ahu"]["env"]["AHU_TASK_ID"], "${AHU_TASK_ID}");
            }
        }
    }
}

#[test]
fn codex_setup_preserves_comments_and_explicit_tool_approval() {
    let f = Fixture::new("exit 99");
    let dir = f.root.join(".codex");
    fs::create_dir(&dir).unwrap();
    let text = format!(
        "# preserve\n[mcp_servers.ahu]\ncommand = {}\nargs=['mcp','serve']\n[mcp_servers.ahu.tools.ahu_agents_list]\napproval_mode='prompt' # preserve too\n",
        json!(f.exe)
    );
    fs::write(dir.join("config.toml"), &text).unwrap();
    let r = call("codex", "setup", &f.setup()).unwrap();
    let text = r["changes"][0]["text"].as_str().unwrap();
    assert!(text.contains("# preserve too"));
    let v: toml::Value = toml::from_str(text).unwrap();
    assert_eq!(
        v["mcp_servers"]["ahu"]["tools"]["ahu_agents_list"]["approval_mode"].as_str(),
        Some("prompt")
    );
}

#[test]
fn public_trust_calls_reconcile_only_owned_receipts() {
    let f = Fixture::new("exit 99");
    let task = f.root.join("task");
    let worktree = f.root.join("worktree");
    fs::create_dir(&task).unwrap();
    fs::create_dir(&worktree).unwrap();
    let mut p = json!({"overrides":[],"task_dir":task,"worktree":worktree,"home":f.home,"permissions":"auto","mode":"interactive"});
    {
        let h = "codex";
        call(h, "trust_prepare", &p).unwrap();
        assert!(task.join("native-trust.json").exists());
        call(h, "trust_cleanup", &p).unwrap();
        assert!(!task.join("native-trust.json").exists());
    }
    p["permissions"] = json!("prompt");
    assert_eq!(
        call("codex", "trust_prepare", &p).unwrap()["status"],
        "not_applicable"
    );
    fs::write(task.join("native-trust.json"), "{}").unwrap();
    assert!(call("codex", "trust_prepare", &p).is_err());
}

#[test]
fn codex_capacity_includes_account_fingerprint_and_rejects_partial_windows() {
    for secondary in ["null", r#"{"usedPercent":200,"windowDurationMins":60}"#] {
        let script = format!(
            r#"read -r initialize
printf '%s\n' '{{"id":1,"result":{{}}}}'
read -r initialized
read -r account
printf '%s\n' '{{"id":2,"result":{{"account":{{"type":"chatgpt","email":"fixture@example.invalid"}}}}}}'
read -r limits
printf '%s\n' '{{"id":3,"result":{{"rateLimits":{{"primary":{{"usedPercent":25,"windowDurationMins":300}},"secondary":{secondary}}}}}}}'
"#
        );
        let f = Fixture::new(&script);
        let result = call("codex", "budget", &f.probe()).unwrap();
        assert_eq!(result["fingerprint"].as_str().unwrap().len(), 64);
        assert!(!result.to_string().contains("fixture@"));
        if secondary == "null" {
            assert_eq!(result["status"], "available");
            assert_eq!(result["windows"][0]["remaining_percent"], 75.0);
        } else {
            assert_eq!(result["status"], "unknown");
            assert_eq!(result["windows"], json!([]));
        }
    }
}

#[test]
fn masked_native_overrides_never_probe_the_default_account() {
    let f = Fixture::new("touch should-not-run; exit 99");
    for (harness, variable) in [
        ("codex", "CODEX_HOME"),
        ("claude-code", "ANTHROPIC_API_KEY"),
        ("opencode", "OLLAMA_HOST"),
        ("kiro", "KIRO_HOME"),
        ("antigravity", "GEMINI_API_KEY"),
    ] {
        let mut p = f.probe();
        p["environment_names"] = json!([variable]);
        assert!(call(harness, "auth", &p).is_err());
        assert!(call(harness, "budget", &p).is_err());
    }
    assert!(!f.root.join("should-not-run").exists());
}

#[test]
fn cleanup_reconciles_owned_receipt_after_eligibility_changes() {
    let f = Fixture::new("exit 99");
    let task = f.root.join("task");
    let tree = f.root.join("tree");
    fs::create_dir(&task).unwrap();
    fs::create_dir(&tree).unwrap();
    let mut p = json!({"task_dir":task,"worktree":tree,"home":f.home,"permissions":"prompt","mode":"interactive","overrides":[]});
    for permission in ["prompt", "accept-edits"] {
        p["permissions"] = json!(permission);
        assert_eq!(
            call("codex", "trust_prepare", &p).unwrap()["status"],
            "not_applicable"
        );
    }
    p["permissions"] = json!("auto");
    call("codex", "trust_prepare", &p).unwrap();
    assert!(task.join("native-trust.json").exists());
    p["permissions"] = json!("prompt");
    p["mode"] = json!("headless");
    call("codex", "trust_cleanup", &p).unwrap();
    assert!(!task.join("native-trust.json").exists());
}
