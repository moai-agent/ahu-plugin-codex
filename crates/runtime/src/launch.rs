use serde::Deserialize;
use serde_json::{Value, json};
const PROMPT: &str = "<prompt: see prompt.txt>";
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Interactive,
    Headless,
    Direct,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Permissions {
    Prompt,
    AcceptEdits,
    Auto,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    mode: Mode,
    model: String,
    permissions: Permissions,
    work_mode: bool,
    session: Option<String>,
    native_version: String,
    timeout_seconds: u64,
    cwd: String,
    broker_dir: Option<String>,
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    native_profile: Option<Value>,
    native_controls: Vec<String>,
}
fn identity(value: &str, limit: usize, alphabet: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || alphabet.contains(&b))
}
pub(super) fn plan(harness: &str, params: Value) -> Result<Value, ()> {
    let r: Request = serde_json::from_value(params).map_err(|_| ())?;
    if !identity(&r.model, 256, b"-_.:/+")
        || !(1..=604800).contains(&r.timeout_seconds)
        || r.session.as_ref().is_some_and(|s| !identity(s, 128, b"-_"))
        || !std::path::Path::new(&r.cwd).is_absolute()
        || r.cwd.contains('\0')
        || r.work_mode && r.permissions != Permissions::Auto
        || r.mode != Mode::Headless && (r.session.is_some() || r.work_mode)
        || r.native_controls.len() > 128
    {
        return Err(());
    }
    // Core enforces explicit project pins. Unpinned native versions float;
    // version-specific controls still require their inspected admission evidence.
    let version = ahu_harness_native::version_token(&r.native_version).ok_or(())?;
    let _standalone = version.starts_with("2.");

    let program = harness;
    let mut args: Vec<String> = Vec::new();
    let mut add = |values: &[&str]| args.extend(values.iter().map(|s| (*s).to_owned()));
    if r.mode == Mode::Direct && r.permissions == Permissions::Auto {
        match harness {
            "codex" => add(&["-m", &r.model, "--dangerously-bypass-approvals-and-sandbox"]),

            // The reviewed mini CLI has no unattended permission override.
            _ => return Err(()),
        }
        return Ok(
            json!({"program":program,"args":args,"prompt_arg":null,"native_eval_otlp":harness != "kiro"}),
        );
    }
    if r.mode == Mode::Headless {
        match harness {
            "codex" => {
                add(&["exec"]);
                if r.session.is_some() {
                    add(&["resume"]);
                }
                add(&[
                    "--model",
                    &r.model,
                    "--json",
                    "-c",
                    "approval_policy=\"never\"",
                ]);
                if !r.work_mode {
                    add(&["-c", "agents.enabled=false"]);
                }
                match r.permissions {
                    Permissions::Prompt => add(&["-c", "sandbox_mode=\"read-only\""]),
                    Permissions::Auto => add(&[
                        "-c",
                        if r.work_mode {
                            "sandbox_mode=\"danger-full-access\""
                        } else {
                            "sandbox_mode=\"workspace-write\""
                        },
                    ]),
                    Permissions::AcceptEdits if r.session.is_none() => add(&["--approve-for-me"]),
                    _ => return Err(()),
                }
                if r.session.is_none() {
                    add(&["--color", "never"]);
                }
                if !r.work_mode && ["0.157.1", "0.160.0"].contains(&version) {
                    let id =
                        format!("native.isolation.codex-{version}-effective-guarded-hooks-v1=flag");
                    if !r.native_controls.contains(&id) {
                        return Err(());
                    }
                    add(&[
                        "--strict-config",
                        "-c",
                        "features.hooks=true",
                        "-c",
                        "features.plugins=false",
                        "-c",
                        "features.remote_plugin=false",
                        "-c",
                        "notify=[]",
                    ]);
                }
                if let Some(dir) = &r.broker_dir {
                    if !std::path::Path::new(dir).is_absolute() || dir.contains('\0') {
                        return Err(());
                    }
                    let quoted = serde_json::to_string(dir).map_err(|_| ())?;
                    add(&[
                        "-c",
                        &format!("sandbox_workspace_write.writable_roots=[{quoted}]"),
                    ]);
                }
                add(&["--"]);
                if let Some(session) = &r.session {
                    add(&[session]);
                }
            }

            _ => return Err(()),
        }
    } else {
        match harness {
            "codex" => {
                add(&["-m", &r.model, "--no-daemon"]);
                match r.permissions {
                    Permissions::Prompt => (),
                    Permissions::AcceptEdits => add(&["--approve-for-me"]),
                    Permissions::Auto => add(&[
                        "--ask-for-approval",
                        "never",
                        "--sandbox",
                        "workspace-write",
                    ]),
                }
                if r.mode == Mode::Interactive {
                    add(&["--"]);
                }
            }

            _ => return Err(()),
        }
    }
    let prompt_arg = if r.mode == Mode::Direct {
        None
    } else {
        let i = args.len();
        args.push(PROMPT.into());
        Some(i)
    };
    Ok(
        json!({"program":program,"args":args,"prompt_arg":prompt_arg,"native_eval_otlp":harness != "kiro"}),
    )
}
