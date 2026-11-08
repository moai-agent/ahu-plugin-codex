//! Bounded, read-only evidence about native hook integrations. Inspection
//! reads at most LIMIT bytes per file and considers at most MAX_ENTRIES entries.
//! No hook bodies are persisted, interpreted, installed, or copied by
//! inspection.
//!
//! Admission is provider-neutral: executable hook and plugin behavior remains
//! unknown unless covered by a harness invocation profile. Inspection never
//! changes native settings or provider environment variables.
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use crate::util::{Error, Result, digest_bytes, display_safe};

const LIMIT: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 256;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Registration {
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    Installed,
    Missing,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Activation {
    Disabled,
    Unknown,
    NotApplicable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    Absent,
    VerifiedDisable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Conformance {
    Untested,
    // Retained for the shared wire schema, although this adapter does not consume it.
    #[allow(dead_code)]
    SourceInspected,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub path: PathBuf,
    pub scope: String,
    pub method: String,
    pub digest: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Component {
    pub name: String,
    pub registration: Registration,
    pub activation: Activation,
    pub isolation: Isolation,
    pub conformance: Conformance,
    pub evidence: Vec<Evidence>,
    pub detail: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub harness: String,
    pub native_agent: Option<String>,
    pub profile: Option<crate::compatibility::IsolationProfile>,
    pub cli_version: Option<String>,
    pub version_checked: bool,
    pub components: Vec<Component>,
    pub gaps: Vec<String>,
    pub conformance: String,
    pub headless: HeadlessPolicy,
    pub next_action: String,
}
impl Status {
    /// Add a version observation to the same evidence used for interactive
    /// disclosure. This never gates interactive execution or probes a provider.
    pub fn with_version(mut self, version: Option<&str>) -> Self {
        self.version_checked = true;
        self.cli_version = version.map(str::to_owned);
        if self.harness == "codex"
            && crate::isolation::profile("codex", version.unwrap_or("")).is_some()
            && !self
                .components
                .iter()
                .any(|c| c.name == "native invocation profile")
        {
            self.headless.allowed = false;
            self.headless.reasons.push("This Codex version requires fresh native effective hook and requirements inspection using the frozen invocation profile".into());
        }
        if let Err(error) =
            crate::compatibility::check_headless_version(&self.harness, version.unwrap_or(""))
        {
            self.headless.allowed = false;
            self.headless.reasons.push(error.to_string());
            if crate::compatibility::supports(
                &self.harness,
                crate::compatibility::Feature::HeadlessLaunch,
            ) {
                self.next_action = format!(
                    "Use a CLI that reports a parseable semantic version. Interactive execution remains available subject to normal prerequisites. {}",
                    self.next_action
                );
            } else {
                self.next_action = "Use interactive execution; this harness has no validated ahu headless adapter.".into();
            }
        }

        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HeadlessPolicy {
    pub allowed: bool,
    pub reasons: Vec<String>,
    pub evidence_digest: String,
}

/// Result of the native preference presence probe. Values are never decoded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedPreferences {
    #[default]
    NotApplicable,
    Absent,
    Present,
    Unknown,
}

/// Explicit inputs keep fixture tests independent of the host's configuration.
#[derive(Debug, Clone, Default)]
pub struct Locations {
    pub home: Option<PathBuf>,
    pub overrides: BTreeMap<String, String>,
    pub managed_claude: Option<PathBuf>,
    pub managed_opencode: Option<PathBuf>,
    pub managed_preferences: Option<PathBuf>,
    pub system_codex: Option<PathBuf>,
    pub codex_managed_preferences: ManagedPreferences,
}
fn native_agent(harness: &str) -> Option<&'static str> {
    match harness {
        "codex" => Some("codex"),

        _ => None,
    }
}
// Check all existing ancestors before opening: dangling links, linked parent
// directories and special files are uncertainty, never evidence of absence.
fn check_path(path: &Path) -> std::result::Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("relative or unresolved path".into());
    }
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err("symlink evidence is unresolved".into());
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("cannot inspect path metadata".into()),
        }
    }
    Ok(())
}
fn read(path: &Path) -> std::result::Result<Option<Vec<u8>>, String> {
    check_path(path)?;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot inspect file".into()),
    };
    if !meta.is_file() || meta.len() > LIMIT {
        return Err("not a bounded regular file".into());
    }
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot open file")?;
    if !file
        .metadata()
        .map_err(|_| "cannot inspect opened file")?
        .is_file()
    {
        return Err("not a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read file")?;
    if bytes.len() as u64 > LIMIT {
        return Err("file exceeds inspection limit".into());
    }
    Ok(Some(bytes))
}
fn component(name: &str, path: &Path, scope: &str) -> Component {
    Component {
        name: name.into(),
        registration: Registration::Unknown,
        activation: Activation::Unknown,
        isolation: Isolation::Unknown,
        conformance: Conformance::Untested,
        evidence: vec![Evidence {
            path: path.into(),
            scope: scope.into(),
            method: "bounded native configuration inspection".into(),
            digest: None,
        }],
        detail: "unverified native component".into(),
    }
}
fn absent(c: &mut Component) {
    c.registration = Registration::Missing;
    c.activation = Activation::NotApplicable;
    c.isolation = Isolation::Absent;
    c.detail = "no registration in inspected scope".into();
}
fn file_bytes(c: &mut Component) -> Option<Vec<u8>> {
    match read(&c.evidence[0].path) {
        Ok(None) => {
            absent(c);
            None
        }
        Ok(Some(bytes)) => {
            c.evidence[0].digest = Some(digest_bytes(&bytes));
            Some(bytes)
        }
        Err(reason) => {
            c.detail = reason;
            None
        }
    }
}

pub fn inspect_in(repo: &Path, harness: &str, locations: &Locations) -> Status {
    let mut components = Vec::new();
    let gaps = vec!["Configuration evidence only; native trust, future surface activation and live delivery are unverified.".into(),
        "Arbitrary hooks, remote plugins and configuration indirection are not interpreted. Same-user concurrent changes are not isolated.".into()];
    let Some(home) = &locations.home else {
        components.push(component("home", Path::new("HOME"), "user"));
        return finish(harness, components, gaps);
    };
    let relevant: &[&str] = match harness {
        "codex" => &["CODEX_HOME"],

        _ => &[],
    };
    for key in relevant {
        if locations.overrides.contains_key(*key) {
            let mut c = component(key, Path::new(key), "environment override");
            c.detail = "custom native configuration scope is not verified; inspect it explicitly or use the default scope".into();
            components.push(c);
        }
    }
    match harness {
        "codex" => {
            scan_codex_sources(repo, locations, &mut components);
            let config = home.join(".codex/config.toml");
            let activation = codex_activation(&config, &mut components);
            scan_hooks(
                &home.join(".codex/hooks.json"),
                "user",
                harness,
                activation,
                &mut components,
            );
            scan_hooks(
                &repo.join(".codex/hooks.json"),
                "project",
                harness,
                Activation::Unknown,
                &mut components,
            );
            // Project features and notify hooks may override user settings.
            codex_activation(&repo.join(".codex/config.toml"), &mut components);
        }

        _ => components.push(component("unsupported harness", repo, "unknown")),
    }
    // Native project discovery may walk upward. Bound that search and include
    // parent settings rather than treating a clean leaf as a clean scope.
    for (depth, parent) in repo.ancestors().skip(1).enumerate() {
        if depth >= 32 || components.len() > MAX_ENTRIES {
            let mut c = component("ancestor scope", parent, "project ancestor");
            c.detail = "ancestor inspection limit exceeded".into();
            components.push(c);
            break;
        }
        if harness == "codex" {
            codex_activation(&parent.join(".codex/config.toml"), &mut components);
            scan_hooks(
                &parent.join(".codex/hooks.json"),
                "project ancestor",
                harness,
                Activation::Unknown,
                &mut components,
            );
        }
    }
    for file in [".mcp.json", ".agents/settings.json"] {
        let path = repo.join(file);
        let mut c = component("additional integration scope", &path, "project");
        if let Some(bytes) = file_bytes(&mut c) {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(value)
                    if value.is_object()
                        && (file == ".mcp.json"
                            || value.as_object().is_some_and(serde_json::Map::is_empty)) =>
                {
                    absent(&mut c);
                    c.detail = "no executable hook policy in inspected scope; MCP subprocess behavior remains native and outside inspection".into();
                }
                Ok(_) => {
                    c.detail =
                        "unsupported executable configuration scope; behavior is unknown".into()
                }
                Err(_) => c.detail = "malformed integration configuration".into(),
            }
        }
        components.push(c);
    }
    finish(harness, components, gaps)
}

// Reviewed against the installed 2.28.0 and 2.29.0 V3 KAS profile loaders.
// Only the explicitly inspected declarative subset is admitted.
// No arbitrary executable source is certified by its filename or contents.

// Deliberately narrower than the native schema: no executable hooks, knowledge
// indexing, Powers activation, or unknown control fields. Permissions and MCP
// are native policy, not a claim that subprocesses are isolated.

fn finish(harness: &str, mut components: Vec<Component>, gaps: Vec<String>) -> Status {
    // A native user path can also be reached by project ancestor discovery.
    // Retain one observation, without collapsing duplicate hook registrations
    // (their numbered names differ).
    let mut seen = std::collections::BTreeSet::new();
    components.retain(|c| seen.insert((c.name.clone(), c.evidence[0].path.clone())));
    let reasons: Vec<String> = components
        .iter()
        .filter(|c| matches!(c.isolation, Isolation::Unknown))
        .map(|c| {
            format!(
                "{} ({}): {}",
                display_safe(&c.name),
                display_safe(&c.evidence[0].path.to_string_lossy()),
                display_safe(&c.detail)
            )
        })
        .collect();
    let headless = HeadlessPolicy {
        allowed: reasons.is_empty(),
        reasons,
        evidence_digest: digest_bytes(
            &serde_json::to_vec(&components).expect("component serialization"),
        ),
    };
    Status { profile: crate::compatibility::isolation_profile(harness), cli_version: None, version_checked: false, harness: harness.into(), native_agent: native_agent(harness).map(str::to_string),
        components, gaps, conformance: "locally_inspected; live_untested".into(), headless,
        next_action: "Review unresolved native configuration with its owner; use interactive execution or explicit --work-mode when native compatibility is unverified.".into() }
}

/// Presence-only inspection for credentials, opaque native stores and legacy
/// formats. Never open these files, hash their contents, or invoke their loader.
fn opaque_source(path: &Path, name: &str, scope: &str, reason: &str, out: &mut Vec<Component>) {
    let mut c = component(name, path, scope);
    c.evidence[0].method = "metadata only; contents not read".into();
    match check_path(path).and_then(|()| match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("cannot inspect native source metadata".into()),
    }) {
        Ok(false) => absent(&mut c),
        Ok(true) => c.detail = reason.into(),
        Err(reason) => c.detail = reason,
    }
    out.push(c);
}

// OpenCode v1.18.29-v1.18.32 config/config.ts, config/managed.ts,
// auth/index.ts and account/repo.ts. Native authentication can cause remote
// config to add plugins; authentication values and account databases stay native.

// Codex rust-v0.154.0 and rust-v0.155.1 hooks/engine/discovery.rs and
// config/loader: native sources include TOML, plugins, managed and cloud layers.
fn scan_codex_sources(repo: &Path, locations: &Locations, out: &mut Vec<Component>) {
    let home = locations.home.as_ref().expect("home checked by caller");
    let codex = home.join(".codex");
    for (file, name, reason) in [
        (
            "plugins",
            "plugin hook sources",
            "native plugin bundles and remote-installed plugin state are unresolved; plugin code is not loaded by inspection",
        ),
        (
            "auth.json",
            "cloud authentication",
            "native authentication may load remote managed hooks/plugins; credentials are not read and remote config is not fetched",
        ),
        (
            "cloud-config-bundle-cache.json",
            "cloud configuration",
            "native cloud configuration cache may contain managed hooks; cached remote context is not read",
        ),
    ] {
        opaque_source(&codex.join(file), name, "user native state", reason, out);
    }
    codex_activation(&repo.join("config.toml"), out);
    scan_hooks(
        &repo.join("hooks.json"),
        "cwd",
        "codex",
        Activation::Unknown,
        out,
    );
    if let Some(system) = &locations.system_codex {
        codex_activation(&system.join("config.toml"), out);
        scan_hooks(
            &system.join("hooks.json"),
            "system",
            "codex",
            Activation::Unknown,
            out,
        );
        for file in ["requirements.toml", "managed_config.toml"] {
            opaque_source(
                &system.join(file),
                "managed hook sources",
                "system",
                "managed native configuration is present; inline hooks and managed directories are unresolved",
                out,
            );
        }
    }
    if locations.codex_managed_preferences != ManagedPreferences::NotApplicable {
        let mut c = component(
            "native managed preferences",
            Path::new("com.openai.codex"),
            "macOS CFPreferences",
        );
        c.evidence[0].method = "native CFPreferences key presence only; values not decoded".into();
        if locations.codex_managed_preferences == ManagedPreferences::Absent {
            absent(&mut c);
        } else {
            c.detail = "Codex managed preference values are present or the native query is unresolved; their executable hooks have not been verified. Use interactive execution".into();
        }
        out.push(c);
    }
}

fn codex_activation(path: &Path, components: &mut Vec<Component>) -> Activation {
    let mut c = component("configuration", path, "native config");
    if let Some(bytes) = file_bytes(&mut c) {
        match std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| toml::from_str::<toml::Value>(s).ok())
        {
            Some(value) => {
                let configured_disabled = value
                    .get("features")
                    .and_then(|v| v.get("hooks"))
                    .and_then(toml::Value::as_bool)
                    == Some(false);
                // Enabling hooks is not proof of effective native trust.
                if codex_indirection(&value) {
                    c.detail =
                        "additional command or configuration indirection is unresolved".into();
                } else {
                    absent(&mut c);
                    c.detail = if configured_disabled {
                        "This scope requests hooks disabled; other layers and effective activation remain unverified."
                    } else {
                        "TOML parsed; no additional hook/notify indirection; effective native trust is unverified"
                    }.into();
                }
            }
            None => c.detail = "malformed TOML".into(),
        }
    }
    components.push(c);
    Activation::Unknown
}

fn codex_indirection(value: &toml::Value) -> bool {
    let Some(table) = value.as_table() else {
        return true;
    };
    for (key, entry) in table {
        // An explicit empty argv defines no notification command. Keep every
        // nonempty or malformed value unresolved, including in native profiles.
        if (key == "notify" && entry.as_array().is_none_or(|args| !args.is_empty()))
            || ["include", "imports", "profile"].contains(&key.as_str())
            || (["plugins", "marketplaces"].contains(&key.as_str())
                && entry.as_table().is_none_or(|t| !t.is_empty()))
            || (key == "cli_auth_credentials_store" && entry.as_str() != Some("file"))
        {
            return true;
        }
        if key == "hooks" && entry.is_table() {
            // Native trust hashes are data, not hook command definitions.
            let Some(state) = entry.get("state").and_then(toml::Value::as_table) else {
                return true;
            };
            if entry.as_table().is_none_or(|t| t.len() != 1)
                || state.values().any(|record| {
                    record.as_table().is_none_or(|r| {
                        r.len() != 1
                            || r.get("trusted_hash")
                                .and_then(toml::Value::as_str)
                                .is_none()
                    })
                })
            {
                return true;
            }
        } else if entry.is_table() && codex_indirection(entry) {
            return true;
        }
    }
    false
}

fn scan_hooks(
    path: &Path,
    scope: &str,
    _harness: &str,
    activation: Activation,
    out: &mut Vec<Component>,
) {
    let mut c = component("hook registration", path, scope);
    let Some(bytes) = file_bytes(&mut c) else {
        out.push(c);
        return;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        c.detail = "malformed JSON".into();
        out.push(c);
        return;
    };
    if !value.is_object() {
        c.detail = "expected a native settings object".into();
        out.push(c);
        return;
    }
    if value
        .get("enabledPlugins")
        .is_some_and(|v| v.as_object().is_none_or(|o| o.values().any(|v| v != false)))
    {
        let mut plugin = c.clone();
        plugin.name = "native plugins".into();
        plugin.detail = "plugin hook behavior is unresolved".into();
        out.push(plugin);
    }
    let Some(hooks) = value.get("hooks") else {
        absent(&mut c);
        out.push(c);
        return;
    };
    let Some(events) = hooks.as_object() else {
        c.detail = "unsupported hook structure".into();
        out.push(c);
        return;
    };
    if events.is_empty() {
        absent(&mut c);
        out.push(c);
        return;
    }
    let mut count = 0;
    for (event, groups) in events {
        let Some(groups) = groups.as_array() else {
            c.detail = "unsupported hook event structure".into();
            out.push(c);
            return;
        };
        for group in groups {
            let Some(entries) = group.get("hooks").and_then(Value::as_array) else {
                c.detail = "unsupported hook group".into();
                out.push(c);
                return;
            };
            for _entry in entries {
                count += 1;
                if count > MAX_ENTRIES {
                    c.detail = "hook inspection entry limit exceeded".into();
                    out.push(c);
                    return;
                }
                let mut item = c.clone();
                item.name = format!("{event} registration {count}");
                item.activation = activation;
                item.detail =
                    "unrecognized native hook command; isolation cannot be established".into();
                out.push(item);
            }
        }
    }
    if count == 0 {
        absent(&mut c);
        out.push(c);
    }
}

/// Apply only controls that batch_command also freezes and emits. Inspection
/// without this explicit headless profile retains its interactive evidence.
pub fn headless_status(mut status: Status, version: &str) -> Status {
    if status.harness == "claude-code"
        && let Some(profile) = crate::isolation::profile(&status.harness, version)
    {
        for component in &mut status.components {
            let evidence = &component.evidence[0];
            if status.harness == "claude-code"
                && matches!(
                    evidence.scope.as_str(),
                    "user" | "project" | "project local" | "project ancestor"
                )
                && evidence.digest.is_some()
                && component.name.contains(" registration ")
                && component.isolation == Isolation::Unknown
            {
                component.isolation = Isolation::VerifiedDisable;
                component.activation = Activation::Disabled;
                component.detail = format!(
                    "disabled by invocation profile {}; managed policy is retained",
                    profile.id
                );
            }
        }
        status = finish(&status.harness, status.components, status.gaps);
        status.gaps.push(format!("Headless invocation profile: {}. Managed hooks and unresolved plugins remain admission blockers.", profile.id));
    }
    status.with_version(Some(version))
}

pub fn codex_effective_status(
    status: Status,
    repo: &Path,
    metadata: &Value,
    version: &str,
) -> Result<Status> {
    let profile = crate::isolation::profile("codex", version).ok_or_else(|| {
        Error::new("no reviewed Codex metadata isolation profile for this version")
    })?;
    if status.harness != "codex" {
        return Err(Error::new(
            "native Codex metadata cannot authorize another harness",
        ));
    }
    let data = metadata
        .get("data")
        .and_then(Value::as_array)
        .filter(|data| data.len() == 1)
        .ok_or_else(|| Error::new("native Codex hook inventory has an invalid scope"))?;
    let entry = &data[0];
    if entry.get("cwd").and_then(Value::as_str) != repo.to_str()
        || !["warnings", "errors"].iter().all(|key| {
            entry
                .get(key)
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        })
    {
        return Err(Error::new(
            "native Codex hook inventory has unresolved scope, warnings or errors",
        ));
    }
    let hooks = entry
        .get("hooks")
        .and_then(Value::as_array)
        .filter(|hooks| hooks.len() <= MAX_ENTRIES)
        .ok_or_else(|| Error::new("native Codex hook inventory is missing or exceeds the bound"))?;
    let mut components = status.components;
    if !hooks.is_empty() {
        return Err(Error::new(
            "native Codex executable hooks are unverified, including disabled or untrusted hooks",
        ));
    }
    for item in &mut components {
        if [
            "plugin hook sources",
            "cloud authentication",
            "cloud configuration",
        ]
        .contains(&item.name.as_str())
            && item.isolation == Isolation::Unknown
            && item.evidence[0].scope == "user native state"
            && item.detail.starts_with("native ")
        {
            item.isolation = Isolation::VerifiedDisable;
            item.detail = "executable consequences covered by the exact Codex invocation profile and fresh native hook metadata; credentials remain native and unread".into();
        }
    }
    let mut invocation = component(
        "native invocation profile",
        repo,
        "native effective metadata",
    );
    invocation.isolation = Isolation::VerifiedDisable;
    invocation.evidence[0].method =
        "exact invocation controls and explicit absent mandatory requirements".into();
    invocation.evidence[0].digest = Some(digest_bytes(&serde_json::to_vec(&(
        profile.id,
        profile.args,
        "requirements:null",
    ))?));
    invocation.detail = format!(
        "{}; fresh native hooks/list and configRequirements/read checked",
        profile.id
    );
    components.push(invocation);
    let mut gaps = status.gaps;
    gaps.push("Codex effective metadata was inspected before this launch with hooks enabled, optional plugins disabled and notify empty. Mandatory requirements must be absent; native strict configuration still rejects newly conflicting requirements. Remote changes between inspection and execution and same-user concurrent changes are not isolated.".into());
    let status = finish("codex", components, gaps);
    if !status.headless.allowed {
        return Err(Error::new(format!(
            "headless native integration admission is unverified for codex:\n{}",
            status.headless.reasons.join("\n")
        )));
    }
    Ok(status)
}
