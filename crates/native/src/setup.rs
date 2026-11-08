//! Proposed edits only. The host owns conflict-checked publication.
use crate::{Error, Result, files, util::digest_bytes};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    project: PathBuf,
    home: PathBuf,
    ahu_executable: PathBuf,
    skills: Vec<Skill>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Skill {
    name: String,
    text: String,
}
const FORWARD: &[&str] = &[
    "AHU_TASK_ID",
    "AHU_TASK_DIR",
    "AHU_EVAL_OTEL_ENDPOINT",
    "AHU_MCP_RESOURCE_ATTRIBUTES",
    "OTEL_RESOURCE_ATTRIBUTES",
];
fn proposal(path: &Path, before: Option<&[u8]>, text: String) -> Result<Value> {
    if text.len() > files::LIMIT {
        return Err(Error::invalid());
    }
    Ok(json!({"path":path,"expected_before_sha256":before.map(digest_bytes),"text":text}))
}
pub(crate) fn call(harness: &str, params: &Value) -> Result<Value> {
    let p: Params = crate::decode(params)?;
    crate::directory(&p.project)?;
    crate::directory(&p.home)?;
    if !p.ahu_executable.is_absolute() || !p.ahu_executable.is_file() || p.skills.len() > 128 {
        return Err(Error::invalid());
    }
    let mut changes = Vec::new();
    let (path, key) = match harness {
        "codex" => (p.project.join(".codex/config.toml"), "mcp_servers"),

        _ => return Err(Error::invalid()),
    };
    files::private_scope(&p.project, &path)?;
    let before = files::read(&path)?;
    let after = {
        let text = std::str::from_utf8(before.as_deref().unwrap_or_default())
            .map_err(|_| Error::invalid())?;
        let mut doc = text
            .parse::<toml_edit::DocumentMut>()
            .map_err(|_| Error::invalid())?;
        let servers = doc
            .entry(key)
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()))
            .as_table_like_mut()
            .ok_or_else(Error::invalid)?;
        let server = servers
            .entry("ahu")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()))
            .as_table_like_mut()
            .ok_or_else(Error::invalid)?;
        let executable = p.ahu_executable.to_str().ok_or_else(Error::invalid)?;
        if server.is_empty() {
            server.insert("command", toml_edit::value(executable));
            server.insert(
                "args",
                toml_edit::value(["mcp", "serve"].into_iter().collect::<toml_edit::Array>()),
            );
        } else if server.get("command").and_then(toml_edit::Item::as_str) != Some(executable)
            || server
                .get("args")
                .and_then(toml_edit::Item::as_array)
                .map(|a| a.iter().map(toml_edit::Value::as_str).collect::<Vec<_>>())
                != Some(vec![Some("mcp"), Some("serve")])
            || server.contains_key("url")
            || server
                .get("enabled")
                .is_some_and(|v| v.as_bool() != Some(true))
        {
            return Err(Error::invalid());
        }
        let env = server
            .entry("env_vars")
            .or_insert(toml_edit::value(toml_edit::Array::new()))
            .as_array_mut()
            .ok_or_else(Error::invalid)?;
        if env.iter().any(|v| v.as_str().is_none()) {
            return Err(Error::invalid());
        }
        for name in FORWARD {
            if !env.iter().any(|v| v.as_str() == Some(name)) {
                env.push(*name);
            }
        }
        let tools = server
            .entry("tools")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()))
            .as_table_like_mut()
            .ok_or_else(Error::invalid)?;
        for tool in [
            "ahu_agents_list",
            "ahu_tasks_list",
            "ahu_task_get",
            "ahu_request_approval",
        ] {
            if let Some(existing) = tools.get(tool) {
                if existing.as_table_like().is_none() {
                    return Err(Error::invalid());
                }
            } else {
                let mut entry = toml_edit::Table::new();
                entry.insert("approval_mode", toml_edit::value("approve"));
                tools.insert(tool, toml_edit::Item::Table(entry));
            }
        }
        doc.to_string()
    };
    if before.as_deref() != Some(after.as_bytes()) {
        changes.push(proposal(&path, before.as_deref(), after)?);
    }
    let mut names = std::collections::BTreeSet::new();
    for skill in p.skills {
        if skill.name.is_empty()
            || skill.name.len() > 128
            || !skill
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || !names.insert(skill.name.clone())
            || skill.text.len() > files::LIMIT
        {
            return Err(Error::invalid());
        }
        let roots: &[&str] = &[".agents/skills"];
        for root in roots {
            let path = p.project.join(root).join(&skill.name).join("SKILL.md");
            files::private_scope(&p.project, &path)?;
            let before = files::read(&path)?;
            if let Some(bytes) = before.as_deref() {
                if bytes != skill.text.as_bytes() {
                    return Err(Error::invalid());
                }
            } else {
                changes.push(proposal(&path, None, skill.text.clone())?);
            }
        }
    }
    if serde_json::to_vec(&changes)?.len() > 4 * files::LIMIT {
        return Err(Error::invalid());
    }
    Ok(json!({"changes":changes,"publication":"host_transaction_required"}))
}
