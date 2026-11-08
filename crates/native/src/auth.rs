use crate::util::{Error, Result, digest_bytes};
use serde_json::{Value, json};
pub struct Identity {
    pub harness: String,
    pub identity_kind: String,
    pub principal: String,
    pub organization: Option<String>,
    pub workspace: Option<String>,
}

impl Identity {
    fn fingerprint(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&json!({
            "harness": self.harness,
            "identity_kind": self.identity_kind,
            "principal": self.principal,
            "organization": self.organization,
            "workspace": self.workspace,
        }))?;
        Ok(digest_bytes(&bytes))
    }
}

fn codex_identity(account: &Value) -> Result<Identity> {
    // account/read returns an envelope with `account` and routing metadata;
    // tolerate a flattened shape as well for compatible app-server versions.
    let account_details = account
        .get("account")
        .filter(|value| value.is_object())
        .unwrap_or(account);
    if account_details.get("type").and_then(Value::as_str) != Some("chatgpt") {
        return Err(Error::new(
            "Codex API-key authentication does not expose a verifiable user principal; account binding is unavailable",
        ));
    }
    let routing = account
        .get("workspaceRouting")
        .or_else(|| account_details.get("workspaceRouting"))
        .unwrap_or(&Value::Null);
    let principal = account_details
        .get("email")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| routing.get("chatgptAccountId").and_then(Value::as_str))
        .ok_or_else(|| Error::new("Codex account metadata has no verifiable account identifier"))?;
    Ok(Identity {
        harness: "codex".into(),
        identity_kind: account_details
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .into(),
        principal: principal.into(),
        organization: None,
        workspace: match (
            routing.get("chatgptAccountId").and_then(Value::as_str),
            routing.get("backendOrigin").and_then(Value::as_str),
        ) {
            (Some(id), Some(origin)) => Some(format!("{id}@{origin}")),
            (Some(id), None) => Some(id.to_owned()),
            (None, Some(origin)) => Some(origin.to_owned()),
            (None, None) => None,
        },
    })
}

// Open agy in the checkout interactively and review its prompt; ahu never
// approves native folder trust automatically.

fn normalize_rate_window(value: &Value) -> Option<(f64, u64, Option<u64>)> {
    let used = value.get("usedPercent")?.as_f64()?;
    if !used.is_finite() || !(0.0..=100.0).contains(&used) {
        return None;
    }
    let duration = value.get("windowDurationMins")?.as_u64()?;
    if duration == 0 || duration > 525_600 {
        return None;
    }
    let reset = match value.get("resetsAt") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_u64()?),
    };
    Some((used, duration, reset))
}

fn normalize_window(name: &str, (used, duration, reset): (f64, u64, Option<u64>)) -> Value {
    json!({
        "name": name,
        "used_percent": used,
        "remaining_percent": 100.0 - used,
        "window_duration_minutes": duration,
        "resets_at_unix": reset
    })
}

pub(crate) fn call(
    harness: &str,
    p: &crate::ProbeParams,
    budget: bool,
    _model: Option<&str>,
    _ollama_host: Option<&str>,
    requested_identity: Option<&str>,
) -> Result<Value> {
    if requested_identity
        .is_some_and(|id| id != harness && !(harness == "opencode" && id == "ollama"))
    {
        return Err(Error::invalid());
    }
    if budget {
        let (account, response) = crate::codex_metadata::read_budget(
            &p.native_executable,
            &p.project,
            &p.home,
            &p.environment,
        )?;
        let identity = codex_identity(&account)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::invalid())?
            .as_secs();
        let limits = response.get("rateLimits").unwrap_or(&response);
        let mut windows = Vec::new();
        let mut incomplete = false;
        for key in ["primary", "secondary"] {
            if let Some(raw) = limits.get(key).filter(|v| !v.is_null()) {
                match normalize_rate_window(raw) {
                    Some(values) if values.2.is_none_or(|reset| reset > now) => {
                        windows.push(normalize_window(key, values))
                    }
                    _ => incomplete = true,
                }
            }
        }
        if incomplete {
            windows.clear();
        }
        return Ok(
            json!({"status":if windows.is_empty(){"unknown"}else{"available"},"fingerprint":identity.fingerprint()?,"binding_harness":"codex","signal_type":if windows.is_empty(){"unknown"}else{"rate_windows"},"source":"codex_app_server","scope":"shared_account","observed_at_unix":now,"windows":windows}),
        );
    }

    let identity = match harness {
        "codex" => codex_identity(&crate::codex_metadata::read_account(
            &p.native_executable,
            &p.project,
            &p.home,
            &p.environment,
        )?)?,

        _ => return Err(Error::invalid()),
    };
    Ok(
        json!({"status":"available","binding_harness":identity.harness,"fingerprint":identity.fingerprint()?,"effective_provider_address_verified":harness!="opencode","identity_kind":identity.identity_kind}),
    )
}
