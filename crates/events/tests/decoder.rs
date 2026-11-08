use ahu_harness_events::Decoder;
use serde_json::{Value, json};

fn feed(decoder: &mut Decoder, event: Value) -> Value {
    decoder
        .observe_stdout(&serde_json::to_vec(&event).unwrap())
        .unwrap()
}

#[test]
fn selected_provider_keeps_terminal_summary_and_unknown_usage_separate() {
    let fixtures = [
        (
            "codex",
            vec![
                json!({"type":"item.completed","item":{"type":"agent_message","text":"answer"}}),
                json!({"type":"turn.completed"}),
            ],
        ),
        (
            "claude-code",
            vec![json!({"type":"result","subtype":"success","is_error":false,"result":"answer"})],
        ),
        (
            "antigravity",
            vec![json!({"type":"result","result":{"status":"success","response":"answer"}})],
        ),
        (
            "opencode",
            vec![
                json!({"type":"text","part":{"text":"answer"}}),
                json!({"type":"step_finish","part":{"id":"end","reason":"stop"}}),
            ],
        ),
        (
            "kiro",
            vec![
                json!({"type":"runStarted","data":{"engine":"v3","payloadSchema":"acp","acpProtocolVersion":1}}),
                json!({"type":"runFinished","data":{"sessionId":"sess_synthetic","status":"success","stopReason":"end_turn","finalText":"answer","finalTextTruncated":false}}),
            ],
        ),
    ];
    for (harness, events) in fixtures
        .into_iter()
        .filter(|(harness, _)| *harness == "codex")
    {
        let mut decoder = Decoder::new(harness).unwrap();
        for event in events {
            feed(&mut decoder, event);
        }
        let result = decoder.finish().unwrap();
        assert_eq!(result["terminal"], true, "{harness}");
        assert_eq!(result["failed"], false, "{harness}: {result}");
        assert_eq!(result["summary"], "answer");
        assert!(result["usage"]["total"].is_null());
        assert!(result["cost"].get("usd").is_none());
        assert_eq!(decoder.finish().unwrap(), result);
    }
    assert!(Decoder::new("invented").is_err());
}

#[test]
fn malformed_input_is_sticky_and_errors_never_echo_native_data() {
    for line in [b"PRIVATE INVALID".as_slice(), b"null", b"[]", b"{", b"\xff"] {
        let mut decoder = Decoder::new("codex").unwrap();
        let error = decoder.observe_stdout(line).unwrap_err();
        assert!(!error.to_string().contains("PRIVATE"));
        feed(&mut decoder, json!({"type":"turn.completed"}));
        let result = decoder.finish().unwrap();
        assert_eq!(result["failed"], true);
        assert_eq!(result["trajectory"]["malformed_events"], 1);
        assert_eq!(result["native_completeness"]["complete"], false);
    }
}

#[test]
fn session_drift_invalid_values_and_alias_conflicts_are_failures() {
    for value in [
        json!("other"),
        json!(42),
        json!("bad\nidentity"),
        Value::Null,
    ] {
        let mut decoder = Decoder::new("codex").unwrap();
        feed(
            &mut decoder,
            json!({"type":"thread.started","thread_id":"first"}),
        );
        let result = feed(
            &mut decoder,
            json!({"type":"turn.completed","thread_id":value}),
        );
        assert_eq!(result["failed"], true);
        assert_eq!(result["session"], "first");
    }
    let mut decoder = Decoder::new("codex").unwrap();
    assert_eq!(
        feed(
            &mut decoder,
            json!({"type":"thread.started","thread_id":"one","session_id":"two"})
        )["failed"],
        true
    );
}

#[test]
fn mixed_stderr_keeps_only_classifications_and_late_failure() {
    let mut decoder = Decoder::new("codex").unwrap();
    feed(&mut decoder, json!({"type":"turn.completed"}));
    for _ in 0..100 {
        decoder
            .observe_stderr(b"PRIVATE permission denied")
            .unwrap();
    }
    decoder
        .observe_stderr(b"PRIVATE unknown diagnostic")
        .unwrap();
    decoder.observe_stderr(b"PRIVATE invalid_api_key").unwrap();
    decoder
        .observe_stderr(b"PRIVATE resource_exhausted")
        .unwrap();
    let result = decoder.finish().unwrap();
    assert_eq!(result["failed"], true);
    assert_eq!(result["stderr_unclassified_lines"], 1);
    assert_eq!(result["stderr_diagnostics"].as_array().unwrap().len(), 3);
    assert!(!result.to_string().contains("PRIVATE"));
    assert!(decoder.observe_stdout(b"{}").is_err());
    assert!(decoder.observe_stderr(b"extra").is_err());
}

#[test]
fn duplicate_terminals_and_unknown_events_remain_visible() {
    let mut decoder = Decoder::new("codex").unwrap();
    feed(
        &mut decoder,
        json!({"type":"future-event","payload":"PRIVATE"}),
    );
    feed(&mut decoder, json!({"type":"turn.completed"}));
    feed(&mut decoder, json!({"type":"turn.completed"}));
    let result = decoder.finish().unwrap();
    assert_eq!(result["unknown_events"], 1);
    assert_eq!(result["failed"], true);
    assert!(!result.to_string().contains("PRIVATE"));
}

#[test]
fn finalization_without_native_completion_leaves_acceptance_to_core() {
    let mut decoder = Decoder::new("codex").unwrap();
    feed(
        &mut decoder,
        json!({"type":"thread.started","thread_id":"fixture"}),
    );
    let final_state = decoder.finish().unwrap();
    assert_eq!(final_state["finished"], true);
    assert_eq!(final_state["terminal"], false);
    assert_eq!(final_state["failed"], false);
    assert!(decoder.observe_stdout(b"{}").is_err());
}

#[test]
fn usage_keeps_independent_maxima_across_native_envelopes() {
    let mut decoder = Decoder::new("codex").unwrap();
    feed(
        &mut decoder,
        json!({"type":"item.started","usage":{
            "input_tokens":20,"output_tokens":2,"cached_input_tokens":7,
            "cache_creation_input_tokens":3,"thinking_tokens":2,"total_tokens":22
        }}),
    );
    for path in [
        "part/usage",
        "result/usage",
        "response/usage",
        "step_update/usage",
        "result/result/usage",
        "step_update/tool_info/usage",
        "tokens",
        "part/tokens",
    ] {
        let usage = json!({"prompt_tokens":10,"completion_tokens":9,
            "cache":{"read":5,"write":8},"reasoning":4,"total_tokens":19});
        let nested = path
            .split('/')
            .rev()
            .fold(usage, |value, key| json!({key:value}));
        let mut event = json!({"type":"item.started"});
        event
            .as_object_mut()
            .unwrap()
            .extend(nested.as_object().unwrap().clone());
        feed(&mut decoder, event);
    }
    assert_eq!(
        decoder.snapshot()["usage"],
        json!({"input":20,"output":9,"cached":7,
        "cache_write":8,"reasoning":4,"total":22})
    );
}
