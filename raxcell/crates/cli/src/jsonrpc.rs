use anyhow::Result;
use raxcell_core::{explain_backend, prepare_run, probe, resolve_profile, run};
use raxcell_protocol::{
    ExplainBackendRequest, ProbeRequest, RaxcellEvent, ResolveProfileRequest, RunRequest,
    RunResponse,
};
use serde_json::Value;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};

pub async fn run_worker() -> Result<()> {
    let stdin = BufReader::new(io::stdin());
    let mut lines = stdin.lines();
    let mut stdout = io::stdout();

    while let Some(line) = lines.next_line().await? {
        let response = handle_line(&line)?;
        stdout.write_all(response.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }
    Ok(())
}

pub fn handle_line(line: &str) -> Result<String> {
    let value: Value = serde_json::from_str(line)?;
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let request_id = id
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| id.to_string());
    let method = value.get("method").and_then(Value::as_str).unwrap_or("");
    let params = value.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "probe" => {
            let request: ProbeRequest = serde_json::from_value(params)?;
            serde_json::to_value(probe(request))?
        }
        "explainBackend" => {
            let request: ExplainBackendRequest = serde_json::from_value(params)?;
            serde_json::to_value(explain_backend(request))?
        }
        "run" => {
            let request: RunRequest = serde_json::from_value(params)?;
            run_payload(request_id, run(request))?
        }
        "prepareRun" => {
            let request: RunRequest = serde_json::from_value(params)?;
            serde_json::to_value(prepare_run(request))?
        }
        "resolveProfile" => {
            let request: ResolveProfileRequest = serde_json::from_value(params)?;
            serde_json::to_value(resolve_profile(request)?)?
        }
        _ => serde_json::json!({
            "error": {
                "code": "METHOD_NOT_FOUND",
                "message": format!("unknown method `{method}`")
            }
        }),
    };
    Ok(serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
    .to_string())
}

pub fn run_payload(request_id: String, result: RunResponse) -> Result<Value> {
    let mut events = vec![RaxcellEvent {
        kind: "raxcell.event.v1".to_string(),
        request_id: request_id.clone(),
        event: "run.started".to_string(),
        data: None,
    }];
    if let Some(policy_decision) = &result.policy_decision {
        events.push(RaxcellEvent {
            kind: "raxcell.event.v1".to_string(),
            request_id,
            event: "policy.decisionRequired".to_string(),
            data: Some(serde_json::to_string(policy_decision)?),
        });
    }
    Ok(serde_json::json!({
        "events": events,
        "result": result
    }))
}
