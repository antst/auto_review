use super::ChatGptAuth;
use crate::{CompleteRequest, CompleteResponse, Error, LlmProvider};
use async_trait::async_trait;
use std::sync::Arc;

pub struct ChatGptProvider {
    auth: Arc<ChatGptAuth>,
    model: String,
    endpoint: String,
}

impl ChatGptProvider {
    pub fn new(auth: Arc<ChatGptAuth>, model: String) -> Self {
        Self {
            auth,
            model,
            endpoint: "https://api.openai.com/v1/responses".into(),
        }
    }
}

use super::auth::now;
use crate::{ResponseFormat, Role};
use serde_json::{json, Value};
use std::time::{Duration, UNIX_EPOCH};

#[async_trait]
impl LlmProvider for ChatGptProvider {
    async fn complete(&self, req: CompleteRequest) -> Result<CompleteResponse, Error> {
        let mut body = json!({
            "model": self.model, "store": false, "stream": true,
            "input": req.messages.iter().map(|m| json!({
                "role": match m.role {Role::Assistant => "assistant", Role::User | Role::Tool => "user"},
                "content": m.content,
            })).collect::<Vec<_>>()
        });
        if let Some(instructions) = req.system {
            body["instructions"] = json!(instructions);
        }
        if let Some(ResponseFormat::JsonSchema { name, schema }) = req.response_format {
            body["text"] = json!({"format":{"type":"json_schema", "name":name, "schema":schema, "strict":true}});
        }
        // max_tokens and temperature are intentionally omitted: the plan route
        // rejects both, including their Responses API equivalents.
        for attempt in 0..3 {
            let token = self.auth.access_token().await?;
            let mut response = self
                .auth
                .http
                .post(&self.endpoint)
                .timeout(Duration::from_secs(300))
                .bearer_auth(token)
                .header("accept", "text/event-stream")
                .json(&body)
                .send()
                .await?;
            let status = response.status().as_u16();
            let retry_at = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(retry_time);
            let request_id = response
                .headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.chars().take(128).collect::<String>());
            if !response.status().is_success() {
                let bytes = limited_body(&mut response, 64 * 1024).await?;
                let value: Value = serde_json::from_slice(&bytes).unwrap_or_default();
                let code = value.pointer("/error/code").and_then(Value::as_str);
                if status == 429 || code == Some("subscription_sharing_usage_limit_exceeded") {
                    // Unknown subscription reset stays unknown. Ordinary rate
                    // limits without a server delay get a local 30-second cooldown.
                    let retry_at = if code == Some("subscription_sharing_usage_limit_exceeded") {
                        retry_at
                    } else {
                        retry_at.or(Some(now().saturating_add(30)))
                    };
                    self.auth.pause(retry_at).await?;
                    return Err(Error::SubscriptionLimit { retry_at });
                }
                // Only retry failures before the stream starts, with bounded
                // backoff. Never replay a stream that may have already run.
                if matches!(status, 502..=504) && attempt < 2 {
                    let delay = retry_at
                        .map(|t| t.saturating_sub(now()))
                        .unwrap_or(1 << attempt);
                    if delay <= 10 {
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                        continue;
                    }
                }
                return Err(provider_error(status, &value, request_id.as_deref()));
            }
            let result = self.read_stream(response, request_id.as_deref()).await?;
            self.auth
                .record_usage(result.input_tokens, result.output_tokens)
                .await?;
            return Ok(result);
        }
        Err(Error::Decode("ChatGPT request retries exhausted".into()))
    }

    fn provider_base_url(&self) -> String {
        // A separate billing identity prevents API price-table estimates from
        // being presented as subscription charges in the review footer.
        "chatgpt-plan".into()
    }
    fn completion_model_name(&self) -> String {
        self.model.clone()
    }
}

impl ChatGptProvider {
    async fn read_stream(
        &self,
        mut response: reqwest::Response,
        request_id: Option<&str>,
    ) -> Result<CompleteResponse, Error> {
        let mut buffer = Vec::new();
        let mut data = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            buffer.extend_from_slice(&chunk);
            if buffer.len() > 4 * 1024 * 1024 {
                return Err(Error::Decode("Responses event exceeds 4 MiB".into()));
            }
            while let Some(end) = buffer.iter().position(|b| *b == b'\n') {
                let mut line: Vec<u8> = buffer.drain(..=end).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.is_empty() && !data.is_empty() {
                    let event: Value = serde_json::from_slice(&data)
                        .map_err(|_| Error::Decode("invalid Responses event".into()))?;
                    data.clear();
                    match event.get("type").and_then(Value::as_str) {
                        Some("response.completed") => {
                            let r = &event["response"];
                            if r["status"] != "completed" {
                                return Err(Error::Decode(
                                    "Responses request did not complete".into(),
                                ));
                            }
                            let content = r["output"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter(|item| item["type"] == "message")
                                .flat_map(|item| item["content"].as_array().into_iter().flatten())
                                .filter(|part| part["type"] == "output_text")
                                .filter_map(|part| part["text"].as_str())
                                .collect::<String>();
                            if content.is_empty() {
                                return Err(Error::Decode(
                                    "Responses request completed without text".into(),
                                ));
                            }
                            return Ok(CompleteResponse {
                                content,
                                input_tokens: token_count(&r["usage"]["input_tokens"]),
                                output_tokens: token_count(&r["usage"]["output_tokens"]),
                            });
                        }
                        Some("response.failed" | "response.incomplete" | "error") => {
                            let error = event.get("response").unwrap_or(&event);
                            if error
                                .pointer("/error/code")
                                .or_else(|| error.get("code"))
                                .and_then(Value::as_str)
                                == Some("subscription_sharing_usage_limit_exceeded")
                            {
                                self.auth.pause(None).await?;
                                return Err(Error::SubscriptionLimit { retry_at: None });
                            }
                            return Err(provider_error(200, error, request_id));
                        }
                        _ => {}
                    }
                } else if let Some(value) = line.strip_prefix(b"data:") {
                    if !data.is_empty() {
                        data.push(b'\n');
                    }
                    data.extend_from_slice(value.strip_prefix(b" ").unwrap_or(value));
                    if data.len() > 4 * 1024 * 1024 {
                        return Err(Error::Decode("Responses event exceeds 4 MiB".into()));
                    }
                }
            }
        }
        Err(Error::Decode(
            "Responses stream ended before response.completed".into(),
        ))
    }
}

fn token_count(value: &Value) -> u32 {
    value.as_u64().unwrap_or(0).min(u32::MAX as u64) as u32
}
fn retry_time(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .map(|s| now().saturating_add(s))
        .or_else(|| {
            httpdate::parse_http_date(value)
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
        })
}
async fn limited_body(response: &mut reqwest::Response, cap: usize) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let remaining = cap.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..remaining.min(chunk.len())]);
        if body.len() == cap {
            break;
        }
    }
    Ok(body)
}
fn provider_error(status: u16, value: &Value, request_id: Option<&str>) -> Error {
    let text = value.to_string();
    let mut body = crate::openai::cap_for_error(&text);
    if let Some(id) = request_id {
        body.push_str(&format!(" (request ID: {id})"));
    }
    Error::Provider { status, body }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Message, ResponseFormat};
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn quota_error_stops_subsequent_requests_across_provider_instances() {
        let server = MockServer::start().await;
        let (_dir, auth) =
            super::super::auth::tests::fixture(&server, super::super::auth::now() + 3600).await;
        let auth = Arc::new(auth);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429).set_body_json(
                json!({"error":{"code":"subscription_sharing_usage_limit_exceeded"}}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        for _ in 0..2 {
            let mut provider = ChatGptProvider::new(auth.clone(), "account-model".into());
            provider.endpoint = format!("{}/v1/responses", server.uri());
            assert!(matches!(
                provider.complete(CompleteRequest::default()).await,
                Err(Error::SubscriptionLimit { retry_at: None })
            ));
        }
    }

    #[tokio::test]
    async fn disconnected_or_incomplete_stream_is_never_accepted_as_a_review() {
        let server = MockServer::start().await;
        let (_dir, auth) =
            super::super::auth::tests::fixture(&server, super::super::auth::now() + 3600).await;
        let mut provider = ChatGptProvider::new(Arc::new(auth), "account-model".into());
        provider.endpoint = format!("{}/v1/responses", server.uri());
        for body in [
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial review\"}\n\n",
            "data: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\"}}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"failed\"}}\n\n",
            "data: [DONE]\n\n",
        ] {
            server.reset().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .expect(1)
                .mount(&server)
                .await;
            assert!(provider.complete(CompleteRequest::default()).await.is_err());
        }
    }

    #[tokio::test]
    async fn top_level_stream_error_pauses_subscription_requests() {
        let server = MockServer::start().await;
        let (_dir, auth) =
            super::super::auth::tests::fixture(&server, super::super::auth::now() + 3600).await;
        let mut provider = ChatGptProvider::new(Arc::new(auth), "account-model".into());
        provider.endpoint = format!("{}/v1/responses", server.uri());
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(200)
            .set_body_string("data: {\"type\":\"error\",\"code\":\"subscription_sharing_usage_limit_exceeded\"}\n\n"))
            .mount(&server).await;
        assert!(matches!(
            provider.complete(CompleteRequest::default()).await,
            Err(Error::SubscriptionLimit { .. })
        ));
    }

    #[tokio::test]
    async fn quota_error_inside_stream_also_pauses_the_session() {
        let server = MockServer::start().await;
        let (_dir, auth) =
            super::super::auth::tests::fixture(&server, super::super::auth::now() + 3600).await;
        let auth = Arc::new(auth);
        let mut provider = ChatGptProvider::new(auth.clone(), "account-model".into());
        provider.endpoint = format!("{}/v1/responses", server.uri());
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(200)
            .set_body_string("data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"subscription_sharing_usage_limit_exceeded\"}}}\n\n"))
            .expect(1).mount(&server).await;
        assert!(matches!(
            provider.complete(CompleteRequest::default()).await,
            Err(Error::SubscriptionLimit { .. })
        ));
        assert!(auth.status().await.unwrap().paused);
    }

    #[tokio::test]
    async fn completion_uses_plan_responses_contract_and_records_actual_tokens() {
        let server = MockServer::start().await;
        let (_dir, auth) =
            super::super::auth::tests::fixture(&server, super::super::auth::now() + 3600).await;
        let auth = Arc::new(auth);
        let mut provider = ChatGptProvider::new(auth.clone(), "account-model".into());
        provider.endpoint = format!("{}/v1/responses", server.uri());
        let completed = json!({"type":"response.completed", "response": {
            "status":"completed", "output":[{"type":"message", "content":[{"type":"output_text","text":"{}"}]}],
            "usage":{"input_tokens":23,"output_tokens":7}
        }});
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .and(header("authorization", "Bearer old"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(format!("data: {completed}\n\n")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let result = provider
            .complete(CompleteRequest {
                system: Some("review carefully".into()),
                messages: vec![Message::user("diff")],
                max_tokens: Some(1024),
                temperature: Some(0.1),
                response_format: Some(ResponseFormat::JsonSchema {
                    name: "Review".into(),
                    schema: json!({"type":"object"}),
                }),
            })
            .await
            .unwrap();
        assert_eq!(result.content, "{}");
        assert_eq!((result.input_tokens, result.output_tokens), (23, 7));
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["store"], false);
        assert_eq!(body["stream"], true);
        assert_eq!(body["model"], "account-model");
        assert_eq!(body["instructions"], "review carefully");
        assert_eq!(body["input"], json!([{"role":"user","content":"diff"}]));
        assert_eq!(body["text"]["format"]["type"], "json_schema");
        for name in [
            "temperature",
            "max_tokens",
            "max_output_tokens",
            "previous_response_id",
        ] {
            assert!(body.get(name).is_none(), "unsupported parameter {name}");
        }
        let status = auth.status().await.unwrap();
        assert_eq!((status.input_tokens, status.output_tokens), (23, 7));
    }
}
