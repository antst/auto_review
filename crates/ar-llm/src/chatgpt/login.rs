use crate::Error;

struct PendingLogin {
    state: String,
    client_id: Option<String>,
}

impl PendingLogin {
    fn parse_callback(&self, target: &str) -> Result<(String, String), Error> {
        let invalid = || Error::Authentication("invalid or declined OAuth callback".into());
        let url = url::Url::parse(&format!("http://127.0.0.1{target}")).map_err(|_| invalid())?;
        if url.path() != "/auth/callback" {
            return Err(invalid());
        }
        let mut values = std::collections::BTreeMap::new();
        for (key, value) in url.query_pairs() {
            if values
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return Err(invalid());
            }
        }
        if values.get("state") != Some(&self.state) {
            return Err(invalid());
        }
        if values.contains_key("error") {
            return Err(Error::AuthorizationDeclined);
        }
        let client = match (&self.client_id, values.get("client_id")) {
            (Some(expected), Some(actual)) if expected != actual => return Err(invalid()),
            (Some(expected), _) => expected.clone(),
            (None, Some(issued)) if issued != "dynamic_agent_client" && !issued.is_empty() => {
                issued.clone()
            }
            _ => return Err(invalid()),
        };
        let code = values
            .get("code")
            .filter(|s| !s.is_empty())
            .ok_or_else(invalid)?
            .clone();
        Ok((code, client))
    }
}

use super::auth::{auth_error, ChatGptAuth, Profile, TokenReply};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn random_secret() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

#[derive(serde::Deserialize)]
struct Identity {
    sub: String,
    nonce: String,
    email: Option<String>,
}

impl ChatGptAuth {
    /// Authorize one named profile. The callback listener is loopback-only;
    /// callers may print the URL or open it in the user's system browser.
    pub async fn login(
        &self,
        port: u16,
        consent: bool,
        show_url: impl FnOnce(&str),
    ) -> Result<(), Error> {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|_| auth_error("cannot bind loopback OAuth callback"))?;
        let redirect = format!(
            "http://127.0.0.1:{}/auth/callback",
            listener
                .local_addr()
                .map_err(|_| auth_error("callback address unavailable"))?
                .port()
        );
        let (host_id, client_id, subject, email) = {
            let _lock = self.lock().await?;
            let mut store = self.load()?;
            if store.host_id.is_empty() {
                store.host_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
                self.save(&store)?;
            }
            let p = store.profiles.get(&self.profile);
            (
                store.host_id.clone(),
                p.map(|p| p.client_id.clone()),
                p.map(|p| p.subject.clone()),
                p.and_then(|p| p.email.clone()),
            )
        };
        let pending = PendingLogin {
            state: random_secret(),
            client_id,
        };
        let nonce = random_secret();
        let verifier = random_secret();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut url = url::Url::parse(&format!("{}/api/accounts/authorize", self.issuer))
            .map_err(|_| auth_error("invalid OAuth issuer"))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair(
                "client_id",
                pending
                    .client_id
                    .as_deref()
                    .unwrap_or("dynamic_agent_client"),
            )
            .append_pair("ext_agent_host_id", &host_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &redirect)
            .append_pair(
                "scope",
                "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct",
            )
            .append_pair("resource", "https://api.openai.com/v1")
            .append_pair("state", &pending.state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &challenge);
            if pending.client_id.is_none() {
                q.append_pair("agent_name_hint", "auto_review");
            }
            if let Some(email) = &email {
                q.append_pair("login_hint", email);
            }
            if consent {
                q.append_pair("prompt", "consent");
            }
        }
        // No id_token_hint is included, so the displayed URL contains no tokens.
        show_url(url.as_str());
        let (code, issued_client) = tokio::time::timeout(Duration::from_secs(300), async {
            loop {
                let (mut socket, _) = listener.accept().await.map_err(|_| auth_error("OAuth callback failed"))?;
                let mut buffer = Vec::new();
                let read = tokio::time::timeout(Duration::from_secs(5), async {
                    while buffer.len() < 8192 {
                        let mut bytes = [0u8; 1024];
                        let n = socket.read(&mut bytes).await?;
                        if n == 0 { break; }
                        buffer.extend_from_slice(&bytes[..n]);
                        if buffer.windows(4).any(|s| s == b"\r\n\r\n") { break; }
                    }
                    Ok::<_, std::io::Error>(())
                }).await;
                let target = std::str::from_utf8(&buffer).ok().and_then(|s| s.lines().next())
                    .and_then(|s| s.strip_prefix("GET ")).and_then(|s| s.split_once(" HTTP/1.1")).map(|(target, _)| target);
                let result = if matches!(read, Ok(Ok(()))) {
                    target.ok_or_else(|| auth_error("invalid callback")).and_then(|target| pending.parse_callback(target))
                } else { Err(auth_error("invalid callback")) };
                let message = if result.is_ok() {
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nAuthorization received. Return to the terminal to confirm sign-in."
                } else {
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nAuthorization rejected. Return to the terminal."
                };
                let _ = tokio::time::timeout(Duration::from_secs(2), socket.write_all(message.as_bytes())).await;
                if result.is_ok() || matches!(result, Err(Error::AuthorizationDeclined)) { return result; }
                // Ignore unrelated localhost requests; the original attempt retains
                // its state and expires after five minutes.
            }
        }).await.map_err(|_| auth_error("sign-in timed out; run auth chatgpt login again"))??;
        let response = self
            .http
            .post(format!("{}/api/accounts/oauth/token", self.issuer))
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", issued_client.as_str()),
                ("code", code.as_str()),
                ("code_verifier", verifier.as_str()),
                ("redirect_uri", redirect.as_str()),
                ("resource", "https://api.openai.com/v1"),
            ])
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(auth_error(format!(
                "code exchange failed ({})",
                super::auth::oauth_error_code(response).await
            )));
        }
        let reply: TokenReply = response
            .json()
            .await
            .map_err(|_| auth_error("invalid token response"))?;
        let identity = self
            .validate_identity(
                reply
                    .id_token
                    .as_deref()
                    .ok_or_else(|| auth_error("missing ID token"))?,
                &issued_client,
                &nonce,
            )
            .await?;
        if subject.as_ref().is_some_and(|s| s != &identity.sub) {
            return Err(auth_error(
                "signed-in identity does not match the selected profile; use another --profile",
            ));
        }
        let tokens = reply.into_tokens(Vec::new(), None)?;
        let _lock = self.lock().await?;
        let mut store = self.load()?;
        if store.profiles.get(&self.profile).map(|p| &p.client_id) != pending.client_id.as_ref() {
            return Err(auth_error("profile changed during sign-in; retry"));
        }
        let previous = store.profiles.remove(&self.profile).unwrap_or_default();
        store.profiles.insert(
            self.profile.clone(),
            Profile {
                client_id: issued_client,
                subject: identity.sub,
                email: identity.email,
                tokens: Some(tokens),
                ..previous
            },
        );
        self.save(&store)
    }

    async fn validate_identity(
        &self,
        token: &str,
        client_id: &str,
        nonce: &str,
    ) -> Result<Identity, Error> {
        let header =
            jsonwebtoken::decode_header(token).map_err(|_| auth_error("invalid ID token"))?;
        if header.alg != jsonwebtoken::Algorithm::RS256 {
            return Err(auth_error("unsupported ID-token signing algorithm"));
        }
        let keys: jsonwebtoken::jwk::JwkSet = self
            .http
            .get(format!("{}/.well-known/jwks.json", self.issuer))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(|_| auth_error("invalid signing keys"))?;
        let jwk = header
            .kid
            .as_deref()
            .and_then(|kid| keys.find(kid))
            .ok_or_else(|| auth_error("ID-token signing key not found"))?;
        let key = jsonwebtoken::DecodingKey::from_jwk(jwk)
            .map_err(|_| auth_error("invalid signing key"))?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[client_id]);
        validation.set_issuer(&[&self.issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        let identity = jsonwebtoken::decode::<Identity>(token, &key, &validation)
            .map_err(|_| auth_error("ID-token signature or claims invalid"))?
            .claims;
        if identity.nonce != nonce || identity.sub.is_empty() {
            return Err(auth_error("ID-token nonce or identity invalid"));
        }
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn identity_validation_checks_signature_issuer_audience_expiry_and_nonce() {
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let (_dir, auth) =
            super::super::auth::tests::fixture(&server, super::super::auth::now() + 3600).await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::from_str::<serde_json::Value>(include_str!(
                        "../../tests/fixtures/oidc-test-jwks.json"
                    ))
                    .unwrap(),
                ),
            )
            .mount(&server)
            .await;
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../../tests/fixtures/oidc-test-private.pem"
        ))
        .unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("test-key".into());
        let claims = json!({"iss":server.uri(),"aud":"oaiapp_test", "sub":"user", "nonce":"random-nonce",
            "exp":super::super::auth::now()+3600});
        let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        assert_eq!(
            auth.validate_identity(&token, "oaiapp_test", "random-nonce")
                .await
                .unwrap()
                .sub,
            "user"
        );
        assert!(auth
            .validate_identity(&token, "oaiapp_test", "wrong-nonce")
            .await
            .is_err());
        for (field, value) in [
            ("iss", json!("https://other.example")),
            ("aud", json!("other-client")),
            ("exp", json!(1)),
        ] {
            let mut invalid = claims.clone();
            invalid[field] = value;
            let token = jsonwebtoken::encode(&header, &invalid, &key).unwrap();
            assert!(
                auth.validate_identity(&token, "oaiapp_test", "random-nonce")
                    .await
                    .is_err(),
                "{field}"
            );
        }
        let mut segments = token.split('.').map(str::to_owned).collect::<Vec<_>>();
        segments[2] = "AAAA".into();
        assert!(auth
            .validate_identity(&segments.join("."), "oaiapp_test", "random-nonce")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn login_exchanges_pkce_code_validates_identity_and_reuses_registration() {
        use serde_json::{json, Value};
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let mut auth = ChatGptAuth::new(
            dir.path().join("private/credentials.json"),
            "default".into(),
        )
        .unwrap();
        auth.issuer = server.uri();
        let seen = Arc::new(Mutex::new(Vec::<BTreeMap<String, String>>::new()));
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::from_str::<Value>(include_str!(
                        "../../tests/fixtures/oidc-test-jwks.json"
                    ))
                    .unwrap(),
                ),
            )
            .mount(&server)
            .await;
        let response_seen = seen.clone();
        let issuer = server.uri();
        Mock::given(method("POST")).and(path("/api/accounts/oauth/token"))
            .respond_with(move |request:&wiremock::Request| {
                let form = url::form_urlencoded::parse(&request.body).into_owned().collect::<BTreeMap<_,_>>();
                let seen = response_seen.lock().unwrap();let pending = seen.last().unwrap();
                assert_eq!(form["grant_type"],"authorization_code");
                assert_eq!(form["client_id"],"oaiapp_issued");
                assert_eq!(form["redirect_uri"],pending["redirect_uri"]);
                assert_eq!(form["resource"],"https://api.openai.com/v1");
                assert_eq!(URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes())),pending["code_challenge"]);
                let key = jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!("../../tests/fixtures/oidc-test-private.pem")).unwrap();
                let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);header.kid=Some("test-key".into());
                let id = jsonwebtoken::encode(&header,&json!({"iss":issuer,"aud":"oaiapp_issued","sub":"real-user",
                    "nonce":pending["nonce"],"exp":super::super::auth::now()+3600}),&key).unwrap();
                ResponseTemplate::new(200).set_body_json(json!({"access_token":"access-value","refresh_token":"refresh-value",
                    "id_token":id,"token_type":"Bearer","expires_in":3600,"scope":"openid chatgpt.tokens.use.direct"}))
            }).expect(2).mount(&server).await;
        for _ in 0..2 {
            let seen = seen.clone();
            auth.login(0, false, move |url| {
                let url = url::Url::parse(url).unwrap();
                let values = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
                let mut callback = url::Url::parse(&values["redirect_uri"]).unwrap();
                callback
                    .query_pairs_mut()
                    .append_pair("state", &values["state"])
                    .append_pair("code", "code-value")
                    .append_pair("client_id", "oaiapp_issued");
                seen.lock().unwrap().push(values);
                tokio::spawn(async move {
                    reqwest::get(callback).await.unwrap();
                });
            })
            .await
            .unwrap();
        }
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen[0]["client_id"], "dynamic_agent_client");
            assert_eq!(seen[1]["client_id"], "oaiapp_issued");
            assert_eq!(seen[0]["ext_agent_host_id"], seen[1]["ext_agent_host_id"]);
            assert_eq!(seen[0]["agent_name_hint"], "auto_review");
            assert!(!seen[1].contains_key("agent_name_hint"));
            assert_ne!(seen[0]["state"], seen[1]["state"]);
        }
        let status = serde_json::to_string(&auth.status().await.unwrap()).unwrap();
        assert!(!status.contains("access-value") && !status.contains("refresh-value"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&auth.path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn declined_oauth_callback_ends_attempt_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let auth = ChatGptAuth::new(
            dir.path().join("private/credentials.json"),
            "default".into(),
        )
        .unwrap();
        let login = auth.login(0, false, |url| {
            let url = url::Url::parse(url).unwrap();
            let values = url
                .query_pairs()
                .into_owned()
                .collect::<std::collections::BTreeMap<_, _>>();
            let mut callback = url::Url::parse(&values["redirect_uri"]).unwrap();
            callback
                .query_pairs_mut()
                .append_pair("state", &values["state"])
                .append_pair("error", "access_denied");
            tokio::spawn(async move {
                let _ = reqwest::get(callback).await;
            });
        });
        let result = tokio::time::timeout(Duration::from_secs(2), login).await;
        assert!(
            matches!(result, Ok(Err(_))),
            "declining consent must stop the attempt"
        );
    }

    #[test]
    fn callback_binds_code_to_state_and_issued_client() {
        let login = PendingLogin {
            state: "random-state".into(),
            client_id: Some("oaiapp_original".into()),
        };
        assert_eq!(
            login
                .parse_callback("/auth/callback?code=abc&state=random-state")
                .unwrap(),
            ("abc".into(), "oaiapp_original".into())
        );
        for target in [
            "/auth/callback?code=abc&state=wrong",
            "/auth/callback?code=abc&state=random-state&client_id=oaiapp_other",
            "/auth/callback?code=abc&state=random-state&state=wrong",
            "/wrong?code=abc&state=random-state",
            "/auth/callback?error=access_denied&state=random-state",
        ] {
            assert!(login.parse_callback(target).is_err(), "accepted {target}");
        }
    }
}
