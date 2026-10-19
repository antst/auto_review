use crate::Error;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(super) fn auth_error(message: impl Into<String>) -> Error {
    Error::Authentication(message.into())
}
fn storage_error(_: impl std::fmt::Display) -> Error {
    auth_error("credential storage unavailable; use a private writable directory")
}

#[derive(Clone)]
pub struct ChatGptAuth {
    pub(crate) path: PathBuf,
    pub(crate) profile: String,
    pub(crate) http: reqwest::Client,
    pub(crate) issuer: String,
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Store {
    pub(super) host_id: String,
    pub(super) profiles: BTreeMap<String, Profile>,
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Profile {
    pub(super) client_id: String,
    pub(super) subject: String,
    pub(super) email: Option<String>,
    pub(super) tokens: Option<Tokens>,
    pub(super) paused: bool,
    pub(super) retry_at: Option<u64>,
    #[serde(default)]
    pub(super) input_tokens: u64,
    #[serde(default)]
    pub(super) output_tokens: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Tokens {
    pub(super) access_token: String,
    pub(super) refresh_token: String,
    pub(super) id_token: Option<String>,
    pub(super) expires_at: u64,
    pub(super) scopes: Vec<String>,
}

impl ChatGptAuth {
    pub fn new(path: PathBuf, profile: String) -> Result<Self, Error> {
        Ok(Self {
            path,
            profile,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(60))
                .build()?,
            issuer: "https://auth.openai.com".into(),
        })
    }

    pub(super) async fn lock(&self) -> Result<File, Error> {
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| auth_error("use an absolute credential file path"))?;
        if !self.path.is_absolute() {
            return Err(auth_error("use an absolute credential file path"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(storage_error)?;
            if std::fs::metadata(parent)
                .map_err(storage_error)?
                .permissions()
                .mode()
                & 0o077
                != 0
            {
                return Err(auth_error(
                    "credential directory must have owner-only permissions (0700)",
                ));
            }
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600);
            self.acquire_lock(options).await
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(parent).map_err(storage_error)?;
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true).truncate(false);
            self.acquire_lock(options).await
        }
    }

    async fn acquire_lock(&self, options: OpenOptions) -> Result<File, Error> {
        let lock_path = self.path.with_extension("lock");
        for path in [&self.path, &lock_path] {
            if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(auth_error(
                    "credential and lock paths must not be symbolic links",
                ));
            }
        }
        let file = options.open(lock_path).map_err(storage_error)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(75);
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(file),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                Err(_) => return Err(auth_error("credential store is locked or unavailable")),
            }
        }
    }

    pub(super) fn load(&self) -> Result<Store, Error> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|_| auth_error("invalid credential store"))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
            Err(e) => Err(storage_error(e)),
        }
    }

    pub(super) fn save(&self, store: &Store) -> Result<(), Error> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| auth_error("missing credential directory"))?;
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(storage_error)?;
        // NamedTempFile uses 0600 on Unix, including before any token bytes are written.
        serde_json::to_writer(&mut temp, store).map_err(storage_error)?;
        temp.flush().map_err(storage_error)?;
        temp.as_file().sync_all().map_err(storage_error)?;
        temp.persist(&self.path).map_err(storage_error)?;
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) async fn pause(&self, retry_at: Option<u64>) -> Result<(), Error> {
        let _lock = self.lock().await?;
        let mut store = self.load()?;
        let p = store
            .profiles
            .get_mut(&self.profile)
            .ok_or_else(|| auth_error("profile not found"))?;
        // An indefinite subscription pause cannot be shortened by a later,
        // concurrently returned rate-limit response.
        p.retry_at = match (p.paused, p.retry_at, retry_at) {
            (true, None, _) | (_, _, None) => None,
            (true, Some(old), Some(new)) => Some(old.max(new)),
            (false, _, retry_at) => retry_at,
        };
        p.paused = true;
        self.save(&store)
    }

    /// Clear a local quota pause after the operator resolves the limit.
    pub async fn resume(&self) -> Result<(), Error> {
        let _lock = self.lock().await?;
        let mut store = self.load()?;
        let p = store
            .profiles
            .get_mut(&self.profile)
            .ok_or_else(|| auth_error("profile not found"))?;
        p.paused = false;
        p.retry_at = None;
        self.save(&store)
    }

    /// Non-secret local status. Token totals describe this app's completed
    /// requests, never a remaining subscription percentage or dollar charge.
    pub async fn status(&self) -> Result<Status, Error> {
        let _lock = self.lock().await?;
        let store = self.load()?;
        let p = store.profiles.get(&self.profile);
        let tokens = p.and_then(|p| p.tokens.as_ref());
        Ok(Status {
            profile: self.profile.clone(),
            email: p.and_then(|p| p.email.clone()),
            client_id: p.map(|p| p.client_id.clone()),
            signed_in: tokens.is_some(),
            expires_at: tokens.map(|t| t.expires_at),
            plan_usage_enabled: tokens
                .is_some_and(|t| t.scopes.iter().any(|s| s == "chatgpt.tokens.use.direct")),
            paused: p.is_some_and(|p| p.paused && p.retry_at.is_none_or(|t| t > now())),
            retry_at: p.and_then(|p| p.retry_at),
            input_tokens: p.map_or(0, |p| p.input_tokens),
            output_tokens: p.map_or(0, |p| p.output_tokens),
            manage_usage: "https://chatgpt.com/settings/usage",
        })
    }

    pub(crate) async fn record_usage(&self, input: u32, output: u32) -> Result<(), Error> {
        let _lock = self.lock().await?;
        let mut store = self.load()?;
        let p = store
            .profiles
            .get_mut(&self.profile)
            .ok_or_else(|| auth_error("profile not found"))?;
        p.input_tokens = p.input_tokens.saturating_add(input as u64);
        p.output_tokens = p.output_tokens.saturating_add(output as u64);
        self.save(&store)
    }

    /// Revoke before clearing tokens. Temporary failures keep credentials so
    /// the operator can retry and confirm revocation.
    pub async fn logout(&self) -> Result<(), Error> {
        let _lock = self.lock().await?;
        let mut store = self.load()?;
        let Some(p) = store.profiles.get_mut(&self.profile) else {
            return Ok(());
        };
        if let Some(tokens) = &p.tokens {
            let metadata: serde_json::Value = self
                .http
                .get(format!("{}/.well-known/openid-configuration", self.issuer))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await
                .map_err(|_| auth_error("invalid OpenID metadata"))?;
            let endpoint = metadata
                .get("revocation_endpoint")
                .and_then(|v| v.as_str())
                .ok_or_else(|| auth_error("revocation endpoint unavailable"))?;
            let endpoint =
                url::Url::parse(endpoint).map_err(|_| auth_error("invalid revocation endpoint"))?;
            let issuer = url::Url::parse(&self.issuer).map_err(|_| auth_error("invalid issuer"))?;
            if endpoint.origin() != issuer.origin() {
                return Err(auth_error("untrusted revocation endpoint"));
            }
            let response = self
                .http
                .post(endpoint)
                .form(&[
                    ("token", tokens.refresh_token.as_str()),
                    ("token_type_hint", "refresh_token"),
                    ("client_id", p.client_id.as_str()),
                ])
                .send()
                .await?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(auth_error("remote revocation was not confirmed; retry logout or disconnect the app in ChatGPT settings"));
            }
        }
        p.tokens = None;
        self.save(&store)
    }

    pub async fn models(&self) -> Result<serde_json::Value, Error> {
        let token = self.access_token().await?;
        let response = self
            .http
            .get("https://api.openai.com/v1/models")
            .bearer_auth(token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(auth_error("model catalog unavailable for this account"));
        }
        response
            .json()
            .await
            .map_err(|_| auth_error("invalid model catalog"))
    }

    pub(crate) async fn access_token(&self) -> Result<String, Error> {
        // Lock the stable sidecar, not the atomically replaced JSON inode. Re-read
        // under the cross-process lock so a rotating refresh token is used once.
        let _lock = self.lock().await?;
        let mut store = self.load()?;
        let profile = store
            .profiles
            .get_mut(&self.profile)
            .ok_or_else(|| auth_error("sign in with auth chatgpt login"))?;
        if profile.paused && profile.retry_at.is_none_or(|t| t > now()) {
            return Err(Error::SubscriptionLimit {
                retry_at: profile.retry_at,
            });
        }
        let tokens = profile
            .tokens
            .as_ref()
            .ok_or_else(|| auth_error("sign in with auth chatgpt login"))?;
        if !tokens
            .scopes
            .iter()
            .any(|s| s == "chatgpt.tokens.use.direct")
        {
            return Err(auth_error(
                "ChatGPT plan permission is disabled; sign in again to enable it",
            ));
        }
        if tokens.expires_at > now().saturating_add(60) {
            return Ok(tokens.access_token.clone());
        }
        let response = self
            .http
            .post(format!("{}/api/accounts/oauth/token", self.issuer))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", profile.client_id.as_str()),
                ("refresh_token", tokens.refresh_token.as_str()),
                ("resource", "https://api.openai.com/v1"),
            ])
            .send()
            .await?;
        if !response.status().is_success() {
            let code = oauth_error_code(response).await;
            if matches!(
                code.as_str(),
                "invalid_grant"
                    | "invalid_refresh_token"
                    | "token_expired"
                    | "refresh_token_expired"
                    | "refresh_token_invalidated"
                    | "refresh_token_reused"
            ) {
                profile.tokens = None;
                self.save(&store)?;
            }
            return Err(auth_error(format!(
                "token refresh failed ({code}); retry later or sign in again"
            )));
        }
        let reply: TokenReply = response
            .json()
            .await
            .map_err(|_| auth_error("invalid token refresh response"))?;
        let updated = reply.into_tokens(tokens.scopes.clone(), tokens.id_token.clone())?;
        let token = updated.access_token.clone();
        let enabled = updated
            .scopes
            .iter()
            .any(|s| s == "chatgpt.tokens.use.direct");
        profile.tokens = Some(updated);
        self.save(&store)?;
        if !enabled {
            return Err(auth_error(
                "ChatGPT plan permission was removed; sign in again to enable it",
            ));
        }
        Ok(token)
    }
}

#[derive(Serialize)]
pub struct Status {
    pub profile: String,
    pub email: Option<String>,
    pub client_id: Option<String>,
    pub signed_in: bool,
    pub expires_at: Option<u64>,
    pub plan_usage_enabled: bool,
    pub paused: bool,
    pub retry_at: Option<u64>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub manage_usage: &'static str,
}

#[derive(Deserialize)]
pub(super) struct TokenReply {
    pub(super) access_token: String,
    pub(super) refresh_token: String,
    pub(super) id_token: Option<String>,
    pub(super) token_type: String,
    pub(super) expires_in: u64,
    pub(super) scope: Option<String>,
}
impl TokenReply {
    pub(super) fn into_tokens(
        self,
        previous_scopes: Vec<String>,
        previous_id: Option<String>,
    ) -> Result<Tokens, Error> {
        if self.access_token.is_empty()
            || self.refresh_token.is_empty()
            || !self.token_type.eq_ignore_ascii_case("bearer")
            || self.expires_in == 0
        {
            return Err(auth_error("invalid token response"));
        }
        Ok(Tokens {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            id_token: self.id_token.or(previous_id),
            expires_at: now().saturating_add(self.expires_in),
            scopes: self
                .scope
                .map(|s| s.split_whitespace().map(str::to_owned).collect())
                .unwrap_or(previous_scopes),
        })
    }
}

pub(super) async fn oauth_error_code(response: reqwest::Response) -> String {
    let value = response
        .json::<serde_json::Value>()
        .await
        .unwrap_or_default();
    let code = value
        .get("error")
        .and_then(|e| {
            e.as_str()
                .or_else(|| e.get("code").and_then(|c| c.as_str()))
        })
        .unwrap_or("oauth_request_failed");
    // Never echo error_description or arbitrary provider bodies containing credentials.
    if code.len() <= 80
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        code.to_owned()
    } else {
        "oauth_request_failed".into()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub(crate) async fn fixture(
        server: &MockServer,
        expires_at: u64,
    ) -> (tempfile::TempDir, ChatGptAuth) {
        let dir = tempfile::tempdir().unwrap();
        let mut auth = ChatGptAuth::new(
            dir.path().join("private/credentials.json"),
            "default".into(),
        )
        .unwrap();
        auth.issuer = server.uri();
        drop(auth.lock().await.unwrap());
        let mut store = Store {
            host_id: "urn:uuid:test".into(),
            ..Default::default()
        };
        store.profiles.insert(
            "default".into(),
            Profile {
                client_id: "oaiapp_test".into(),
                subject: "user".into(),
                tokens: Some(Tokens {
                    access_token: "old".into(),
                    refresh_token: "refresh-old".into(),
                    id_token: None,
                    expires_at,
                    scopes: vec!["chatgpt.tokens.use.direct".into()],
                }),
                ..Default::default()
            },
        );
        auth.save(&store).unwrap();
        (dir, auth)
    }

    #[tokio::test]
    async fn subscription_pause_survives_restart_without_a_fabricated_reset() {
        let server = MockServer::start().await;
        let (_dir, auth) = fixture(&server, now() + 3600).await;
        auth.pause(None).await.unwrap();
        let restarted = ChatGptAuth::new(auth.path.clone(), "default".into()).unwrap();
        assert!(matches!(
            restarted.access_token().await,
            Err(Error::SubscriptionLimit { retry_at: None })
        ));
    }

    #[tokio::test]
    async fn concurrent_refresh_uses_rotating_token_once() {
        let server = MockServer::start().await;
        let (_dir, auth) = fixture(&server, 0).await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(50))
                    .set_body_json(
                        serde_json::json!({"access_token":"new", "refresh_token":"rotated",
                    "token_type":"Bearer", "expires_in":3600}),
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;
        let other = auth.clone();
        let (a, b) = tokio::join!(auth.access_token(), other.access_token());
        assert_eq!(a.unwrap(), "new");
        assert_eq!(b.unwrap(), "new");
    }

    #[tokio::test]
    async fn terminal_refresh_failure_clears_tokens_but_retains_registration() {
        let server = MockServer::start().await;
        let (_dir, auth) = fixture(&server, 0).await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(400)
            .set_body_json(serde_json::json!({"error":"invalid_grant", "error_description":"secret-refresh-token"})))
            .mount(&server).await;
        let error = auth.access_token().await.err().unwrap().to_string();
        assert!(!error.contains("secret-refresh-token"));
        let saved = auth.load().unwrap();
        assert!(saved.profiles["default"].tokens.is_none());
        assert_eq!(saved.profiles["default"].client_id, "oaiapp_test");
    }

    #[tokio::test]
    async fn temporary_refresh_failure_keeps_credentials_for_recovery() {
        let server = MockServer::start().await;
        let (_dir, auth) = fixture(&server, 0).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        assert!(auth.access_token().await.is_err());
        assert_eq!(
            auth.load().unwrap().profiles["default"]
                .tokens
                .as_ref()
                .unwrap()
                .refresh_token,
            "refresh-old"
        );
    }

    #[tokio::test]
    async fn reduced_refresh_scope_disables_inference_immediately() {
        let server = MockServer::start().await;
        let (_dir, auth) = fixture(&server, 0).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"access_token":"new", "refresh_token":"rotated",
                "token_type":"Bearer", "expires_in":3600, "scope":"openid profile"}),
            ))
            .mount(&server)
            .await;
        assert!(auth.access_token().await.is_err());
        assert!(!auth.status().await.unwrap().plan_usage_enabled);
    }

    #[tokio::test]
    async fn an_indefinite_quota_pause_is_not_shortened_by_concurrent_rate_limits() {
        let server = MockServer::start().await;
        let (_dir, auth) = fixture(&server, now() + 3600).await;
        auth.pause(None).await.unwrap();
        auth.pause(Some(now() + 300)).await.unwrap();
        assert_eq!(auth.status().await.unwrap().retry_at, None);
    }

    #[tokio::test]
    async fn expired_token_is_refreshed_and_rotation_is_persisted() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("private/credentials.json");
        let mut auth = ChatGptAuth::new(file.clone(), "default".into()).unwrap();
        auth.issuer = server.uri();
        drop(auth.lock().await.unwrap());
        std::fs::write(
            &file,
            serde_json::to_vec(&serde_json::json!({
                "host_id": "urn:uuid:test", "profiles": {"default": {
                    "client_id": "oaiapp_test", "subject": "user", "email": null,
                    "tokens": {"access_token": "old", "refresh_token": "refresh-old",
                        "id_token": null, "expires_at": 0,
                        "scopes": ["chatgpt.tokens.use.direct"]},
                    "paused": false, "retry_at": null
                }}
            }))
            .unwrap(),
        )
        .unwrap();
        Mock::given(method("POST"))
            .and(path("/api/accounts/oauth/token"))
            .and(body_string_contains("client_id=oaiapp_test"))
            .and(body_string_contains("refresh_token=refresh-old"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new", "refresh_token": "refresh-new",
                "token_type": "Bearer", "expires_in": 3600,
                "scope": "chatgpt.tokens.use.direct"
            })))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(auth.access_token().await.unwrap(), "new");
        let saved: Store = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        assert_eq!(
            saved.profiles["default"]
                .tokens
                .as_ref()
                .unwrap()
                .refresh_token,
            "refresh-new"
        );
    }
}
