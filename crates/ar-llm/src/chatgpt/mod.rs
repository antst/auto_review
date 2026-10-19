//! ChatGPT plan usage through the public OAuth and Responses APIs.
mod auth;
mod login;
mod provider;
pub use auth::ChatGptAuth;
pub use provider::ChatGptProvider;

use crate::{Error, LlmProvider, OpenAiProvider};
use std::{path::Path, sync::Arc};

/// Explicit billing selection shared by all completion entrypoints.
pub enum CompletionAuth {
    ApiKey,
    ChatGpt(Arc<ChatGptAuth>, Option<String>),
}

impl CompletionAuth {
    pub fn from_settings(
        mode: &str,
        credentials: Option<&Path>,
        profile: &str,
        reasoning_effort: Option<&str>,
    ) -> Result<Self, Error> {
        match mode {
            "api_key" => Ok(Self::ApiKey),
            "chatgpt" => {
                let path = credentials.ok_or_else(|| {
                    Error::Authentication(
                        "LLM_CHATGPT_CREDENTIALS is required for chatgpt mode".into(),
                    )
                })?;
                Ok(Self::ChatGpt(
                    Arc::new(ChatGptAuth::new(path.to_path_buf(), profile.into())?),
                    reasoning_effort.map(str::to_owned),
                ))
            }
            _ => Err(Error::Authentication(
                "LLM_AUTH_MODE must be api_key or chatgpt".into(),
            )),
        }
    }

    /// Read-only selection for CLI entrypoints. Gateway startup passes its
    /// validated environment values to from_settings instead.
    pub fn from_env() -> Result<Self, Error> {
        let mode = std::env::var("LLM_AUTH_MODE").unwrap_or_else(|_| "api_key".into());
        let credentials = std::env::var_os("LLM_CHATGPT_CREDENTIALS").map(std::path::PathBuf::from);
        let profile = std::env::var("LLM_CHATGPT_PROFILE").unwrap_or_else(|_| "default".into());
        let effort = std::env::var("LLM_REASONING_EFFORT").ok();
        Self::from_settings(&mode, credentials.as_deref(), &profile, effort.as_deref())
    }

    pub fn provider(
        &self,
        base: &str,
        api_key: Option<&str>,
        model: &str,
    ) -> Result<Arc<dyn LlmProvider>, Error> {
        match self {
            Self::ApiKey => Ok(Arc::new(OpenAiProvider::new(base, api_key, model)?)),
            Self::ChatGpt(auth, effort) => {
                if base.trim_end_matches('/') != "https://api.openai.com" {
                    return Err(Error::Authentication(
                        "chatgpt mode requires LLM_BASE_URL=https://api.openai.com".into(),
                    ));
                }
                if api_key.is_some_and(|k| !k.trim().is_empty()) {
                    return Err(Error::Authentication("unset LLM_API_KEY in chatgpt mode; select api_key mode explicitly for API billing".into()));
                }
                Ok(Arc::new(
                    ChatGptProvider::new(auth.clone(), model.into())
                        .with_reasoning_effort(effort.as_deref())?,
                ))
            }
        }
    }

    pub fn uses_chatgpt(&self) -> bool {
        matches!(self, Self::ChatGpt(..))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn billing_mode_never_silently_falls_back() {
        assert!(CompletionAuth::from_settings("chatgpt", None, "default", None).is_err());
        assert!(CompletionAuth::from_settings("typo", None, "default", None).is_err());
    }
}
