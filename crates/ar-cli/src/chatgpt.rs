//! Operator-only ChatGPT authentication; no gateway OAuth routes.
use crate::cli::{ChatGptArgs, ChatGptCommand};
use anyhow::{Context, Result};
use ar_llm::chatgpt::ChatGptAuth;

fn auth(args: ChatGptArgs) -> Result<ChatGptAuth> {
    let path = match args.credentials {
        Some(path) => path,
        None => {
            let root = std::env::var_os("XDG_CONFIG_HOME")
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".config"))
                })
                .context("set --credentials or LLM_CHATGPT_CREDENTIALS")?;
            root.join("auto_review/chatgpt/credentials.json")
        }
    };
    Ok(ChatGptAuth::new(path, args.profile)?)
}

pub async fn run(command: ChatGptCommand) -> Result<()> {
    match command {
        ChatGptCommand::Login(args) => {
            let auth = auth(args.connection)?;
            auth.login(args.port, args.consent, |url| {
                println!("Continue with ChatGPT by opening this URL in your browser:\n{url}\n\nWaiting for the loopback callback (five-minute timeout)...");
            }).await?;
            if !auth.status().await?.plan_usage_enabled {
                anyhow::bail!("Signed in, but ChatGPT plan usage was not granted. Run auth chatgpt login --consent to enable it, or explicitly select LLM_AUTH_MODE=api_key.");
            }
            println!(
                "You're using your ChatGPT plan. Manage usage: https://chatgpt.com/settings/usage"
            );
        }
        ChatGptCommand::Status(args) => println!(
            "{}",
            serde_json::to_string_pretty(&auth(args)?.status().await?)?
        ),
        ChatGptCommand::Models(args) => println!(
            "{}",
            serde_json::to_string_pretty(&auth(args)?.models().await?)?
        ),
        ChatGptCommand::Logout(args) => {
            auth(args)?.logout().await?;
            println!("Signed out. Registration and host identity retained for future sign-in.");
        }
        ChatGptCommand::Resume(args) => {
            auth(args)?.resume().await?;
            println!("Local request pause cleared. The next request will check availability; manage usage: https://chatgpt.com/settings/usage");
        }
    }
    Ok(())
}
