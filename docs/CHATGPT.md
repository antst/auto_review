# ChatGPT subscription authentication

This fork can use an eligible ChatGPT plan for review, verification, and chat
completion requests. It uses OpenAI's public Sign in with ChatGPT flow and
`POST https://api.openai.com/v1/responses`. It does not import Codex's cached
credentials or use ChatGPT's private backend endpoints.

## Sign in on the reviewer host

Create a dedicated private credential directory and select the same file for
the CLI and service:

```sh
install -d -m 700 "$HOME/.config/auto_review/chatgpt"
export LLM_CHATGPT_CREDENTIALS="$HOME/.config/auto_review/chatgpt/credentials.json"
export LLM_CHATGPT_PROFILE=default
auto-review auth chatgpt login
```

Open the displayed authorization URL in your browser. For a remote reviewer,
first forward the callback port from your workstation:

```sh
ssh -L 1455:127.0.0.1:1455 user@reviewer-host
```

Run the sign-in command in that SSH session. The callback binds only to
`127.0.0.1`; no gateway OAuth endpoint is exposed. `--port` changes the callback
port. `--consent` explicitly requests permission again if plan usage was declined.
Each `--profile NAME` retains a separate account/workspace registration. Reusing
a profile reuses its issued client ID and stable host ID, and validates the
returned account before replacing credentials.

Only the operator should access the credential directory. Tokens are saved
atomically with mode 0600, and the directory must have mode 0700. Mount the
whole directory writable for a container, rather than mounting just the JSON
file: refresh rotates that file and uses a persistent sidecar lock.

## Configure completion tiers

```sh
LLM_AUTH_MODE=chatgpt
LLM_BASE_URL=https://api.openai.com
LLM_CHATGPT_CREDENTIALS=/absolute/private/chatgpt/credentials.json
LLM_CHATGPT_PROFILE=default
# Choose an available slug from `auto-review auth chatgpt models`:
LLM_REASONING_MODEL=<account-model-slug>
# Optional verifier/chat tier, using the same subscription profile:
LLM_CHEAP_MODEL=<account-model-slug>
```

Unset `LLM_API_KEY` and `LLM_CHEAP_API_KEY` in this mode. Selecting API billing
requires an explicit `LLM_AUTH_MODE=api_key` (the existing default). The same
selection applies to the gateway, `review once`, `bench run`, and AgentCore.
The packaged gateway adds a writable directory bind mount for the selected
credential store. Custom containers must provide their own directory mount.

ChatGPT plan usage does not supply embeddings. Leave `LLM_EMBEDDING_MODEL`
unset, or configure a separate `LLM_EMBEDDING_BASE_URL` and, if required,
`LLM_EMBEDDING_API_KEY`. This is a separately configured provider/billing path.
The plan route rejects sampling and output-token-limit parameters, so this
provider omits `temperature`, `max_tokens`, and `max_output_tokens`.

## Refresh, usage, and recovery

Access tokens refresh near expiry. The credential sidecar lock serializes
refreshes across tiers and processes; credentials are reread under the lock and
rotated tokens are persisted together. Temporary network/server failures retain
the session. Terminal refresh errors clear unusable tokens while retaining the
client/account mapping for the next sign-in.

```sh
auto-review auth chatgpt status
auto-review auth chatgpt models
auto-review auth chatgpt resume
auto-review auth chatgpt logout
```

`status` prints account information, expiry, local completed-request token totals,
and any request pause. It never prints access, refresh, or ID tokens. Those
local totals are not a remaining plan allowance or a percentage. Review footers
label subscription usage and exclude it from API dollar estimates.

A subscription-limit error pauses new requests for that profile, including
across service restarts. If the server provides `Retry-After`, requests become
eligible after that time; the service does not automatically replay failed PR
reviews. Without a server delay, a subscription pause remains until an operator
runs `resume`. Review the applicable plan/app limit in
[ChatGPT Settings → Usage](https://chatgpt.com/settings/usage), then resume and
request a new review. Ordinary rate limits without a server delay use a local
30-second cooldown; this is not a claimed subscription reset time. Requests
already in flight may still finish.

Pre-stream temporary server failures use bounded backoff. Partial, failed, and
incomplete streams are rejected and never posted as successful review results.
The service never switches to API-key billing after a plan error. `logout`
attempts remote session revocation before removing local tokens; if revocation
cannot be confirmed, it retains credentials and reports the failure for retry.

Official integration references: [registration](https://developers.openai.com/siwc/token-sharing-open-source/sign-in),
[refresh and sessions](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions),
[request requirements](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference),
[errors and recovery](https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery),
and [preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations).
