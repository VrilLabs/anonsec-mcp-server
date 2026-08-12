
### Summary

A MCP tool which connects to Firefox Relay to create random email addresses to effectively make the AI agent anonymous and harden OPSEC.

### Concepts

The AI agent has its own dedicated Firefox Relay account with agent mail resend or Cloudflare workers plus mail email addresses attached, which it can create anonymous forwarders  for on the fly.

Every Firefox Relay email that is generated is logged into a secure SQLite database which is PQC encrypted at rest and Includes (at least) columns for time, the Firefox Relay email and the email it forwards to.

The MCP tool includes a single source of truth in-database inbox where all emails forwarded by the Firefox Relay accumulate. 

The emails can be listed in a non-interactive CLI by the agent or user.

### Functionality 

- MCP tool includes `new_emails`, `read_emails`,  `all_emails` , `latest_email`, and `latest_email_otp` endpoints where `latest_email_otp` reads the latest email that was received in the inbox and cleanly returns any detected OTP as plaintext, allowing easier navigation for the agent in authenticated web browsing environments. 

- MCP tool also includes endpoints for sending emails (attachments forbidden for security): `send_anon_email` (accepts `to` and `from` addresses where `from`  must be a valid Firefox Relay email address, enforced by checking and validating the Firefox Relay sending `mozmail` domain exists).

### Security

- This MCP tool requires an API key to use, set as an environment variable: `AGENTANON_EMAIL_API_KEY`

- The user CLI essentially copies the MCP endpoints and also requires a valid `AGENTANON_EMAIL_API_KEY` to be present in the environment. It includes a function that the MCP does not to roll the upstream API key as a “kill switch” for enhanced safety and control.

- Provenance between subagents and main orchestrator agent calls to the MCP are delineated simply by observing their call history. 

### Development Guidance

- Instead of “reinventing the wheel”, existing Firefox Relay API packages, Firefox Relay SDK, and other associated already-made packages must be utilized.

- A dedicated agent SKILL.md for using the MCP tool must be created, which interlinks other necessary skills (such as Resend’s [agent-email-inbox](https://github.com/resend/resend-skills/tree/main/skills/agent-email-inbox) skill).

**Note:** Always check the official Firefox Relay documentation to ensure precision-correctness and alignment with any potential updates to the API surface itself. This goes for the mailing APIs as well. 

### Open Questions

- Should this be released open-source or utilized internally and released to the public as a purchasable-token-gated application (user paying for actual AI inference and the underlying functionality afforded) where they must have tokens in their in-app wallet to pass commands? With this route, the agent is served in a cloud run container, and this way, we can also include an Apple Shortcut so commands can be issued by users on-the-fly. 
	- The result is that you could literally ask Siri to send email anonymously/privately, read emails and even ask for the latest OTP code that was received. 
	- Great idea but must be checked against Apple’s App Store guidelines.

___

### References

- [Firefox Relay](https://relay.firefox.com/)
- [Technical | Firefox Relay Help - Mozilla Support](https://support.mozilla.org/en-US/products/relay/technical](https://support.mozilla.org/en-US/products/relay/technical)
- [https://relay.firefox.com/api/v1/runtime\_data](https://relay.firefox.com/api/v1/runtime_data)
- [ffrelay\_api - Rust](https://docs.rs/ffrelay-api/latest/ffrelay_api/index.html)
- [Firefox Relay API - Developer docs, APIs, SDKs, and auth. \| API Tracker](https://apitracker.io/a/firefox-relay)
- [GitHub - mozilla/fx-private-relay: Keep your email safe from hackers and trackers. Make an email alias with 1 click, and keep your address to yourself. · GitHub](https://github.com/mozilla/fx-private-relay)
- [GitHub - leo-proger/firefox-relay-api: Unoffical API for Firefox Relay · GitHub](https://github.com/leo-proger/firefox-relay-api)
- [GitHub - cloudflare/agentic-inbox: A self-hosted email client with an AI agent, running entirely on Cloudflare Workers · GitHub](https://github.com/cloudflare/agentic-inbox)
- [AgentMail \| Email Inbox API for AI Agents](https://www.agentmail.to/)
- [Agent Email Inbox Skill - Resend](https://resend.com/docs/agent-email-inbox-skill)
- [Email for agents · Resend](https://resend.com/agents)
- [resend-skills/skills/agent-email-inbox at main · resend/resend-skills · GitHub](https://github.com/resend/resend-skills/tree/main/skills/agent-email-inbox)