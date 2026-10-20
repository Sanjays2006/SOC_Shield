# SOCShield — Security Notes

## Resolved during the rebuild

| Area | Before | After |
|------|--------|-------|
| Secrets | Telegram bot token, chat ID, WSL password committed in `app.py` / `README.md` | All secrets in env (`config.py`); `.env` git-ignored; `.env.example` has placeholders only |
| CORS | `CORS(app)` wildcard + `cors_allowed_origins="*"` | Restricted to `CORS_ORIGINS` allowlist |
| Debug | `debug=True` hard-coded | `FLASK_DEBUG` env, off by default |
| Command injection | `os.system(f'... {ip}')` and `subprocess.run(..., shell=True)` | Argument-list `subprocess.run(shell=False)` + strict IP validation |
| Auto-block | Always ran firewall rules | **Config-gated** by `ENABLE_AUTO_BLOCK` (off by default) |
| Error handling | Raw tracebacks + `str(e)` returned to clients | Generic messages to clients, full detail logged server-side; global error handler |
| Input validation | None | JSON body checks, `ObjectId` validation, `ipaddress`-based IP validation, pagination clamping |
| File upload | Saved raw `file.filename` (path traversal) | Sanitized basename + extension allowlist (`.pcap/.pcapng/.cap`) |
| LLM | n/a | Untrusted-input handling, prompt-injection defanging, no tools/execution, keys in env, deterministic fallback |

## 🔴 Action required by the operator
1. **Revoke** the previously-committed Telegram bot token in @BotFather; issue a new one.
2. **Change** the WSL/user password that was exposed in the old README.
3. If the repo has git history, **scrub** the secrets from past commits (e.g. `git filter-repo`).

## Operational hardening (recommended before any real deployment)
- Put the backend behind TLS (reverse proxy) and a production WSGI/ASGI server.
- Enable MongoDB authentication + network restrictions (`authSource`, firewall).
- [IMPLEMENTED] JWT authentication + role-based access control (viewer/analyst/admin)
  protects all data and state-changing endpoints. `/ingest` additionally accepts a
  service API key (X-API-Key) for the agent. Passwords are PBKDF2-hashed.
- Add rate limiting (e.g. Flask-Limiter) to public endpoints.
- Only run live traffic capture / IP blocking in explicitly authorized environments.

> This project has **not** undergone formal security testing. Do not treat
> it as production-secure without appropriate review and testing.
