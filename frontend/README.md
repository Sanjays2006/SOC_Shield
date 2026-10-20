# SOCShield — Frontend (React + Vite)

React + Vite dashboard for the SOCShield SOC platform.

## Available plugins

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## Run the frontend

```bash
npm install
npm run dev
```

The dev server runs on http://127.0.0.1:5173 and talks to the backend on
http://127.0.0.1:5000.

---

## Running the full SOCShield stack

> ⚠️ **Secrets** are configured via environment variables only. Never commit a
> real `.env` file or paste tokens/passwords into this README. Copy
> `backend/.env.example` to `backend/.env` and fill in real values locally.

1. **MongoDB** — start the database first and keep it running:
   ```
   mongod --config <path-to>\mongod.cfg
   ```

2. **Backend** (WSL) — create/activate the virtualenv, install deps, run:
   ```bash
   cd <path-to>/SOCShield/backend
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env      # then edit .env with real values
   python3 app.py
   ```

3. **Agent** (WSL) — streams IDS events to the backend:
   ```bash
   cd <path-to>/SOCShield/agent
   python3 agent.py
   ```

4. **Suricata** (optional, live IDS):
   ```bash
   sudo systemctl status suricata
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0
   sudo tail -f /var/log/suricata/eve.json
   ```

5. **Frontend**:
   ```bash
   npm run dev
   ```

---

## Security note

A previous version of this repository committed a live Telegram bot token, a
chat ID, and a WSL password in plain text. Those credentials are considered
**compromised** and must be rotated:

- Revoke the old Telegram bot token in **@BotFather** and issue a new one.
- Change the WSL/user password that was exposed.
- Keep all secrets in `backend/.env` (git-ignored), never in source or docs.
