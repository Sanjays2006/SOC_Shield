import { useState } from "react";
import axios, { API_URL, setAuth } from "../api";

// Login + first-user bootstrap screen.
export default function Login({ onAuthed }) {
  const [mode, setMode] = useState("login"); // 'login' | 'register'
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "login") {
        const res = await axios.post(`${API_URL}/auth/login`, { username, password });
        setAuth(res.data);
        onAuthed(res.data);
      } else {
        await axios.post(`${API_URL}/auth/register`, { username, password });
        // Auto-login after bootstrap registration.
        const res = await axios.post(`${API_URL}/auth/login`, { username, password });
        setAuth(res.data);
        onAuthed(res.data);
      }
    } catch (err) {
      setError(err?.response?.data?.error || "Request failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={submit}>
        <h2>🛡 SOCShield</h2>
        <p className="login-sub">
          {mode === "login" ? "Sign in to continue" : "Create the first admin account"}
        </p>

        <input
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoFocus
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        {error && <div className="error-banner">{error}</div>}

        <button type="submit" disabled={busy}>
          {busy ? "…" : mode === "login" ? "Sign In" : "Create Account"}
        </button>

        <div className="login-toggle">
          {mode === "login" ? (
            <span>
              First time?{" "}
              <a onClick={() => { setMode("register"); setError(null); }}>
                Bootstrap admin
              </a>
            </span>
          ) : (
            <span>
              Have an account?{" "}
              <a onClick={() => { setMode("login"); setError(null); }}>Sign in</a>
            </span>
          )}
        </div>
      </form>
    </div>
  );
}
