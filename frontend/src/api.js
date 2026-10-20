import axios from "axios";

// Centralized API base URL. Override at build time with VITE_API_URL.
export const API_URL =
  import.meta.env.VITE_API_URL || "http://127.0.0.1:5000";

// ---- Auth token storage ----
const TOKEN_KEY = "socshield_token";
const ROLE_KEY = "socshield_role";
const USER_KEY = "socshield_user";

export function setAuth({ token, role, username }) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(ROLE_KEY, role || "");
  localStorage.setItem(USER_KEY, username || "");
}
export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(ROLE_KEY);
  localStorage.removeItem(USER_KEY);
}
export function getToken() { return localStorage.getItem(TOKEN_KEY); }
export function getRole() { return localStorage.getItem(ROLE_KEY); }
export function getUser() { return localStorage.getItem(USER_KEY); }
export function isAuthed() { return !!getToken(); }

// Attach the bearer token to every request.
axios.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// On 401, clear auth so the app shows the login screen again.
axios.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err?.response?.status === 401) clearAuth();
    return Promise.reject(err);
  }
);

export default axios;
