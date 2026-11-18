import type { LoginResponse } from "../api/types";

const CSRF_KEY = "oracle-hcm.csrf";
const USER_KEY = "oracle-hcm.user";

export const ROLE_ADMIN = "admin";

export interface SessionUser {
  user_id: string;
  role: string;
  tenant_id: string;
}

function storage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

/** Keep the session of the caller. The CSRF token never leaves the tab. */
export function saveSession(login: LoginResponse): SessionUser {
  const user: SessionUser = {
    user_id: login.user_id,
    role: login.role,
    tenant_id: login.tenant_id,
  };
  const store = storage();
  store?.setItem(CSRF_KEY, login.csrf_token);
  store?.setItem(USER_KEY, JSON.stringify(user));
  return user;
}

export function loadSession(): { user: SessionUser | null; csrf: string | null } {
  const store = storage();
  const csrf = store?.getItem(CSRF_KEY) ?? null;
  const raw = store?.getItem(USER_KEY) ?? null;
  if (raw === null) {
    return { user: null, csrf };
  }
  try {
    const parsed = JSON.parse(raw) as Partial<SessionUser>;
    if (typeof parsed.user_id !== "string" || typeof parsed.role !== "string") {
      return { user: null, csrf };
    }
    return {
      user: {
        user_id: parsed.user_id,
        role: parsed.role,
        tenant_id: typeof parsed.tenant_id === "string" ? parsed.tenant_id : "",
      },
      csrf,
    };
  } catch {
    return { user: null, csrf };
  }
}

export function clearSession(): void {
  const store = storage();
  store?.removeItem(CSRF_KEY);
  store?.removeItem(USER_KEY);
}
