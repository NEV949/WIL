import { render, type RenderResult } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "../auth/AuthProvider";

export type Role = "admin" | "user";

export const CSRF_TOKEN = "the-csrf-token-of-the-session";

/** Open a session of the console, as the gateway would. */
export function openSession(role: Role = "admin"): void {
  window.sessionStorage.setItem("oracle-hcm.csrf", CSRF_TOKEN);
  window.sessionStorage.setItem(
    "oracle-hcm.user",
    JSON.stringify({ user_id: "tester", role, tenant_id: "t1" }),
  );
}

export function renderWithSession(
  element: ReactElement,
  options: { path?: string; role?: Role } = {},
): RenderResult {
  openSession(options.role ?? "admin");
  return render(
    <MemoryRouter initialEntries={[options.path ?? "/"]}>
      <AuthProvider>{element}</AuthProvider>
    </MemoryRouter>,
  );
}
