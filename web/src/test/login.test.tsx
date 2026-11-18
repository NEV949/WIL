import { MemoryRouter } from "react-router-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { LoginPage } from "../pages/LoginPage";
import { AuthProvider } from "../auth/AuthProvider";
import { ApiError, api, setCsrfToken } from "../api/client";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, api: { ...actual.api, login: vi.fn() } };
});

const login = vi.mocked(api.login);

function answer(): void {
  login.mockResolvedValue({
    user_id: "admin",
    role: "admin",
    tenant_id: "t1",
    csrf_token: "the-csrf-token",
    expires_at: "2026-11-17T10:00:00+00:00",
  });
}

describe("the login", () => {
  it("opens the session and keeps the token out of the local storage", async () => {
    answer();
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>,
    );

    await user.type(screen.getByLabelText("User"), "admin");
    await user.type(screen.getByLabelText("Password"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => {
      expect(login).toHaveBeenCalledWith("admin", "correct horse battery staple");
    });
    await waitFor(() => {
      expect(window.sessionStorage.getItem("oracle-hcm.csrf")).toBe("the-csrf-token");
    });
    expect(window.localStorage.length).toBe(0);
  });

  it("shows the lockout of the account with the delay of the gateway", async () => {
    login.mockRejectedValue(
      new ApiError(429, "account_locked", "the account is locked for another 42 second(s)", 42),
    );
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>,
    );

    await user.type(screen.getByLabelText("User"), "admin");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    const notice = await screen.findByRole("alert");
    expect(notice).toHaveTextContent("the account is locked");
    expect(notice).toHaveTextContent("42 seconds");
  });

  it("shows the refusal of the credentials", async () => {
    login.mockRejectedValue(
      new ApiError(401, "unauthenticated", "the credentials are not valid", null),
    );
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>,
    );

    await user.type(screen.getByLabelText("User"), "admin");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("the credentials are not valid");
  });

  it("sends the CSRF token on a state-changing request", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchMock = vi.fn((url: string, init: RequestInit) => {
      calls.push({ url, init });
      return Promise.resolve(
        new Response(JSON.stringify({ user_id: "admin", logged_out: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    setCsrfToken("the-csrf-token");

    await api.logout();

    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("/auth/logout");
    const headers = calls[0]?.init.headers as Record<string, string>;
    expect(headers["X-CSRF-Token"]).toBe("the-csrf-token");
  });
});
