import { render, screen, waitFor, type RenderResult } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AdminOnly, Protected } from "../App";
import { AuthProvider } from "../auth/AuthProvider";
import { Layout } from "../components/Layout";
import { openSession, type Role } from "./helpers";

const UNAUTHORIZED = "oracle-hcm:unauthorized";

function renderApp(role: Role | null, path: string): RenderResult {
  if (role !== null) {
    openSession(role);
  }
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<div>the login page</div>} />
          <Route element={<Protected />}>
            <Route element={<Layout />}>
              <Route index element={<div>the dashboard</div>} />
              <Route element={<AdminOnly />}>
                <Route path="approvals" element={<div>the approvals</div>} />
              </Route>
            </Route>
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("what a role sees", () => {
  it("shows the approvals link to an admin", () => {
    renderApp("admin", "/");
    expect(screen.getByRole("link", { name: "Approvals" })).toBeInTheDocument();
  });

  it("hides the approvals link from a user that is not an admin", () => {
    renderApp("user", "/");
    expect(screen.queryByRole("link", { name: "Approvals" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Metrics" })).toBeInTheDocument();
  });

  it("refuses the approvals page to a user that is not an admin", async () => {
    renderApp("user", "/approvals");
    expect(await screen.findByText("This page needs the role admin.")).toBeInTheDocument();
    expect(screen.queryByText("the approvals")).not.toBeInTheDocument();
  });

  it("opens the approvals page to an admin", async () => {
    renderApp("admin", "/approvals");
    expect(await screen.findByText("the approvals")).toBeInTheDocument();
  });

  it("shows the name of the caller in the top bar", () => {
    renderApp("user", "/");
    expect(screen.getByText("tester")).toBeInTheDocument();
  });
});

describe("the session", () => {
  it("sends a caller with no session to the login", async () => {
    renderApp(null, "/");
    expect(await screen.findByText("the login page")).toBeInTheDocument();
  });

  it("goes back to the login when the gateway refuses the session", async () => {
    renderApp("user", "/");
    expect(await screen.findByText("the dashboard")).toBeInTheDocument();

    window.dispatchEvent(new Event(UNAUTHORIZED));

    await waitFor(() => {
      expect(screen.getByText("the login page")).toBeInTheDocument();
    });
    expect(window.sessionStorage.getItem("oracle-hcm.user")).toBeNull();
  });
});
