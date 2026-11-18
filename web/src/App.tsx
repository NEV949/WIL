import { BrowserRouter, Navigate, Outlet, Route, Routes, useLocation } from "react-router-dom";
import type { ReactNode } from "react";
import { AuthProvider } from "./auth/AuthProvider";
import { useAuth } from "./auth/useAuth";
import { Layout } from "./components/Layout";
import { Loading, Notice } from "./components/Bits";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { ArtifactPage } from "./pages/ArtifactPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DeploymentPage } from "./pages/DeploymentPage";
import { LoginPage } from "./pages/LoginPage";
import { MetricsPage } from "./pages/MetricsPage";
import { SecurityPage } from "./pages/SecurityPage";
import { TaskPage } from "./pages/TaskPage";

export function Protected(): ReactNode {
  const { user, ready } = useAuth();
  const location = useLocation();
  if (!ready) {
    return <Loading label="Opening the session…" />;
  }
  if (user === null) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <Outlet />;
}

export function AdminOnly(): ReactNode {
  const { isAdmin } = useAuth();
  if (!isAdmin) {
    return <Notice tone="danger">This page needs the role admin.</Notice>;
  }
  return <Outlet />;
}

export function App(): ReactNode {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<Protected />}>
            <Route element={<Layout />}>
              <Route index element={<DashboardPage />} />
              <Route path="tasks/:taskId" element={<TaskPage />} />
              <Route path="artifacts/:taskId" element={<ArtifactPage />} />
              <Route path="security" element={<SecurityPage />} />
              <Route path="deployment" element={<DeploymentPage />} />
              <Route path="metrics" element={<MetricsPage />} />
              <Route element={<AdminOnly />}>
                <Route path="approvals" element={<ApprovalsPage />} />
              </Route>
            </Route>
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
