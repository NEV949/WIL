import { type ReactNode } from "react";
import { api } from "../api/client";
import { Badge, Bar, Card, Empty, Fields, Loading, Notice } from "../components/Bits";
import { statusTone } from "../components/format";
import { useAsync } from "../hooks/useAsync";

export function DeploymentPage(): ReactNode {
  const metrics = useAsync(() => api.metrics());
  const rollout = metrics.data?.rollout ?? null;

  return (
    <div className="page">
      <h1>Deployment</h1>
      {metrics.loading && <Loading label="Loading the rollout…" />}
      {metrics.error !== null && <Notice tone="danger">{metrics.error}</Notice>}
      {rollout !== null && (
        <>
          <Card title="The last rollout">
            <div className="task-head">
              <Badge tone={statusTone(rollout.status)}>{rollout.status}</Badge>
              <span className="muted">{rollout.deployment_id}</span>
            </div>
            <Fields
              items={[
                { label: "Version", value: rollout.version === "" ? "—" : rollout.version },
                { label: "Slot", value: rollout.slot === "" ? "—" : rollout.slot },
                {
                  label: "Error rate threshold",
                  value: `${(rollout.error_rate_threshold * 100).toFixed(2)}%`,
                },
                { label: "Steps", value: rollout.steps.length },
              ]}
            />
            {rollout.status === "rolled_back" && (
              <Notice tone="danger">
                The rollout was rolled back: the error rate passed the threshold.
              </Notice>
            )}
            {rollout.status === "refused" && (
              <Notice tone="danger">The rollout was refused by the gate of the deployment.</Notice>
            )}
          </Card>
          <Card title="The traffic split">
            {rollout.steps.length === 0 && <Empty>No traffic was measured yet.</Empty>}
            <ul className="step-list">
              {rollout.steps.map((step, index) => (
                <li className="step" key={`${step.percent}-${index}`}>
                  <div className="task-head">
                    <span className="step-percent">{step.percent}% of the traffic</span>
                    <Badge tone={step.healthy ? "ok" : "danger"}>
                      {step.healthy ? "healthy" : "unhealthy"}
                    </Badge>
                  </div>
                  <Bar
                    value={step.percent}
                    max={100}
                    label={`${step.percent}% of the traffic, ${step.errors} error(s) of ${step.requests} request(s)`}
                  />
                  <span className="muted">
                    {step.requests} request(s), {step.errors} error(s),{" "}
                    {(step.error_rate * 100).toFixed(2)}% of errors
                  </span>
                </li>
              ))}
            </ul>
          </Card>
        </>
      )}
    </div>
  );
}
