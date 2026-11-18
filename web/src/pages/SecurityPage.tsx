import { useMemo, type ReactNode } from "react";
import { api } from "../api/client";
import { Bar, Card, Empty, Fields, Loading, Notice } from "../components/Bits";
import { useAsync } from "../hooks/useAsync";

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

export function SecurityPage(): ReactNode {
  const metrics = useAsync(() => api.metrics());
  const findings = useMemo(() => metrics.data?.security_findings ?? [], [metrics.data]);
  const details = useMemo(() => metrics.data?.security_details ?? [], [metrics.data]);
  const ordered = useMemo(
    () =>
      [...findings].sort(
        (left, right) =>
          SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity),
      ),
    [findings],
  );
  const highest = Math.max(1, ...ordered.map((finding) => finding.count));

  return (
    <div className="page">
      <h1>Security</h1>
      <Card title="Findings of the tenant">
        {metrics.loading && <Loading label="Loading the findings…" />}
        {metrics.error !== null && <Notice tone="danger">{metrics.error}</Notice>}
        {metrics.data !== null && (
          <Fields
            items={[
              { label: "Risk signals", value: metrics.data.risk_signals },
              { label: "Findings", value: metrics.data.security_findings.length },
            ]}
          />
        )}
        {!metrics.loading && metrics.error === null && ordered.length === 0 && (
          <Empty>No finding was reported for this tenant.</Empty>
        )}
        <ul className="finding-list">
          {ordered.map((finding) => (
            <li className="finding" key={finding.severity}>
              <span className={`badge badge-${toneOf(finding.severity)}`}>
                {finding.severity}
              </span>
              <Bar
                value={finding.count}
                max={highest}
                label={`${finding.count} finding(s) of severity ${finding.severity}`}
              />
              <span className="muted">{finding.count}</span>
            </li>
          ))}
        </ul>
      </Card>
      <Card title="Security findings by task">
        {details.length === 0 && <Empty>No security finding details were recorded.</Empty>}
        <ul className="finding-list">
          {details.map((finding, index) => (
            <li className="finding" key={`${finding.run_id}-${finding.rule}-${finding.file}-${finding.line}-${index}`}>
              <span className={`badge badge-${toneOf(finding.severity)}`}>
                {finding.severity}
              </span>
              <div>
                <strong>{finding.rule}</strong>
                <div className="muted">
                  {finding.run_id} - {finding.file}:{finding.line}
                </div>
                <div>{finding.message}</div>
              </div>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}

function toneOf(severity: string): "danger" | "warn" | "info" | "neutral" {
  switch (severity) {
    case "critical":
      return "danger";
    case "high":
      return "warn";
    case "medium":
      return "info";
    default:
      return "neutral";
  }
}
