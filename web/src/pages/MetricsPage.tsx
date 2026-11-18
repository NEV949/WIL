import { useMemo, type ReactNode } from "react";
import { api } from "../api/client";
import { Bar, Card, Empty, Fields, Loading, Notice } from "../components/Bits";
import { formatPercent } from "../components/format";
import limits from "../generated/model-limits.json";
import { useAsync } from "../hooks/useAsync";

interface ModelLimit {
  model: string;
  roles: string[];
  rpm: number;
  tpm: number;
}

const known = limits.models as ModelLimit[];

export function MetricsPage(): ReactNode {
  const metrics = useAsync(() => api.metrics());

  const usage = useMemo(() => {
    const totals = new Map<string, number>();
    for (const entry of metrics.data?.tokens_per_model_today ?? []) {
      totals.set(entry.model, entry.total_tokens);
    }
    const models = new Map<string, ModelLimit>();
    for (const limit of known) {
      models.set(limit.model, limit);
    }
    for (const model of totals.keys()) {
      if (!models.has(model)) {
        models.set(model, { model, roles: [], rpm: 0, tpm: 0 });
      }
    }
    return [...models.values()]
      .map((limit) => ({ ...limit, tokens: totals.get(limit.model) ?? 0 }))
      .sort((left, right) => right.tokens - left.tokens);
  }, [metrics.data]);

  const highest = Math.max(1, ...usage.map((entry) => entry.tokens));
  const attempts = useMemo(
    () =>
      Object.entries(metrics.data?.attempts_per_task ?? {}).sort(
        ([left], [right]) => left.localeCompare(right),
      ),
    [metrics.data],
  );

  return (
    <div className="page">
      <h1>Metrics</h1>
      {metrics.loading && <Loading label="Loading the metrics…" />}
      {metrics.error !== null && <Notice tone="danger">{metrics.error}</Notice>}
      {metrics.data !== null && (
        <>
          <Card title="The tasks of the tenant">
            <Fields
              items={[
                { label: "Tasks", value: metrics.data.tasks_total },
                { label: "Completed", value: metrics.data.tasks_completed },
                { label: "Failed", value: metrics.data.tasks_failed },
                { label: "Blocked by security", value: metrics.data.tasks_blocked },
                { label: "Pass rate", value: formatPercent(metrics.data.pass_rate) },
                { label: "Attempts", value: metrics.data.attempts_total },
              ]}
            />
          </Card>
          <Card title="The tokens of today">
            <p className="muted">
              The tokens every model used today, with the limits the engine enforces on it. The
              limit of the registry is a number of tokens per minute: it is not the budget of the
              day.
            </p>
            {usage.length === 0 && <Empty>No model is configured for this tenant.</Empty>}
            <ul className="model-list">
              {usage.map((entry) => (
                <li className="model" key={entry.model}>
                  <div className="task-head">
                    <span className="model-name">{entry.model}</span>
                    <span className="muted">{entry.roles.join(", ")}</span>
                  </div>
                  <Bar
                    value={entry.tokens}
                    max={highest}
                    label={`${entry.tokens} token(s) today for ${entry.model}`}
                  />
                  <span className="muted">
                    {entry.tokens} token(s) today, {entry.tpm} tokens per minute, {entry.rpm}{" "}
                    request(s) per minute
                  </span>
                </li>
              ))}
            </ul>
          </Card>
          <Card title="The attempts of every task">
            {attempts.length === 0 && <Empty>No task ran yet.</Empty>}
            <ul className="attempt-list">
              {attempts.map(([taskId, count]) => (
                <li key={taskId}>
                  <span className="task-link">{taskId}</span>
                  <span className="muted">{count} attempt(s)</span>
                </li>
              ))}
            </ul>
          </Card>
        </>
      )}
    </div>
  );
}
