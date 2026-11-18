import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { TaskEventView } from "../api/types";
import { Badge, Card, Empty, Fields, Loading, Notice } from "../components/Bits";
import { statusTone } from "../components/format";
import { useAsync } from "../hooks/useAsync";
import { useTaskEventsBulk } from "../hooks/useTaskEvents";

function riskTierOf(events: TaskEventView[] | undefined): string {
  if (events === undefined) {
    return "—";
  }
  let tier = "";
  for (const event of events) {
    if (event.action !== "risk_assessed") {
      continue;
    }
    const value = event.payload["risk_tier"];
    if (typeof value === "string") {
      tier = value;
    }
  }
  return tier === "" ? "—" : tier;
}

export function DashboardPage(): ReactNode {
  const navigate = useNavigate();
  const tasks = useAsync(() => api.listTasks());
  const [request, setRequest] = useState("");
  const [sopId, setSopId] = useState("sop_lightweight");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const list = useMemo(() => tasks.data ?? [], [tasks.data]);
  const ids = useMemo(() => list.map((task) => task.task_id), [list]);
  const events = useTaskEventsBulk(ids);

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const created = await api.createTask(request, sopId);
      setRequest("");
      tasks.reload();
      navigate(`/tasks/${created.task_id}`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "the task was not submitted");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <h1>Dashboard</h1>
      <Card title="Submit a requirement">
        <form className="stack" onSubmit={submit}>
          {error !== null && <Notice tone="danger">{error}</Notice>}
          <label className="stack">
            <span>Requirement</span>
            <textarea
              name="request"
              rows={3}
              value={request}
              placeholder="Add overtime pay for the employees of the plant"
              onChange={(event) => {
                setRequest(event.target.value);
              }}
            />
          </label>
          <label className="stack">
            <span>SOP</span>
            <input
              name="sop"
              value={sopId}
              onChange={(event) => {
                setSopId(event.target.value);
              }}
            />
          </label>
          <button type="submit" className="primary" disabled={busy || request.trim() === ""}>
            {busy ? "Submitting…" : "Submit"}
          </button>
        </form>
      </Card>

      <Card
        title="Tasks"
        actions={
          <button
            type="button"
            className="ghost"
            onClick={() => {
              tasks.reload();
            }}
          >
            Refresh
          </button>
        }
      >
        {tasks.loading && <Loading label="Loading the tasks…" />}
        {tasks.error !== null && <Notice tone="danger">{tasks.error}</Notice>}
        {!tasks.loading && tasks.error === null && list.length === 0 && (
          <Empty>No task yet. Submit a requirement above.</Empty>
        )}
        <ul className="task-list">
          {list.map((task) => (
            <li className="task-card" key={task.task_id}>
              <div className="task-head">
                <Link to={`/tasks/${task.task_id}`} className="task-link">
                  {task.task_id}
                </Link>
                <Badge tone={statusTone(task.status)}>{task.status}</Badge>
              </div>
              <Fields
                items={[
                  { label: "Stage", value: task.stage },
                  { label: "Risk tier", value: riskTierOf(events[task.task_id]) },
                  { label: "Attempts", value: task.attempts },
                  {
                    label: "Approval",
                    value: task.approval_status ?? "—",
                  },
                ]}
              />
              {task.failure !== null && <Notice tone="danger">{task.failure}</Notice>}
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
