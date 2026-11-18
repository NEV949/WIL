import { useMemo, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { StreamEvent } from "../api/types";
import { Badge, Card, Empty, Fields, Loading, Notice, TextBlock } from "../components/Bits";
import { formatMoment, statusTone } from "../components/format";
import { useAsync } from "../hooks/useAsync";
import { useEventStream } from "../hooks/useEventStream";
import { useTaskEvents } from "../hooks/useTaskEvents";

interface TimelineEntry {
  seq: number;
  timestamp: string;
  actor: string;
  action: string;
  payload: Record<string, unknown>;
}

export function TaskPage(): ReactNode {
  const { taskId = "" } = useParams();
  const task = useAsync(() => api.getTask(taskId));
  const history = useTaskEvents(taskId);
  const [live, setLive] = useState<StreamEvent[]>([]);

  useEventStream((event) => {
    if (String(event.payload["run_id"] ?? "") !== taskId) {
      return;
    }
    setLive((events) => [...events, event]);
  });

  const timeline = useMemo<TimelineEntry[]>(() => {
    const entries: TimelineEntry[] = [
      ...history.events.map((event) => ({
        seq: event.seq,
        timestamp: event.timestamp,
        actor: event.actor,
        action: event.action,
        payload: event.payload,
      })),
      ...live.map((event) => ({
        seq: event.seq,
        timestamp: event.timestamp,
        actor: event.actor,
        action: event.action,
        payload: event.payload,
      })),
    ];
    const seen = new Set<number>();
    return entries
      .filter((entry) => {
        if (seen.has(entry.seq)) {
          return false;
        }
        seen.add(entry.seq);
        return true;
      })
      .sort((left, right) => left.seq - right.seq);
  }, [history.events, live]);

  if (task.error !== null) {
    return (
      <div className="page">
        <h1>Task</h1>
        <Notice tone="danger">{task.error}</Notice>
        <Link to="/">Back to the dashboard</Link>
      </div>
    );
  }

  return (
    <div className="page">
      <h1>Task {taskId}</h1>
      {task.loading && <Loading label="Loading the task…" />}
      {task.data !== null && (
        <>
          <Card title="State">
            <div className="task-head">
              <Badge tone={statusTone(task.data.status)}>{task.data.status}</Badge>
              <Badge tone={statusTone(task.data.stage)}>{task.data.stage}</Badge>
            </div>
            <Fields
              items={[
                { label: "SOP", value: task.data.sop_id },
                { label: "Attempts", value: task.data.attempts },
                { label: "Approval", value: task.data.approval_status ?? "—" },
                { label: "Created", value: formatMoment(task.data.created_at) },
                { label: "Updated", value: formatMoment(task.data.updated_at) },
              ]}
            />
            {task.data.failure !== null && <Notice tone="danger">{task.data.failure}</Notice>}
            <p>
              <Link to={`/artifacts/${task.data.task_id}`}>The artifact and its verification</Link>
            </p>
          </Card>
          <Card title="Requirement">
            <TextBlock text={task.data.request === "" ? "—" : task.data.request} />
          </Card>
        </>
      )}
      <Card title="Timeline">
        {history.error !== null && <Notice tone="danger">{history.error}</Notice>}
        {history.loading && timeline.length === 0 && <Loading label="Loading the events…" />}
        {timeline.length === 0 && !history.loading && history.error === null && (
          <Empty>No event yet.</Empty>
        )}
        <ol className="timeline">
          {timeline.map((entry) => (
            <li className="timeline-entry" key={entry.seq}>
              <div className="timeline-head">
                <span className="timeline-action">{entry.action}</span>
                <span className="muted">{entry.actor}</span>
                <span className="muted">{formatMoment(entry.timestamp)}</span>
              </div>
              {Object.keys(entry.payload).length > 0 && (
                <TextBlock text={JSON.stringify(entry.payload, null, 2)} />
              )}
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}
