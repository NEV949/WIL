import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "../api/client";
import type { ApprovalView } from "../api/types";
import { Badge, Card, Empty, Fields, Loading, Notice, TextBlock } from "../components/Bits";
import { formatMoment, statusTone } from "../components/format";
import { useAsync } from "../hooks/useAsync";
import { useEventStream } from "../hooks/useEventStream";

function artifactLabel(type: string): string {
  switch (type) {
    case "tests":
      return "Test suite";
    case "risk_assessment":
      return "Risk assessment";
    case "requirements":
      return "Specification";
    default:
      return type.replaceAll("_", " ");
  }
}

function ApprovalCard({
  approval,
  onDecided,
}: {
  approval: ApprovalView;
  onDecided: () => void;
}): ReactNode {
  const run = useAsync(() => api.getTask(approval.run_id));
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function decide(decision: "approved" | "rejected"): Promise<void> {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const decided = await api.decide(
        approval.approval_id,
        decision,
        comment,
        approval.artifact_hash,
      );
      setResult(
        decision === "approved"
          ? `Approved${decided.decided_by === null ? "" : ` by ${decided.decided_by}`}.`
          : `Rejected${decided.decided_by === null ? "" : ` by ${decided.decided_by}`}.`,
      );
      onDecided();
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 409) {
        setError(
          "The artifact changed since it was shown: the decision is refused. Reload the list.",
        );
      } else {
        setError(reason instanceof Error ? reason.message : "the decision failed");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <li className="task-card">
      <div className="task-head">
        <span className="task-link">{approval.gate_id}</span>
        <Badge tone={statusTone(approval.status)}>{approval.status}</Badge>
      </div>
      <Fields
        items={[
          { label: "Stage", value: approval.stage },
          { label: "Artifact", value: approval.artifact_type },
          { label: "Run", value: <Link to={`/tasks/${approval.run_id}`}>{approval.run_id}</Link> },
          { label: "Requested", value: formatMoment(approval.requested_at) },
        ]}
      />
      <div className="stack">
        <span className="muted">The hash of the artifact under review</span>
        <code className="hash">{approval.artifact_hash}</code>
      </div>
      <div className="stack">
        <span className="muted">{artifactLabel(approval.artifact_type)} under review</span>
        {run.loading && <Loading label="Loading the run…" />}
        {run.data !== null && (
          <TextBlock text={run.data.request === "" ? "—" : run.data.request} />
        )}
      </div>
      {error !== null && <Notice tone="danger">{error}</Notice>}
      {result !== null && <Notice tone="ok">{result}</Notice>}
      <label className="stack">
        <span>Comment</span>
        <textarea
          name={`comment-${approval.approval_id}`}
          rows={2}
          value={comment}
          onChange={(event) => {
            setComment(event.target.value);
          }}
        />
      </label>
      <div className="row">
        <button
          type="button"
          className="primary"
          disabled={busy}
          onClick={() => {
            void decide("approved");
          }}
        >
          Approve
        </button>
        <button
          type="button"
          className="danger"
          disabled={busy}
          onClick={() => {
            void decide("rejected");
          }}
        >
          Reject
        </button>
      </div>
    </li>
  );
}

export function ApprovalsPage(): ReactNode {
  const approvals = useAsync(() => api.pendingApprovals());
  const list = useMemo(() => approvals.data ?? [], [approvals.data]);
  const reload = useRef(approvals.reload);
  reload.current = approvals.reload;

  useEventStream((event) => {
    if (event.action === "approval_requested" || event.action === "approval_decided") {
      approvals.reload();
    }
  });

  useEffect(() => {
    const refresh = (): void => reload.current();
    const timer = window.setInterval(refresh, 15_000);
    window.addEventListener("focus", refresh);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("focus", refresh);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, []);

  return (
    <div className="page">
      <h1>Approvals</h1>
      <Card
        title="Waiting for a decision"
        actions={
          <button
            type="button"
            className="ghost"
            onClick={() => {
              approvals.reload();
            }}
          >
            Refresh
          </button>
        }
      >
        {approvals.loading && <Loading label="Loading the approvals…" />}
        {approvals.error !== null && <Notice tone="danger">{approvals.error}</Notice>}
        {!approvals.loading && approvals.error === null && list.length === 0 && (
          <Empty>No approval waits for a decision.</Empty>
        )}
        <ul className="task-list">
          {list.map((approval) => (
            <ApprovalCard
              key={approval.approval_id}
              approval={approval}
              onDecided={() => {
                approvals.reload();
              }}
            />
          ))}
        </ul>
      </Card>
    </div>
  );
}
