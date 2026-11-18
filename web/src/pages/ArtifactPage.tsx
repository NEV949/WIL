import { type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, Fields, Loading, Notice, TextBlock } from "../components/Bits";
import { useAsync } from "../hooks/useAsync";

function textField(manifest: Record<string, unknown>, name: string): string {
  const value = manifest[name];
  return typeof value === "string" ? value : "—";
}

function fileEntries(manifest: Record<string, unknown>): { path: string; sha256: string; size: number }[] {
  const files = manifest["files"];
  if (!Array.isArray(files)) {
    return [];
  }
  const entries: { path: string; sha256: string; size: number }[] = [];
  for (const file of files) {
    if (typeof file !== "object" || file === null) {
      continue;
    }
    const record = file as Record<string, unknown>;
    entries.push({
      path: typeof record["path"] === "string" ? record["path"] : "—",
      sha256: typeof record["sha256"] === "string" ? record["sha256"] : "—",
      size: typeof record["size"] === "number" ? record["size"] : 0,
    });
  }
  return entries;
}

export function ArtifactPage(): ReactNode {
  const { taskId = "" } = useParams();
  const artifact = useAsync(() => api.artifact(taskId));

  if (artifact.error !== null) {
    return (
      <div className="page">
        <h1>Artifact</h1>
        <Notice tone="danger">{artifact.error}</Notice>
        <Link to={`/tasks/${taskId}`}>Back to the task</Link>
      </div>
    );
  }

  const manifest = artifact.data?.manifest ?? {};
  const files = fileEntries(manifest);

  return (
    <div className="page">
      <h1>Artifact</h1>
      {artifact.loading && <Loading label="Loading the artifact…" />}
      {artifact.data !== null && (
        <>
          <Card title="Verification">
            <div className="task-head">
              <Badge tone={artifact.data.verified ? "ok" : "danger"}>
                {artifact.data.verified ? "verified" : "not verified"}
              </Badge>
              <span className="muted">{artifact.data.artifact_id}</span>
            </div>
            <p className="muted">{artifact.data.reason}</p>
            <ul className="check-list">
              {artifact.data.checks.map((check) => (
                <li className="check" key={check.name}>
                  <Badge tone={check.passed ? "ok" : "danger"}>
                    {check.passed ? "passed" : "failed"}
                  </Badge>
                  <span className="check-name">{check.name}</span>
                  <span className="muted">{check.detail}</span>
                </li>
              ))}
            </ul>
          </Card>
          <Card title="The manifest">
            <Fields
              items={[
                { label: "Artifact", value: textField(manifest, "artifact_id") },
                { label: "Requirement", value: textField(manifest, "requirement_id") },
                { label: "Risk tier", value: textField(manifest, "risk_tier") },
                { label: "Created", value: textField(manifest, "created_at") },
                { label: "Root hash", value: <code className="hash">{textField(manifest, "root_hash")}</code> },
                {
                  label: "Test report",
                  value: <code className="hash">{textField(manifest, "test_report_hash")}</code>,
                },
                {
                  label: "Security report",
                  value: <code className="hash">{textField(manifest, "security_report_hash")}</code>,
                },
                {
                  label: "Acceptance",
                  value: <code className="hash">{textField(manifest, "acceptance_result_hash")}</code>,
                },
                {
                  label: "Log head",
                  value: <code className="hash">{textField(manifest, "log_head_hash")}</code>,
                },
              ]}
            />
            <h3>The files of the build</h3>
            <ul className="file-list">
              {files.map((file) => (
                <li key={file.path}>
                  <span className="file-path">{file.path}</span>
                  <span className="muted">{file.size} bytes</span>
                  <code className="hash">{file.sha256}</code>
                </li>
              ))}
            </ul>
            <h3>The signature</h3>
            <TextBlock text={artifact.data.signature === "" ? "—" : artifact.data.signature} />
          </Card>
        </>
      )}
      <p>
        <Link to={`/tasks/${taskId}`}>Back to the task</Link>
      </p>
    </div>
  );
}
