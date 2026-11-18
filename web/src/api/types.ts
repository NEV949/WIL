export interface LoginResponse {
  user_id: string;
  role: string;
  tenant_id: string;
  csrf_token: string;
  expires_at: string;
}

export interface LogoutResponse {
  user_id: string;
  logged_out: boolean;
}

export interface TaskCreatedResponse {
  task_id: string;
  tenant_id: string;
  status: string;
  stage: string;
}

export interface TaskSummary {
  task_id: string;
  tenant_id: string;
  sop_id: string;
  status: string;
  stage: string;
  stage_number: number;
  created_at: string;
  updated_at: string;
  attempts: number;
  approval_id: string | null;
  approval_status: string | null;
  approval_stage: number | null;
  failure: string | null;
}

export interface TaskView extends TaskSummary {
  request: string;
}

export interface TaskEventView {
  event_id: string;
  seq: number;
  timestamp: string;
  actor: string;
  action: string;
  payload: Record<string, unknown>;
}

export interface ApprovalView {
  approval_id: string;
  run_id: string;
  gate_id: string;
  stage: number;
  artifact_type: string;
  status: string;
  requested_at: string;
  decided_at: string | null;
  decided_by: string | null;
  note: string;
  artifact_hash: string;
}

export interface ManifestCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface ArtifactView {
  artifact_id: string;
  manifest: Record<string, unknown>;
  signature: string;
  verified: boolean;
  reason: string;
  checks: ManifestCheck[];
}

export interface TokenUsage {
  model: string;
  total_tokens: number;
}

export interface SecurityFindingCount {
  severity: string;
  count: number;
}

export interface SecurityFindingView {
  run_id: string;
  rule: string;
  severity: string;
  file: string;
  line: number;
  message: string;
  tool: string;
}

export interface SecurityFindingView {
  run_id: string;
  rule: string;
  severity: string;
  file: string;
  line: number;
  message: string;
  tool: string;
}

export interface RolloutStep {
  percent: number;
  requests: number;
  errors: number;
  error_rate: number;
  healthy: boolean;
}

export interface RolloutState {
  deployment_id: string;
  version: string;
  slot: string;
  status: string;
  error_rate_threshold: number;
  steps: RolloutStep[];
}

export interface MetricsView {
  tenant_id: string;
  tasks_total: number;
  tasks_completed: number;
  tasks_failed: number;
  tasks_blocked: number;
  pass_rate: number;
  attempts_total: number;
  attempts_per_task: Record<string, number>;
  tokens_per_model_today: TokenUsage[];
  security_findings: SecurityFindingCount[];
  security_details: SecurityFindingView[];
  risk_signals: number;
  rollout: RolloutState;
}

export interface StreamEvent {
  event_id: string;
  seq: number;
  timestamp: string;
  tenant_id: string;
  actor: string;
  action: string;
  payload: Record<string, unknown>;
}
