import type {
  ApprovalView,
  ArtifactView,
  LoginResponse,
  LogoutResponse,
  MetricsView,
  TaskCreatedResponse,
  TaskEventView,
  TaskSummary,
  TaskView,
} from "./types";

export const CSRF_HEADER = "X-CSRF-Token";

const UNAUTHORIZED_EVENT = "oracle-hcm:unauthorized";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryAfter: number | null;

  constructor(status: number, code: string, message: string, retryAfter: number | null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

let csrfToken: string | null = null;

/** The CSRF token the gateway handed out with the session. */
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function getCsrfToken(): string | null {
  return csrfToken;
}

/** Called when the gateway refuses the session: the console goes back to the login. */
export function onUnauthorized(handler: () => void): () => void {
  window.addEventListener(UNAUTHORIZED_EVENT, handler);
  return () => {
    window.removeEventListener(UNAUTHORIZED_EVENT, handler);
  };
}

interface RequestOptions {
  method?: "GET" | "POST";
  body?: unknown;
  anonymous?: boolean;
}

async function toApiError(response: Response): Promise<ApiError> {
  let code = "error";
  let message = `the request failed with the status ${response.status}`;
  try {
    const body = (await response.json()) as { error?: unknown; message?: unknown };
    if (typeof body.error === "string") {
      code = body.error;
    }
    if (typeof body.message === "string") {
      message = body.message;
    }
  } catch {
    // the answer is not a JSON body
  }
  const header = response.headers.get("Retry-After");
  const retryAfter = header === null ? null : Number(header);
  return new ApiError(
    response.status,
    code,
    message,
    retryAfter !== null && Number.isFinite(retryAfter) ? retryAfter : null,
  );
}

export async function apiRequest<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET" && csrfToken !== null) {
    headers[CSRF_HEADER] = csrfToken;
  }
  const init: RequestInit = { method, headers, credentials: "same-origin" };
  if (options.body !== undefined) {
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, init);
  if (!response.ok) {
    if (response.status === 401 && options.anonymous !== true) {
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    }
    throw await toApiError(response);
  }
  return (await response.json()) as T;
}

export const api = {
  login: (username: string, password: string): Promise<LoginResponse> =>
    apiRequest<LoginResponse>("/auth/login", {
      method: "POST",
      body: { username, password },
      anonymous: true,
    }),

  logout: (): Promise<LogoutResponse> =>
    apiRequest<LogoutResponse>("/auth/logout", { method: "POST" }),

  listTasks: (): Promise<TaskSummary[]> => apiRequest<TaskSummary[]>("/tasks"),

  getTask: (taskId: string): Promise<TaskView> =>
    apiRequest<TaskView>(`/tasks/${encodeURIComponent(taskId)}`),

  taskEvents: (taskId: string): Promise<TaskEventView[]> =>
    apiRequest<TaskEventView[]>(`/tasks/${encodeURIComponent(taskId)}/events`),

  artifact: (taskId: string): Promise<ArtifactView> =>
    apiRequest<ArtifactView>(`/tasks/${encodeURIComponent(taskId)}/artifact`),

  pendingApprovals: (): Promise<ApprovalView[]> =>
    apiRequest<ApprovalView[]>("/approvals/pending"),

  decide: (
    approvalId: string,
    decision: "approved" | "rejected",
    comment: string,
    artifactHash: string,
  ): Promise<ApprovalView> =>
    apiRequest<ApprovalView>(`/approvals/${encodeURIComponent(approvalId)}/decide`, {
      method: "POST",
      body: { decision, comment, artifact_hash: artifactHash },
    }),

  createTask: (request: string, sopId: string): Promise<TaskCreatedResponse> =>
    apiRequest<TaskCreatedResponse>("/tasks", {
      method: "POST",
      body: { request, sop_id: sopId },
    }),

  metrics: (): Promise<MetricsView> => apiRequest<MetricsView>("/metrics"),
};
