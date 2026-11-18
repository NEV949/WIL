import { act, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router-dom";
import { api } from "../api/client";
import type { TaskEventView, TaskView } from "../api/types";
import { TaskPage } from "../pages/TaskPage";
import { renderWithSession } from "./helpers";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      getTask: vi.fn(),
      taskEvents: vi.fn(),
    },
  };
});

type Listener = (event: Event) => void;

class FakeEventSource {
  static last: FakeEventSource | null = null;

  readonly url: string;
  closed = false;
  private readonly listeners = new Map<string, Set<Listener>>();

  constructor(url: string) {
    this.url = url;
    FakeEventSource.last = this;
  }

  addEventListener(type: string, listener: Listener): void {
    const group = this.listeners.get(type) ?? new Set<Listener>();
    group.add(listener);
    this.listeners.set(type, group);
  }

  removeEventListener(type: string, listener: Listener): void {
    this.listeners.get(type)?.delete(listener);
  }

  close(): void {
    this.closed = true;
  }

  emit(type: string, payload: Record<string, unknown>): void {
    const event = { data: JSON.stringify(payload) } as unknown as Event;
    for (const listener of this.listeners.get(type) ?? []) {
      listener(event);
    }
  }
}

const TASK: TaskView = {
  task_id: "task-live",
  tenant_id: "t1",
  sop_id: "sop-1",
  status: "running",
  stage: "code",
  stage_number: 2,
  created_at: "2026-11-17T09:00:00Z",
  updated_at: "2026-11-17T09:01:00Z",
  attempts: 1,
  approval_id: null,
  approval_status: null,
  approval_stage: null,
  failure: null,
  request: "build a thing",
};

function event(seq: number, action: string, payload: Record<string, unknown>): TaskEventView {
  return {
    event_id: `e-${seq}`,
    seq,
    timestamp: "2026-11-17T09:02:00Z",
    actor: "orchestrator",
    action,
    payload,
  };
}

describe("the live timeline of a task", () => {
  beforeEach(() => {
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(api.getTask).mockResolvedValue(TASK);
    vi.mocked(api.taskEvents).mockResolvedValue([
      event(1, "run_started", { run_id: "task-live" }),
    ]);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    FakeEventSource.last = null;
  });

  it("shows the events that already happened", async () => {
    renderWithSession(
      <Routes>
        <Route path="/tasks/:taskId" element={<TaskPage />} />
      </Routes>,
      { path: "/tasks/task-live" },
    );

    expect(await screen.findByText("run_started")).toBeInTheDocument();
    expect(screen.getByText("build a thing")).toBeInTheDocument();
  });

  it("adds an event that arrives over the stream", async () => {
    renderWithSession(
      <Routes>
        <Route path="/tasks/:taskId" element={<TaskPage />} />
      </Routes>,
      { path: "/tasks/task-live" },
    );

    await screen.findByText("run_started");
    const source = FakeEventSource.last;
    expect(source).not.toBeNull();
    expect(source?.url).toBe("/events/stream?since=0");

    await act(async () => {
      source?.emit("step_completed", {
        event_id: "e-2",
        seq: 2,
        timestamp: "2026-11-17T09:03:00Z",
        tenant_id: "t1",
        actor: "coder",
        action: "step_completed",
        payload: { run_id: "task-live", stage: "code" },
      });
    });

    expect(await screen.findByText("step_completed")).toBeInTheDocument();
  });

  it("ignores an event that belongs to another task", async () => {
    renderWithSession(
      <Routes>
        <Route path="/tasks/:taskId" element={<TaskPage />} />
      </Routes>,
      { path: "/tasks/task-live" },
    );

    await screen.findByText("run_started");
    const source = FakeEventSource.last;

    await act(async () => {
      source?.emit("run_completed", {
        event_id: "e-9",
        seq: 9,
        timestamp: "2026-11-17T09:04:00Z",
        tenant_id: "t1",
        actor: "orchestrator",
        action: "run_completed",
        payload: { run_id: "another-task" },
      });
    });

    await waitFor(() => {
      expect(screen.queryByText("run_completed")).not.toBeInTheDocument();
    });
  });

  it("closes the stream when the page goes away", async () => {
    const view = renderWithSession(
      <Routes>
        <Route path="/tasks/:taskId" element={<TaskPage />} />
      </Routes>,
      { path: "/tasks/task-live" },
    );

    await screen.findByText("run_started");
    const source = FakeEventSource.last;

    view.unmount();

    expect(source?.closed).toBe(true);
  });
});
