import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApprovalsPage } from "../pages/ApprovalsPage";
import { api, ApiError } from "../api/client";
import type { ApprovalView, TaskView } from "../api/types";
import { renderWithSession } from "./helpers";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      pendingApprovals: vi.fn(),
      getTask: vi.fn(),
      decide: vi.fn(),
    },
  };
});

const pending = vi.mocked(api.pendingApprovals);
const getTask = vi.mocked(api.getTask);
const decide = vi.mocked(api.decide);

const HASH = "a".repeat(64);

const APPROVAL: ApprovalView = {
  approval_id: "ap-1",
  run_id: "run-1",
  gate_id: "admin_approval",
  stage: 1,
  artifact_type: "requirements",
  status: "pending",
  requested_at: "2026-11-17T09:00:00+00:00",
  decided_at: null,
  decided_by: null,
  note: "",
  artifact_hash: HASH,
};

const RISK_APPROVAL: ApprovalView = {
  ...APPROVAL,
  approval_id: "risk-ap-1015",
  run_id: "1015b33bed12",
  gate_id: "risk_tier",
  stage: 0,
  artifact_type: "risk_assessment",
};

const RUN: TaskView = {
  task_id: "run-1",
  tenant_id: "t1",
  sop_id: "sop_lightweight",
  status: "awaiting_approval",
  stage: "requirements",
  stage_number: 0,
  created_at: "2026-11-17T09:00:00+00:00",
  updated_at: "2026-11-17T09:01:00+00:00",
  attempts: 1,
  approval_id: "ap-1",
  approval_status: "pending",
  approval_stage: 1,
  failure: null,
  request: "Add overtime pay for the employees of the plant",
};

describe("the approvals", () => {
  it("shows the artifact under review and approves it with the hash it showed", async () => {
    pending.mockResolvedValue([APPROVAL]);
    getTask.mockResolvedValue(RUN);
    decide.mockResolvedValue({ ...APPROVAL, status: "approved", decided_by: "admin" });
    const user = userEvent.setup();
    renderWithSession(<ApprovalsPage />);

    expect(await screen.findByText(HASH)).toBeInTheDocument();
    expect(await screen.findByText("Add overtime pay for the employees of the plant")).toBeVisible();

    await user.type(screen.getByLabelText("Comment"), "the spec is right");
    await user.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() => {
      expect(decide).toHaveBeenCalledWith("ap-1", "approved", "the spec is right", HASH);
    });
    expect(await screen.findByText(/Approved/)).toBeVisible();
  });

  it("renders risk assessment metadata and reloads pending items after a page refresh", async () => {
    pending.mockResolvedValueOnce([]).mockResolvedValueOnce([RISK_APPROVAL]);
    getTask.mockResolvedValue(RUN);
    const firstPage = renderWithSession(<ApprovalsPage />);
    await waitFor(() => expect(pending).toHaveBeenCalledTimes(1));
    firstPage.unmount();

    renderWithSession(<ApprovalsPage />);

    expect(await screen.findByText("Risk assessment under review")).toBeVisible();
    expect(screen.getByText("risk_tier")).toBeVisible();
    expect(screen.getByText("pending")).toBeVisible();
    expect(screen.getByRole("link", { name: "1015b33bed12" })).toBeVisible();
    expect(await screen.findByText(HASH)).toBeVisible();
    expect(pending).toHaveBeenCalledTimes(2);
  });

  it("reloads the persistent pending list when an approval event arrives", async () => {
    class EventSourceStub {
      static current: EventSourceStub;
      private listeners = new Map<string, EventListener>();

      constructor(_url: string) {
        EventSourceStub.current = this;
      }

      addEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
        if (typeof listener === "function") {
          this.listeners.set(type, listener);
        }
      }

      close(): void {}

      emit(action: string): void {
        const listener = this.listeners.get(action);
        listener?.(
          new MessageEvent(action, {
            data: JSON.stringify({
              seq: 1,
              action,
              payload: { run_id: RISK_APPROVAL.run_id, approval_id: RISK_APPROVAL.approval_id },
            }),
          }),
        );
      }
    }

    vi.stubGlobal("EventSource", EventSourceStub);
    pending.mockResolvedValueOnce([]).mockResolvedValue([RISK_APPROVAL]);
    getTask.mockResolvedValue(RUN);
    const page = renderWithSession(<ApprovalsPage />);
    await waitFor(() => expect(pending).toHaveBeenCalledTimes(1));

    act(() => EventSourceStub.current.emit("approval_requested"));

    expect(await screen.findByText("Risk assessment under review")).toBeVisible();
    expect(pending).toHaveBeenCalledTimes(2);
    page.unmount();
    vi.unstubAllGlobals();
  });

  it("rejects an approval with the comment of the administrator", async () => {
    pending.mockResolvedValue([APPROVAL]);
    getTask.mockResolvedValue(RUN);
    decide.mockResolvedValue({ ...APPROVAL, status: "rejected", decided_by: "admin" });
    const user = userEvent.setup();
    renderWithSession(<ApprovalsPage />);

    await screen.findByText(HASH);
    await user.type(screen.getByLabelText("Comment"), "the tests are missing a case");
    await user.click(screen.getByRole("button", { name: "Reject" }));

    await waitFor(() => {
      expect(decide).toHaveBeenCalledWith(
        "ap-1",
        "rejected",
        "the tests are missing a case",
        HASH,
      );
    });
  });

  it("refuses the decision when the artifact changed in the meantime", async () => {
    pending.mockResolvedValue([APPROVAL]);
    getTask.mockResolvedValue(RUN);
    decide.mockRejectedValue(
      new ApiError(409, "conflict", "the artifact changed since it was shown: the decision is refused", null),
    );
    const user = userEvent.setup();
    renderWithSession(<ApprovalsPage />);

    await screen.findByText(HASH);
    await user.click(screen.getByRole("button", { name: "Approve" }));

    expect(await screen.findByText(/artifact changed since it was shown/i)).toBeVisible();
  });
});
