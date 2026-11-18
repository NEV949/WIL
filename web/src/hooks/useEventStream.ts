import { useEffect, useRef } from "react";
import type { StreamEvent } from "../api/types";

export const STREAM_ACTIONS = [
  "task_submitted",
  "run_started",
  "step_completed",
  "risk_assessed",
  "approval_requested",
  "approval_decided",
  "run_resumed",
  "run_completed",
  "run_failed",
  "artifact_signed",
  "model_called",
  "deployment_started",
  "traffic_measured",
  "deployment_completed",
  "deployment_rolled_back",
  "deployment_refused",
  "qdrant_collection_recreated",
] as const;

/** The events of the tenant of the caller, as they happen. */
export function useEventStream(onEvent: (event: StreamEvent) => void): void {
  const handler = useRef(onEvent);

  useEffect(() => {
    handler.current = onEvent;
  }, [onEvent]);

  useEffect(() => {
    if (typeof EventSource === "undefined") {
      return;
    }
    const source = new EventSource("/events/stream?since=0");
    let lastSeq = 0;
    const listener = (event: Event): void => {
      const message = event as MessageEvent<string>;
      let parsed: StreamEvent;
      try {
        parsed = JSON.parse(message.data) as StreamEvent;
      } catch {
        return;
      }
      if (parsed.seq <= lastSeq) {
        return;
      }
      lastSeq = parsed.seq;
      handler.current(parsed);
    };
    for (const action of STREAM_ACTIONS) {
      source.addEventListener(action, listener);
    }
    return () => {
      source.close();
    };
  }, []);
}
