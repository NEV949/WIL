import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { TaskEventView } from "../api/types";
import { messageOf } from "./useAsync";

const cache = new Map<string, TaskEventView[]>();

/** The audit events of one task. They are kept for the session. */
export function useTaskEvents(taskId: string): {
  events: TaskEventView[];
  error: string | null;
  loading: boolean;
} {
  const [events, setEvents] = useState<TaskEventView[]>(() => cache.get(taskId) ?? []);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(() => !cache.has(taskId));

  useEffect(() => {
    let alive = true;
    setLoading(!cache.has(taskId));
    api.taskEvents(taskId).then(
      (loaded) => {
        if (!alive) {
          return;
        }
        cache.set(taskId, loaded);
        setEvents(loaded);
        setError(null);
        setLoading(false);
      },
      (reason: unknown) => {
        if (!alive) {
          return;
        }
        setError(messageOf(reason));
        setLoading(false);
      },
    );
    return () => {
      alive = false;
    };
  }, [taskId]);

  return { events, error, loading };
}

/** The events of many tasks at once, for the list of the dashboard. */
export function useTaskEventsBulk(taskIds: string[]): Record<string, TaskEventView[]> {
  const [events, setEvents] = useState<Record<string, TaskEventView[]>>(() => pick(taskIds));

  useEffect(() => {
    const missing = taskIds.filter((taskId) => !cache.has(taskId));
    if (missing.length === 0) {
      return;
    }
    let alive = true;
    const loads = missing.map((taskId) =>
      api.taskEvents(taskId).then(
        (loaded) => [taskId, loaded] as const,
        () => [taskId, [] as TaskEventView[]] as const,
      ),
    );
    void Promise.all(loads).then((entries) => {
      if (!alive) {
        return;
      }
      for (const [taskId, loaded] of entries) {
        cache.set(taskId, loaded);
      }
      setEvents(pick(taskIds));
    });
    return () => {
      alive = false;
    };
  }, [taskIds]);

  return events;
}

function pick(taskIds: string[]): Record<string, TaskEventView[]> {
  const chosen: Record<string, TaskEventView[]> = {};
  for (const taskId of taskIds) {
    const found = cache.get(taskId);
    if (found !== undefined) {
      chosen[taskId] = found;
    }
  }
  return chosen;
}
