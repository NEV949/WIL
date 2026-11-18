import { useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";

export function messageOf(reason: unknown): string {
  if (reason instanceof ApiError) {
    return reason.message;
  }
  if (reason instanceof Error) {
    return reason.message;
  }
  return "the request failed";
}

export interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/** Load a value from the gateway, and let the caller load it again. */
export function useAsync<T>(load: () => Promise<T>): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);
  const loader = useRef(load);

  useEffect(() => {
    loader.current = load;
  }, [load]);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    loader.current().then(
      (value) => {
        if (!alive) {
          return;
        }
        setData(value);
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
  }, [nonce]);

  return { data, error, loading, reload: () => setNonce((value) => value + 1) };
}
