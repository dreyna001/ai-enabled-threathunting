import { useCallback, useEffect, useRef, useState } from "react";
import {
  cancelHunt,
  enqueueExecution,
  ExecutionApiError,
  ExecutionResponse,
  getExecution,
  resumeExecution,
} from "../api/execution";

export type HuntExecutionViewState =
  | { kind: "empty" }
  | { kind: "loading" }
  | { kind: "ready"; execution: ExecutionResponse }
  | { kind: "error"; message: string };

function errorMessage(error: unknown): string {
  if (error instanceof ExecutionApiError) {
    return error.message;
  }
  return "The hunt execution status could not be loaded. Please try again.";
}

function isPollingState(execution: ExecutionResponse): boolean {
  return execution.state === "queued"
    || execution.state === "running"
    || execution.state === "synthesizing";
}

export interface HuntExecutionActions {
  refresh: () => void;
  enqueue: () => Promise<void>;
  resume: () => Promise<void>;
  cancel: () => Promise<void>;
}

export function useHuntExecution(huntId: string | null): {
  state: HuntExecutionViewState;
  actions: HuntExecutionActions;
  actionPending: boolean;
  actionError: string | null;
} {
  const [state, setState] = useState<HuntExecutionViewState>({ kind: huntId ? "loading" : "empty" });
  const [refreshToken, setRefreshToken] = useState(0);
  const [actionPending, setActionPending] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const refresh = useCallback(() => {
    setRefreshToken((token) => token + 1);
  }, []);

  useEffect(() => {
    if (!huntId) {
      setState({ kind: "empty" });
      return;
    }

    const controller = new AbortController();
    setState({ kind: "loading" });
    setActionError(null);

    void getExecution(huntId, controller.signal)
      .then((execution) => {
        if (mounted.current) {
          setState({ kind: "ready", execution });
        }
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }
        if (mounted.current) {
          setState({ kind: "error", message: errorMessage(error) });
        }
      });

    return () => controller.abort();
  }, [huntId, refreshToken]);

  useEffect(() => {
    if (state.kind !== "ready" || !huntId || !isPollingState(state.execution)) {
      return;
    }
    const timer = window.setTimeout(() => {
      setRefreshToken((token) => token + 1);
    }, 2500);
    return () => window.clearTimeout(timer);
  }, [huntId, state]);

  const runAction = useCallback(async (action: () => Promise<ExecutionResponse>) => {
    if (!huntId || actionPending) {
      return;
    }
    setActionPending(true);
    setActionError(null);
    try {
      const execution = await action();
      if (mounted.current) {
        setState({ kind: "ready", execution });
      }
    } catch (error: unknown) {
      if (error instanceof DOMException && error.name === "AbortError") {
        return;
      }
      if (mounted.current) {
        setActionError(errorMessage(error));
      }
    } finally {
      if (mounted.current) {
        setActionPending(false);
      }
    }
  }, [actionPending, huntId]);

  const actions: HuntExecutionActions = {
    refresh,
    enqueue: () => runAction(() => enqueueExecution(huntId ?? "")),
    resume: () => runAction(() => resumeExecution(huntId ?? "")),
    cancel: () => runAction(() => cancelHunt(huntId ?? "")),
  };

  return { state, actions, actionPending, actionError };
}
