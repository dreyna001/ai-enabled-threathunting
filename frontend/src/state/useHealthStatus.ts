import { useCallback, useEffect, useState } from "react";
import { getHealth, HealthApiError, HealthResponse } from "../api/health";

export type HealthViewState =
  | { kind: "startup" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; health: HealthResponse }
  | { kind: "not_ready"; health: HealthResponse };

function errorMessage(error: unknown): string {
  if (error instanceof HealthApiError) {
    return error.message;
  }

  return "The service status could not be loaded. Please try again.";
}

export function useHealthStatus(): {
  state: HealthViewState;
  refresh: () => void;
} {
  const [state, setState] = useState<HealthViewState>({ kind: "startup" });
  const [refreshToken, setRefreshToken] = useState(0);

  const refresh = useCallback(() => {
    setRefreshToken((token) => token + 1);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    setState({ kind: "loading" });

    void getHealth(controller.signal)
      .then((health) => {
        setState(health.status === "ready" ? { kind: "ready", health } : { kind: "not_ready", health });
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }

        setState({ kind: "error", message: errorMessage(error) });
      });

    return () => controller.abort();
  }, [refreshToken]);

  return { state, refresh };
}
