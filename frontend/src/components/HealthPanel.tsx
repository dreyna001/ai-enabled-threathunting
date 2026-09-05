import { HealthCheck, HealthResponse } from "../api/health";
import { HealthViewState } from "../state/useHealthStatus";

interface HealthPanelProps {
  state: HealthViewState;
  onRetry: () => void;
}

function CheckList({ checks }: { checks: HealthCheck[] }) {
  if (checks.length === 0) {
    return <p className="muted">No dependency checks were returned.</p>;
  }

  return (
    <ul className="check-list" aria-label="Dependency checks">
      {checks.map((check) => (
        <li className="check-item" key={check.name}>
          <span aria-hidden="true" className={`check-indicator check-${check.status}`} />
          <span>
            <strong>{check.name}</strong>
            {check.detail ? <span className="check-detail">{check.detail}</span> : null}
          </span>
          <span className="check-status">{check.status === "pass" ? "Passing" : "Unavailable"}</span>
        </li>
      ))}
    </ul>
  );
}

function HealthDetails({ health }: { health: HealthResponse }) {
  return (
    <section className="health-details" aria-labelledby="health-details-heading">
      <h2 id="health-details-heading">Service checks</h2>
      <CheckList checks={health.checks} />
    </section>
  );
}

export function HealthPanel({ state, onRetry }: HealthPanelProps) {
  switch (state.kind) {
    case "startup":
      return (
        <section className="status-card" aria-labelledby="startup-heading">
          <p className="eyebrow">Starting workspace</p>
          <h2 id="startup-heading">Preparing the service check</h2>
          <p className="muted">The workspace is getting ready.</p>
        </section>
      );
    case "loading":
      return (
        <section className="status-card" aria-labelledby="loading-heading" aria-busy="true">
          <p className="eyebrow">Loading</p>
          <h2 id="loading-heading">Checking service readiness</h2>
          <p className="muted" role="status">Contacting the application health endpoint…</p>
        </section>
      );
    case "error":
      return (
        <section className="status-card status-error" aria-labelledby="error-heading" role="alert">
          <p className="eyebrow">Unavailable</p>
          <h2 id="error-heading">The workspace is unavailable</h2>
          <p>{state.message}</p>
          <button type="button" onClick={onRetry}>Try again</button>
        </section>
      );
    case "not_ready":
      return (
        <section className="status-card status-warning" aria-labelledby="not-ready-heading">
          <p className="eyebrow">Not ready</p>
          <h2 id="not-ready-heading">The workspace is waiting for dependencies</h2>
          <p className="muted">Some required services are not ready yet. Try again after they recover.</p>
          <HealthDetails health={state.health} />
          <button type="button" onClick={onRetry}>Check again</button>
        </section>
      );
    case "ready":
      return (
        <section className="status-card status-ready" aria-labelledby="ready-heading">
          <p className="eyebrow">Ready</p>
          <h2 id="ready-heading">The workspace is ready</h2>
          <p className="muted">Foundation services are available. Additional hunt workflows will appear in later blocks.</p>
          <HealthDetails health={state.health} />
        </section>
      );
  }
}
