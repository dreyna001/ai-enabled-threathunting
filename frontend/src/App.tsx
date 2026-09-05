import { HuntWorkspace } from "./components/HuntWorkspace";
import { HealthPanel } from "./components/HealthPanel";
import { useHealthStatus } from "./state/useHealthStatus";
import "./App.css";

function selectedHuntId(): string | null {
  const query = new URLSearchParams(window.location.search);
  const queryHuntId = query.get("hunt_id") ?? query.get("hunt");
  if (queryHuntId) {
    return queryHuntId;
  }

  const pathParts = window.location.pathname.split("/").filter(Boolean);
  const huntIndex = pathParts.findIndex((part) => part === "hunts" || part === "hunt");
  return huntIndex >= 0 && pathParts[huntIndex + 1] ? decodeURIComponent(pathParts[huntIndex + 1]) : null;
}

export default function App() {
  const { state, refresh } = useHealthStatus();
  const huntId = selectedHuntId();

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">Agentic threat hunting</p>
          <h1>Threat Hunting Workspace</h1>
        </div>
      </header>
      <main className="app-main">
        {huntId ? <HuntWorkspace huntId={huntId} /> : <HealthPanel state={state} onRetry={refresh} />}
      </main>
      <footer className="app-footer">
        <p>Bounded threat-hunting workspace</p>
      </footer>
    </div>
  );
}
