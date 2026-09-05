import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import ThreatHuntApp from "./ThreatHuntApp";

const rootElement = document.getElementById("root");

if (!rootElement) {
  throw new Error("The application root element is missing.");
}

createRoot(rootElement).render(
  <StrictMode>
    <ThreatHuntApp />
  </StrictMode>,
);
