import { ChangeEvent, FormEvent, useEffect, useState } from "react";
import {
  CreateHuntInput,
  Hunt,
  HuntPlan,
  HuntResults,
  HuntSummary,
  JobStatus,
  JsonObject,
  ReportPreview,
  RetainedInventory,
  Session,
  workflowApi,
} from "./api/hunts";
import "./threat-hunt.css";

const INTAKE_LIMIT = 50_000;
const FILE_ACCEPT = ".txt,.md,.csv,.tsv,.json,.yaml,.yml,text/*,application/json,application/yaml";
const EMPTY_HUNT: CreateHuntInput = {
  title: "",
  hypothesis: "",
  objective: "",
  threat_intelligence: "",
  synthetic_data: "",
};

function dump(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Operation failed.";
}

function StatusMessage({ error }: { error: string }) {
  return error ? <p className="vs-error" role="alert">{error}</p> : null;
}

function Login({ onLogin }: { onLogin: (session: Session) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      onLogin(await workflowApi.login(username, password));
    } catch (error) {
      setError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="vs-login">
      <form className="vs-card" onSubmit={submit} aria-busy={busy}>
        <p className="vs-eyebrow">Federal SOC workspace</p>
        <h1>Threat Hunt Console</h1>
        <p className="vs-muted">Authenticate to create, approve, execute, and report a bounded investigation.</p>
        <label>Username<input required autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} /></label>
        <label>Password<input required type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        <StatusMessage error={error} />
        <button disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </main>
  );
}

interface IntakeFieldProps {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  onError: (message: string) => void;
}

function IntakeField({ id, label, value, onChange, onError }: IntakeFieldProps) {
  async function loadFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > INTAKE_LIMIT) {
      onError(`${label} file exceeds the 50,000-byte limit.`);
      return;
    }
    try {
      const content = await file.text();
      if (content.length > INTAKE_LIMIT) {
        onError(`${label} file exceeds the 50,000-character limit.`);
        return;
      }
      onError("");
      onChange(content);
    } catch {
      onError(`${label} file could not be read as text.`);
    }
  }

  return (
    <fieldset className="vs-intake">
      <legend>{label} <span>(optional)</span></legend>
      <textarea
        id={id}
        rows={5}
        maxLength={INTAKE_LIMIT}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        aria-describedby={`${id}-help ${id}-count`}
      />
      <div className="vs-field-meta">
        <span id={`${id}-help`}>Paste text or load TXT, MD, CSV, TSV, JSON, YAML, or YML; 50,000 bytes and characters maximum.</span>
        <span id={`${id}-count`}>{value.length.toLocaleString()} / {INTAKE_LIMIT.toLocaleString()}</span>
      </div>
      <label className="vs-file-label" htmlFor={`${id}-file`}>Load a supported text file</label>
      <input id={`${id}-file`} className="vs-file" type="file" accept={FILE_ACCEPT} onChange={(event) => void loadFile(event)} />
    </fieldset>
  );
}

function CreateHuntForm({ token, onCreated }: { token: string | undefined; onCreated: (hunt: Hunt) => void }) {
  const [form, setForm] = useState<CreateHuntInput>(EMPTY_HUNT);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function update(field: keyof CreateHuntInput, value: string) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      onCreated(await workflowApi.createHunt(token, form));
    } catch (error) {
      setError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="vs-card" onSubmit={submit} aria-busy={busy}>
      <p className="vs-eyebrow">New investigation</p>
      <h2>Create a hunt</h2>
      <label>Title<input required value={form.title} onChange={(event) => update("title", event.target.value)} /></label>
      <label>Hypothesis<textarea required rows={3} value={form.hypothesis} onChange={(event) => update("hypothesis", event.target.value)} /></label>
      <label>Objective<textarea required rows={3} value={form.objective} onChange={(event) => update("objective", event.target.value)} /></label>
      <IntakeField id="threat-intelligence" label="Threat intelligence" value={form.threat_intelligence} onChange={(value) => update("threat_intelligence", value)} onError={setError} />
      <IntakeField id="synthetic-data" label="Environment context" value={form.synthetic_data} onChange={(value) => update("synthetic_data", value)} onError={setError} />
      <StatusMessage error={error} />
      <button disabled={busy}>{busy ? "Creating hunt…" : "Create hunt"}</button>
    </form>
  );
}

function ResultCard({ title, items }: { title: string; items: JsonObject[] }) {
  return (
    <section className="vs-card">
      <header><h3>{title}</h3><span>{items.length} · scroll</span></header>
      {items.length ? <div className="vs-result-items">{items.map((item, index) => (
        <pre key={String(item.id ?? item.evidence_id ?? item.finding_id ?? `${title}-${index}`)}>{dump(item)}</pre>
      ))}</div> : <p className="vs-empty">None recorded.</p>}
    </section>
  );
}

function QuestionInventories({ inventories }: { inventories: RetainedInventory[] }) {
  if (!inventories.length) return null;
  return <details>
    <summary>View measured counts</summary>
    <p>Calculated from the selected retained records. Field values do not establish confirmed affected entities.</p>
    {inventories.map((inventory) => <section className="vs-inventory" key={JSON.stringify(inventory.scope)}>
      <p>{inventory.raw_record_count} retained raw rows. Repeated representations may remain.</p>
      <details>
        <summary>Show record selection</summary>
        <p>Search references: {inventory.scope.query_ids.join(", ")}</p>
        {inventory.scope.filters.length ? <dl>{inventory.scope.filters.map((filter) => <div key={filter.field}>
          <dt>{filter.field.replaceAll("_", " ")}</dt><dd>{JSON.stringify(filter.value)}</dd>
        </div>)}</dl> : <p>No additional field filters.</p>}
        <p>From {inventory.scope.earliest_utc ?? "the selected search start"} to {inventory.scope.latest_utc ?? "the selected search end"} (end excluded).</p>
      </details>
      <div className="table-wrap" role="region" aria-label="Measured field counts" tabIndex={0}>
        <table>
          <caption>Observed field values in this selection</caption>
          <thead><tr><th scope="col">Field</th><th scope="col">Distinct values</th><th scope="col">Unambiguous values</th><th scope="col">Rows missing values</th><th scope="col">Rows with multiple values</th></tr></thead>
          <tbody>{inventory.fields.map((field) => <tr key={field.field}>
            <th scope="row">{field.field.replaceAll("_", " ")}</th>
            <td>{field.distinct_literal_value_count}</td><td>{field.distinct_unambiguous_value_count}</td>
            <td>{field.rows_with_missing_or_nonscalar_value}</td><td>{field.rows_with_multiple_distinct_values}</td>
          </tr>)}</tbody>
        </table>
      </div>
      <p>Unambiguous values come from rows with one distinct scalar value. Do not add counts from overlapping selections.</p>
      {!!inventory.limitations.length && <ul>{inventory.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul>}
    </section>)}
  </details>;
}

export function QuestionAnswers({ results }: { results: HuntResults }) {
  if (!results.question_answers?.length) return null;
  const findings = new Map(results.findings.map((item) => [String(item.finding_id), item]));
  return (
    <section className="vs-card vs-span">
      <h2>Approved question answers</h2>
      {results.question_answers.map((answer) => (
        <article key={answer.question_id}>
          <h3>{answer.question}</h3>
          <p>{answer.summary}</p>
          {answer.limitations.length > 0 && <ul>{answer.limitations.map((item, index) => <li key={`${answer.question_id}-${index}`}>{item}</li>)}</ul>}
          <QuestionInventories inventories={answer.inventories ?? []} />
          {!!answer.lead_coverage?.length && <details>
            <summary>Review {answer.lead_coverage.length} advisory leads for this question</summary>
            <p>Observed identity fields group records for review. Linked findings still require analyst review.</p>
            {answer.lead_coverage.map((lead) => <section key={lead.lead_evidence_ids[0]}>
              <dl>{Object.entries(lead.identity_fields).map(([field, value]) => <div key={field}>
                <dt>{field.replaceAll("_", " ")}</dt><dd>{value}</dd>
              </div>)}</dl>
              {!Object.keys(lead.identity_fields).length && <p>Identity fields unavailable.</p>}
              <p>{lead.finding_ids.length} findings linked.</p>
              {lead.limitation && <p>Unanswered or limited: {lead.limitation}</p>}
            </section>)}
          </details>}
          {answer.finding_ids.length > 0 && <details>
            <summary>View all {answer.finding_ids.length} findings for this question</summary>
            <div className="vs-result-items">{answer.finding_ids.map((id) => (
              <pre key={id}>{findings.has(id) ? dump(findings.get(id)) : "Finding details unavailable. Reload the hunt results."}</pre>
            ))}</div>
          </details>}
        </article>
      ))}
    </section>
  );
}

function Workspace({ session, initial, onBack }: { session: Session; initial: Hunt; onBack: () => void }) {
  const [hunt, setHunt] = useState(initial);
  const [results, setResults] = useState<HuntResults | null>(null);
  const [report, setReport] = useState<ReportPreview | null>(null);
  const [job, setJob] = useState<JobStatus | null>(null);
  const [planBody, setPlanBody] = useState(dump(initial.plan));
  const [reportBody, setReportBody] = useState("");
  const [instruction, setInstruction] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  useEffect(() => setPlanBody(dump(hunt.plan)), [hunt.plan]);
  useEffect(() => { if (report) setReportBody(dump(report.content)); }, [report]);

  async function loadArtifacts(next: Hunt) {
    if (!["report_draft", "finalized", "budget_exhausted"].includes(next.state)) return;
    const [nextResults, nextReport] = await Promise.all([
      workflowApi.results(session.access_token, next.hunt_id),
      workflowApi.report(session.access_token, next.hunt_id),
    ]);
    setResults(nextResults);
    setReport(nextReport);
  }

  useEffect(() => {
    if (!["report_draft", "finalized", "budget_exhausted"].includes(hunt.state)) return;
    let active = true;
    void loadArtifacts(hunt).catch((error) => {
      if (active) setError(errorMessage(error));
    });
    return () => { active = false; };
  }, [hunt.hunt_id, hunt.state, session.access_token]);

  async function act(name: string, task: () => Promise<Hunt>) {
    setBusy(name);
    setError("");
    try {
      const next = await task();
      setHunt(next);
      await loadArtifacts(next);
    } catch (error) {
      setError(errorMessage(error));
    } finally {
      setBusy("");
    }
  }

  useEffect(() => {
    if (!["queued", "running", "synthesizing"].includes(hunt.state)) return;
    let active = true;
    const poll = async () => {
      try {
        const [nextJob, nextHunt] = await Promise.all([
          workflowApi.jobStatus(session.access_token, hunt.hunt_id),
          workflowApi.getHunt(session.access_token, hunt.hunt_id),
        ]);
        if (!active) return;
        setJob(nextJob);
        setHunt(nextHunt);
        await loadArtifacts(nextHunt);
      } catch (error) {
        if (active) setError(errorMessage(error));
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 2500);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [hunt.state, hunt.hunt_id, session.access_token]);

  function savePlan() {
    try {
      const plan = JSON.parse(planBody) as HuntPlan;
      void act("save", () => workflowApi.savePlan(session.access_token, hunt.hunt_id, hunt.plan_version ?? 1, plan));
    } catch {
      setError("Plan JSON is not valid.");
    }
  }

  async function saveReport(finalize: boolean) {
    if (!report) return;
    let content: JsonObject;
    try {
      content = JSON.parse(reportBody) as JsonObject;
    } catch {
      setError("Report JSON is not valid.");
      return;
    }
    setBusy("report");
    setError("");
    try {
      const saved = await workflowApi.saveReport(session.access_token, hunt.hunt_id, report.version, content);
      setReport(finalize ? await workflowApi.finalizeReport(session.access_token, hunt.hunt_id, saved.version) : saved);
    } catch (error) {
      setError(errorMessage(error));
    } finally {
      setBusy("");
    }
  }

  const editable = ["plan_draft", "awaiting_plan_review"].includes(hunt.state);
  const isDemo = hunt.mode === "deterministic_local_demo" || hunt.discovery_snapshot?.mode === "deterministic_local_demo" || results?.mode === "deterministic_local_demo";
  const canCancel = ["discovering", "queued", "running", "synthesizing"].includes(hunt.state);

  return (
    <main className="vs-workspace" aria-busy={Boolean(busy)}>
      <button className="vs-link" onClick={onBack}>Back to hunts</button>
      <header className="vs-hunt"><div><p className="vs-eyebrow">Hunt <code>{hunt.hunt_id}</code></p><h1>{hunt.title}</h1><p>{hunt.hypothesis}</p></div><span className="vs-badge">{hunt.state.replaceAll("_", " ")}</span></header>
      {isDemo && <p className="vs-warning"><strong>Local deterministic demo:</strong> synthetic verification data, not production Splunk evidence.</p>}
      <StatusMessage error={error} />
      <nav className="vs-steps" aria-label="Workflow">{["Create", "Discover", "Review", "Approve", "Execute", "Report"].map((step, index) => <span key={step}>{index + 1} {step}</span>)}</nav>
      <div className="vs-grid">
        <section className="vs-card"><p className="vs-eyebrow">Data source</p><h2>Splunk discovery</h2>{hunt.discovery_snapshot ? <div className="vs-scroll-panel"><pre>{dump(hunt.discovery_snapshot)}</pre></div> : <p className="vs-empty">No metadata discovered.</p>}<button disabled={Boolean(busy) || hunt.state !== "created"} onClick={() => void act("discover", () => workflowApi.discover(session.access_token, hunt.hunt_id))}>{busy === "discover" ? "Discovering…" : "Run discovery"}</button></section>
        <section className="vs-card"><header><div><p className="vs-eyebrow">Analyst gate</p><h2>Plan review</h2></div><span>v{hunt.plan_version ?? 1}</span></header>{hunt.plan ? <><label>Plan JSON<textarea className="vs-code" rows={15} readOnly={!editable} value={planBody} onChange={(event) => setPlanBody(event.target.value)} /></label>{editable && <><button disabled={Boolean(busy)} onClick={savePlan}>Save edits</button><label>Revision instruction<textarea value={instruction} onChange={(event) => setInstruction(event.target.value)} /></label><button className="vs-secondary" disabled={Boolean(busy) || !instruction.trim()} onClick={() => void act("revise", () => workflowApi.revisePlan(session.access_token, hunt.hunt_id, instruction))}>Request revision</button><label>Analyst note<textarea value={note} onChange={(event) => setNote(event.target.value)} /></label><div className="vs-actions"><button disabled={Boolean(busy)} onClick={() => void act("approve", () => workflowApi.approvePlan(session.access_token, hunt.hunt_id, note))}>Approve plan</button><button className="vs-danger" disabled={Boolean(busy) || !note.trim()} onClick={() => void act("reject", () => workflowApi.rejectPlan(session.access_token, hunt.hunt_id, note))}>Reject plan</button></div></>}</> : <p className="vs-empty">Run discovery to generate a plan.</p>}</section>
        <section className="vs-card vs-span"><p className="vs-eyebrow">Bounded action</p><h2>Execution</h2><p className="vs-muted">Uses only the approved, locked plan and limits.</p>{job && <p className="vs-muted" role="status">Job <code>{job.job_id}</code> · {job.status}{job.attempts === undefined ? "" : ` · attempt ${job.attempts}`}{job.last_error ? ` · ${job.last_error}` : ""}</p>}<div className="vs-actions"><button disabled={Boolean(busy) || hunt.state !== "approved"} onClick={() => void act("execute", () => workflowApi.execute(session.access_token, hunt.hunt_id))}>{busy === "execute" ? "Executing…" : "Execute approved hunt"}</button>{canCancel && <button className="vs-danger" disabled={Boolean(busy)} onClick={() => void act("cancel", () => workflowApi.cancel(session.access_token, hunt.hunt_id))}>{busy === "cancel" ? "Cancelling…" : "Cancel hunt"}</button>}</div></section>
        {results && <QuestionAnswers results={results} />}
        {results && <div id="hunt-results" className="vs-results vs-span">{(["findings", "evidence", "entities", "timeline"] as const).map((key) => <ResultCard key={key} title={key[0].toUpperCase() + key.slice(1)} items={results[key]} />)}</div>}
        {report && <section className="vs-card vs-span"><header><div><p className="vs-eyebrow">Final product</p><h2>Editable report</h2></div><span>{report.state} · v{report.version}</span></header><p>The report summarizes the investigation. <a href="#hunt-results">View complete findings and evidence</a>.</p><label>Structured report content<textarea className="vs-code" rows={20} readOnly={report.state === "finalized"} value={reportBody} onChange={(event) => setReportBody(event.target.value)} /></label><div className="vs-actions">{report.state !== "finalized" ? <><button disabled={Boolean(busy)} onClick={() => void saveReport(false)}>Save draft</button><button className="vs-secondary" disabled={Boolean(busy)} onClick={() => void saveReport(true)}>Save and finalize PDF</button></> : <button onClick={() => void workflowApi.downloadPdf(session.access_token, hunt.hunt_id).catch((error) => setError(errorMessage(error)))}>Download PDF</button>}</div></section>}
      </div>
    </main>
  );
}

function Dashboard({ session, onSelect, onSignOut }: { session: Session; onSelect: (hunt: Hunt) => void; onSignOut: () => void }) {
  const pageSize = 50;
  const [hunts, setHunts] = useState<HuntSummary[]>([]);
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined]);
  const [loading, setLoading] = useState(true);
  const [opening, setOpening] = useState<string | null>(null);
  const [error, setError] = useState("");
  const cursor = cursors[cursors.length - 1];
  const visible = hunts.slice(0, pageSize);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    workflowApi.listHunts(session.access_token, { limit: pageSize + 1, cursor })
      .then((items) => { if (active) setHunts(items); })
      .catch((error) => { if (active) { setHunts([]); setError(errorMessage(error)); } })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [session.access_token, cursor]);

  async function openHunt(id: string) {
    setOpening(id);
    setError("");
    try {
      onSelect(await workflowApi.getHunt(session.access_token, id));
    } catch (error) {
      setError(errorMessage(error));
    } finally {
      setOpening(null);
    }
  }

  return (
    <>
      <header className="vs-top">
        <div><p className="vs-eyebrow">Federal SOC workspace</p><strong>Threat Hunt Console</strong></div>
        <div><span>{session.user.display_name}</span><button className="vs-secondary" onClick={onSignOut}>Sign out</button></div>
      </header>
      <main className="vs-dashboard">
        <section aria-busy={loading || Boolean(opening)}>
          <h1>Threat hunts</h1><p className="vs-muted">Create a bounded investigation or resume one.</p>
          <StatusMessage error={error} />
          {loading ? <p className="vs-muted" role="status">Loading hunts…</p> : visible.length ? visible.map((hunt) => (
            <button className="vs-hunt-row" key={hunt.hunt_id} disabled={Boolean(opening)} onClick={() => void openHunt(hunt.hunt_id)}>
              <span><strong>{hunt.title}</strong><small>{hunt.hypothesis}</small></span>
              <span>{opening === hunt.hunt_id ? "Opening…" : hunt.state.replaceAll("_", " ")}</span>
            </button>
          )) : !error && <p className="vs-empty">{cursors.length === 1 ? "No hunts yet. Create your first investigation." : "No more hunts on this page."}</p>}
          <nav className="vs-actions" aria-label="Hunt pages">
            <button className="vs-secondary" disabled={loading || Boolean(opening) || cursors.length === 1} onClick={() => setCursors((pages) => pages.slice(0, -1))}>Previous</button>
            <span aria-live="polite">Page {cursors.length}</span>
            <button className="vs-secondary" disabled={loading || Boolean(opening) || hunts.length <= pageSize} onClick={() => setCursors((pages) => [...pages, visible[pageSize - 1].hunt_id])}>Next</button>
          </nav>
        </section>
        <CreateHuntForm token={session.access_token} onCreated={onSelect} />
      </main>
    </>
  );
}

export default function ThreatHuntApp() {
  const [session, setSession] = useState<Session | null | undefined>(undefined);
  const [selected, setSelected] = useState<Hunt | null>(null);

  useEffect(() => {
    let active = true;
    const handleExpiry = () => {
      setSession(null);
      setSelected(null);
    };
    window.addEventListener("threat-hunt-auth-expired", handleExpiry);
    void workflowApi.me()
      .then((restored) => { if (active) setSession(restored); })
      .catch(() => { if (active) setSession(null); });
    return () => {
      active = false;
      window.removeEventListener("threat-hunt-auth-expired", handleExpiry);
    };
  }, []);
  if (session === undefined) return <main className="vs-login"><p className="vs-muted">Restoring session…</p></main>;
  if (!session) return <Login onLogin={setSession} />;
  if (selected) return <Workspace session={session} initial={selected} onBack={() => setSelected(null)} />;
  return <Dashboard session={session} onSelect={setSelected} onSignOut={() => {
    void workflowApi.logout().finally(() => setSession(null));
  }} />;
}
