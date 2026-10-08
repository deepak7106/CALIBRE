import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";
const stages = ["URL STRUCTURE", "DOMAIN REPUTATION", "REDIRECT ANALYSIS", "WEBSITE INSPECTION", "THREAT ANALYSIS", "FINAL VERDICT"];

function riskTone(level) {
  return { LOW: "safe", MEDIUM: "warn", HIGH: "danger", CRITICAL: "critical" }[level] || "neutral";
}

function ScanPage() {
  const initialUrl = useMemo(() => new URLSearchParams(window.location.search).get("url") || "", []);
  const [url, setUrl] = useState(initialUrl);
  const [state, setState] = useState(initialUrl ? "analyzing" : "idle");
  const [result, setResult] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [error, setError] = useState("");
  const [stageIndex, setStageIndex] = useState(0);
  const [decision, setDecision] = useState("");

  useEffect(() => {
    if (initialUrl) inspect(initialUrl);
  }, [initialUrl]);

  async function inspect(destination) {
    setState("analyzing");
    setError("");
    setResult(null);
    setEvidence(null);
    setDecision("");
    setStageIndex(0);
    try {
      const response = await fetch(`${API_BASE}/api/analyze/url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: destination }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "TrustShield could not validate this URL.");
      setStageIndex(stages.length - 1);
      setResult(body);
      const evidenceResponse = await fetch(`${API_BASE}/api/scan/${body.scan_id}/evidence`);
      if (!evidenceResponse.ok) throw new Error("Evidence could not be loaded.");
      setEvidence(await evidenceResponse.json());
      setState("complete");
    } catch (err) {
      setError(err.message);
      setState("error");
    }
  }

  function continueToDestination() {
    if (!result || !["LOW", "MEDIUM", "HIGH"].includes(result.analysis.risk_level)) return;
    setDecision("navigation approved for this explicit user action");
    window.location.assign(result.destination_url);
  }

  const level = result?.analysis?.risk_level;
  const tone = riskTone(level);
  return (
    <main className="shell">
      <header className="brand">
        <div className="shield">✓</div>
        <div><strong>TRUSTSHIELD</strong><span>SECURE LINK GATEWAY</span></div>
      </header>
      <section className="card hero">
        <p className="eyebrow">BEFORE YOU CONTINUE</p>
        <h1>TrustShield Security Check</h1>
        <p className="muted">We analyze this link before your browser reaches the destination.</p>
        {!initialUrl && (
          <form onSubmit={(event) => { event.preventDefault(); inspect(url); }}>
            <label htmlFor="url">Link to inspect</label>
            <div className="url-form">
              <input id="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" />
              <button type="submit">Check link</button>
            </div>
          </form>
        )}
        {url && <div className="destination"><span>DESTINATION</span><code>{url}</code></div>}
      </section>
      {state === "analyzing" && (
        <section className="card">
          <h2>Analyzing link</h2>
          <p className="muted">The destination has not been opened.</p>
          <ol className="timeline">
            {stages.map((stage, index) => <li className={index <= stageIndex ? "active" : ""} key={stage}><i />{stage}</li>)}
          </ol>
        </section>
      )}
      {state === "error" && <section className="card error"><h2>Link blocked before analysis</h2><p>{error}</p><button onClick={() => setUrl("")}>Try another link</button></section>}
      {state === "complete" && result && evidence && (
        <section className="card result">
          <div className={`verdict ${tone}`}><span className="verdict-label">{level === "LOW" ? "SAFE" : level === "CRITICAL" ? "CRITICAL THREAT" : "SUSPICIOUS WEBSITE"}</span><strong>{result.analysis.score}/100</strong></div>
          <h2>{result.analysis.category}</h2>
          <p>{evidence.explanation}</p>
          <div className="meta"><span>Confidence: {result.analysis.confidence}%</span><span>Action: {result.analysis.action}</span><span>Uncertainty: {result.analysis.uncertainty ? "yes" : "no"}</span><span>Conflicting evidence: {result.analysis.conflicting_evidence ? "yes" : "no"}</span></div>
          <h3>Evidence</h3>
          {evidence.indicators.length ? <ul className="indicators">{evidence.indicators.map((item) => <li key={item.id}><b>{item.name.replaceAll("_", " ")}</b><span>{item.description}</span><small>{item.id}</small></li>)}</ul> : <p className="muted">No significant threat indicators were found.</p>}
          {result.analysis.explanation_data?.reasons?.length > 0 && <><h3>Why this verdict</h3><ul className="indicators">{result.analysis.explanation_data.reasons.map((reason) => <li key={reason.indicator_ids.join("-")}><span>{reason.text}</span><small>{reason.indicator_ids.join(", ")}</small></li>)}</ul></>}
          {result.analysis.explanation_data?.uncertainties?.length > 0 && <p className="muted">Uncertainty: {result.analysis.explanation_data.uncertainties.map((item) => item.text).join(" ")}</p>}
          {result.analysis.trust_graph?.timeline?.length > 0 && <><h3>Attack timeline</h3><ol className="timeline">{result.analysis.trust_graph.timeline.map((event, index) => <li className="active" key={`${event.timestamp}-${index}`}><i />{event.timestamp} — {event.event_type || event.event}</li>)}</ol></>}
          {result.analysis.trust_graph?.nodes?.length > 0 && <><h3>TrustGraph evidence</h3><div className="graph-list">{result.analysis.trust_graph.nodes.map((node) => <span key={node.id}>{node.type}: {node.label}</span>)}</div><p className="muted">{result.analysis.trust_graph.edges.length} evidence-backed relationships</p></>}
          <div className="actions">
            {level !== "CRITICAL" && <button className={level === "LOW" ? "primary" : "danger-button"} onClick={continueToDestination}>{level === "LOW" ? "Continue to website" : "Continue anyway"}</button>}
            {level !== "LOW" && <button className="secondary" onClick={() => window.history.back()}>Go back</button>}
          </div>
          {decision && <p className="muted">{decision}</p>}
        </section>
      )}
      <footer>TrustShield does not submit credentials, execute downloads, or open destinations during analysis.</footer>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<ScanPage />);
