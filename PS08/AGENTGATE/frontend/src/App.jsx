import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, ShieldCheck, ShieldAlert, RefreshCw, Download, Search, Filter,
  CheckCircle2, XCircle, Clock3, Database, LockKeyhole, Server, ChevronLeft,
  ChevronRight, ExternalLink, KeyRound, Eye, EyeOff, AlertTriangle, Radio,
  ArrowUpRight, FileJson, FileSpreadsheet, Menu, X
} from "lucide-react";

const DEFAULT_API = import.meta.env.VITE_AGENTGATE_API_URL || "http://127.0.0.1:8000";
const fmtDate = (v) => {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? String(v) : d.toLocaleString();
};
const statusTone = (v) => {
  const s = String(v || "").toUpperCase();
  if (["ALLOW", "ALLOWED", "ALLOW_READ", "ALLOW_SAVE", "ALLOW_DELIVER", "PASS", "TRUE"].includes(s) || s.includes("ALLOW")) return "good";
  if (["BLOCK", "BLOCKED", "DENY", "DENIED", "FAIL", "FALSE"].includes(s) || s.includes("BLOCK") || s.includes("DENY")) return "bad";
  return "neutral";
};
function App() {
  const [apiUrl, setApiUrl] = useState(DEFAULT_API);
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [connected, setConnected] = useState(false);
  const [health, setHealth] = useState("disconnected");
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [verify, setVerify] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [filter, setFilter] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [page, setPage] = useState(0);
  const [pageSize] = useState(50);
  const [selected, setSelected] = useState(null);
  const [mobileMenu, setMobileMenu] = useState(false);
  const base = apiUrl.trim().replace(/\/+$/, "");
  const headers = useMemo(() => ({ "Authorization": `Bearer ${apiKey.trim()}` }), [apiKey]);

  const request = useCallback(async (path, options = {}) => {
    if (!apiKey.trim()) throw new Error("Enter your Gateway API key to authenticate.");
    let response;
    try {
      response = await fetch(`${base}${path}`, { ...options, headers: { ...headers, ...(options.headers || {}) } });
    } catch {
      throw new Error("Cannot reach the Gateway API. Check the API URL, server status, and CORS configuration.");
    }
    if (response.status === 401) throw new Error("401 Unauthorized — the Gateway API key or session is invalid.");
    if (response.status === 403) throw new Error("403 Forbidden — this identity is not authorized to view audit data.");
    if (!response.ok) {
      let message = `Request failed (${response.status})`;
      try { const data = await response.json(); message = data.detail || message; } catch {}
      throw new Error(message);
    }
    return response;
  }, [base, headers, apiKey]);

  const loadHealth = useCallback(async () => {
    try {
      const res = await fetch(`${base}/health`);
      if (!res.ok) throw new Error();
      setHealth("online");
      setConnected(true);
      return true;
    } catch {
      setHealth("offline");
      setConnected(false);
      return false;
    }
  }, [base]);

  const loadAudit = useCallback(async (requestedPage = page) => {
    setLoading(true); setError(""); setNotice("");
    try {
      const params = new URLSearchParams({ limit: String(pageSize), offset: String(requestedPage * pageSize) });
      const query = filter.trim();
      if (query) {
        // Search uses exact-match backend filters, avoiding arbitrary SQL/query construction.
        const [key, ...rest] = query.split(":");
        const value = rest.join(":").trim();
        const allowed = ["user_id", "session_id", "principal", "action", "resource", "decision", "code"];
        if (value && allowed.includes(key.trim())) params.set(key.trim(), value);
        else if (value) throw new Error("Use an exact filter like decision:BLOCK or principal:agent-name.");
      }
      if (decisionFilter !== "all") params.set("decision", decisionFilter);
      const res = await request(`/v1/audit?${params.toString()}`);
      const data = await res.json();
      const rows = Array.isArray(data) ? data : (data.events || []);
      setEvents(rows);
      setTotal(data.total ?? rows.length);
      setPage(requestedPage);
      setConnected(true); setHealth("online");
    } catch (e) { setError(e.message || "Unable to load audit events."); }
    finally { setLoading(false); }
  }, [request, filter, decisionFilter, page, pageSize]);

  const verifyAudit = useCallback(async () => {
    setError(""); setNotice("");
    try {
      const res = await request("/v1/audit/verify");
      const data = await res.json();
      setVerify(data);
      setNotice(data.valid ? "Audit hash chain verified successfully." : "Integrity verification FAILED. Investigate immediately.");
    } catch (e) { setError(e.message); }
  }, [request]);

  const connect = async () => {
    setError(""); setNotice("");
    if (!base) { setError("Enter the Gateway API URL."); return; }
    const online = await loadHealth();
    if (!online) { setError("Gateway API is offline or unreachable. Start the backend and verify its URL."); return; }
    await loadAudit(0);
    await verifyAudit();
  };
  useEffect(() => { loadHealth(); }, [loadHealth]);

  const visibleEvents = events.filter((e) => {
    if (!decisionFilter || decisionFilter === "all") return true;
    return String(e.decision || e.status || "").toUpperCase().includes(decisionFilter);
  });
  const allowCount = visibleEvents.filter(e => statusTone(e.decision || e.status) === "good").length;
  const blockCount = visibleEvents.filter(e => statusTone(e.decision || e.status) === "bad").length;
  const latest = visibleEvents[0]?.timestamp || visibleEvents[0]?.created_at;
  const exportData = async (format) => {
    setError(""); setNotice("");
    try {
      const res = await request(`/v1/audit/export?format=${format}&limit=5000`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = `agentgate-audit.${format === "csv" ? "csv" : "json"}`;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
      setNotice(`${format.toUpperCase()} export downloaded.`);
    } catch (e) { setError(e.message); }
  };
  const openEvent = async (event) => {
    const id = event.id ?? event.event_id;
    if (!id) { setSelected(event); return; }
    try {
      const res = await request(`/v1/audit/${id}`);
      setSelected(await res.json());
    } catch { setSelected(event); }
  };

  return <div className="app-shell">
    <aside className={`sidebar ${mobileMenu ? "sidebar-open" : ""}`}>
      <div className="brand"><div className="brand-mark" aria-hidden="true"><svg viewBox="0 0 40 40" focusable="false"><path className="brand-mark-shield" d="M20 3.5 34 9v9.2c0 8.5-5.8 14.8-14 18.3C11.8 33 6 26.7 6 18.2V9l14-5.5Z"/><path className="brand-mark-bolt" d="m22.5 9.5-9 12h6.2l-2 9 9-13h-6.2l2-8Z"/></svg></div><div><strong>FIREWALL</strong><span>AGENTGATE SECURITY</span></div><button className="mobile-close" onClick={() => setMobileMenu(false)}><X size={18}/></button></div>
      <div className="workspace-label">WORKSPACE</div>
      <button className="nav-item active"><Activity size={17}/> Command center <span className="nav-dot"/></button>
      <button className="nav-item" onClick={() => document.getElementById("audit-table")?.scrollIntoView({ behavior: "smooth" })}><Database size={17}/> Audit events</button>
      <button className="nav-item" onClick={verifyAudit}><ShieldCheck size={17}/> Chain integrity</button>
      <div className="sidebar-spacer"/>
      <div className="side-status"><span className={`status-dot ${health === "online" ? "online" : ""}`}/><div><b>Firewall gateway</b><small>{health === "online" ? "Connected" : health === "offline" ? "Offline" : "Checking…"}</small></div><Radio size={15}/></div>
      <div className="sidebar-footer">FIREWALL <span>•</span> PHASE 05<br/><small>Policy defense · Local audit mode</small></div>
    </aside>
    {mobileMenu && <div className="scrim" onClick={() => setMobileMenu(false)}/>}
    <main className="main-area">
      <header className="topbar"><button className="mobile-menu" onClick={() => setMobileMenu(true)}><Menu size={20}/></button><div className="crumb">Firewall <span>/</span> <b>Command center</b></div><div className="topbar-right"><span className={`connection-pill ${health}`}><span/> {health === "online" ? "API online" : health === "offline" ? "API offline" : "Checking API"}</span><div className="avatar">FW</div></div></header>
      <div className="page-content">
        <section className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line"/> FIREWALL OPERATIONS</div><h1>Command center<span>.</span></h1><p>Monitor access decisions, inspect audit trails, and verify system integrity.</p></div><button className="btn btn-primary" onClick={() => connect()} disabled={loading}><RefreshCw size={16} className={loading ? "spin" : ""}/> {loading ? "Refreshing…" : "Refresh data"}</button></section>
        <section className="connect-panel">
          <div className="connect-intro"><div className="connect-icon"><KeyRound size={18}/></div><div><b>Connect to your gateway</b><p>Credentials stay in this browser tab and are not saved to local storage.</p></div></div>
          <div className="connect-fields"><label>API BASE URL<input value={apiUrl} onChange={e => setApiUrl(e.target.value)} placeholder="http://127.0.0.1:8000" spellCheck="false"/></label><label className="key-field">GATEWAY API KEY<div className="key-input"><input type={showKey ? "text" : "password"} value={apiKey} onChange={e => setApiKey(e.target.value)} placeholder="Paste API key" autoComplete="off"/><button aria-label="Show or hide key" onClick={() => setShowKey(!showKey)}>{showKey ? <EyeOff size={16}/> : <Eye size={16}/>}</button></div></label><button className="btn btn-dark connect-btn" onClick={connect} disabled={loading}><LockKeyhole size={15}/> Connect</button></div>
          <div className="connect-foot"><span><LockKeyhole size={13}/> Bearer authentication</span><span><Server size={13}/> {apiUrl || DEFAULT_API}</span></div>
        </section>
        {error && <div className="alert alert-error"><AlertTriangle size={17}/><span>{error}</span><button onClick={() => setError("")}><X size={15}/></button></div>}
        {notice && <div className={`alert ${notice.toLowerCase().includes("failed") ? "alert-error" : "alert-success"}`}><CheckCircle2 size={17}/><span>{notice}</span><button onClick={() => setNotice("")}><X size={15}/></button></div>}
        <section className="metric-grid">
          <Metric icon={<Database size={18}/>} label="AUDIT EVENTS" value={total.toLocaleString()} foot="Matching server-side records" tone="violet"/>
          <Metric icon={<CheckCircle2 size={18}/>} label="ALLOWED · CURRENT PAGE" value={allowCount.toLocaleString()} foot="Visible page only" tone="green"/>
          <Metric icon={<ShieldAlert size={18}/>} label="BLOCKED · CURRENT PAGE" value={blockCount.toLocaleString()} foot="Visible page only" tone="red"/>
          <Metric icon={<ShieldCheck size={18}/>} label="CHAIN INTEGRITY" value={verify ? (verify.valid ? "Verified" : "Failed") : "Not checked"} foot={verify ? `${verify.events_checked ?? 0} events checked` : "Run integrity check"} tone={verify?.valid ? "green" : verify && !verify.valid ? "red" : "blue"}/>
        </section>
        <section className="content-grid">
          <div className="panel integrity-panel"><div className="panel-heading"><div><span className="section-kicker">AUDIT HEALTH</span><h2>Integrity status</h2></div><span className={`mini-tag ${verify?.valid ? "tag-green" : verify && !verify.valid ? "tag-red" : "tag-muted"}`}>{verify ? (verify.valid ? "HEALTHY" : "ALERT") : "UNVERIFIED"}</span></div>
            <div className={`integrity-visual ${verify?.valid ? "verified" : verify && !verify.valid ? "failed" : ""}`}><div className="integrity-ring"><div className="ring-core">{verify?.valid ? <CheckCircle2 size={31}/> : verify && !verify.valid ? <XCircle size={31}/> : <ShieldCheck size={31}/>}</div></div><div><b>{verify ? (verify.valid ? "Hash chain is valid" : "Integrity check failed") : "Verify your audit chain"}</b><p>{verify ? `${verify.events_checked ?? 0} event records checked using ${verify.algorithm || "configured integrity algorithm"}.` : "Run a check to validate the local HMAC-SHA256 audit chain."}</p></div></div>
            <div className="integrity-details"><div><span>FIRST EVENT</span><b>#{verify?.first_event_id ?? "—"}</b></div><div><span>LATEST EVENT</span><b>#{verify?.last_event_id ?? "—"}</b></div><div><span>LAST LOADED</span><b>{latest ? fmtDate(latest) : "—"}</b></div></div>
            <button className="btn btn-outline full-btn" onClick={verifyAudit}><ShieldCheck size={16}/> Verify integrity now <ArrowUpRight size={15}/></button>
          </div>
          <div className="panel distribution-panel"><div className="panel-heading"><div><span className="section-kicker">LIVE SNAPSHOT</span><h2>Decision activity</h2></div><span className="live-label"><span/> CURRENT PAGE</span></div>
            <div className="distribution-total"><div><strong>{visibleEvents.length}</strong><span>events loaded</span></div><span className="period-chip">Latest {pageSize}</span></div>
            <div className="bar-row"><div className="bar-label"><span className="legend-dot green-dot"/>Allowed <b>{allowCount}</b></div><div className="bar-track"><div className="bar-fill bar-green" style={{width: `${visibleEvents.length ? allowCount / visibleEvents.length * 100 : 0}%`}}/></div></div>
            <div className="bar-row"><div className="bar-label"><span className="legend-dot red-dot"/>Blocked <b>{blockCount}</b></div><div className="bar-track"><div className="bar-fill bar-red" style={{width: `${visibleEvents.length ? blockCount / visibleEvents.length * 100 : 0}%`}}/></div></div>
            <div className="distribution-note"><Clock3 size={15}/><span>Counts reflect the currently loaded page and filters, not all historical records.</span></div>
            <div className="export-row"><button className="btn btn-outline" onClick={() => exportData("json")}><FileJson size={15}/> Export JSON</button><button className="btn btn-outline" onClick={() => exportData("csv")}><FileSpreadsheet size={15}/> Export CSV</button></div>
          </div>
        </section>
        <section className="panel audit-panel" id="audit-table"><div className="panel-heading audit-heading"><div><span className="section-kicker">SECURITY RECORDS</span><h2>Audit events <span className="count-chip">{total}</span></h2><p>Search exact fields or open a record for its full event payload.</p></div><button className="btn btn-outline small-refresh" onClick={() => loadAudit(0)} disabled={loading}><RefreshCw size={14} className={loading ? "spin" : ""}/> Reload</button></div>
          <div className="table-toolbar"><div className="search-wrap"><Search size={16}/><input value={filter} onChange={e => setFilter(e.target.value)} onKeyDown={e => e.key === "Enter" && loadAudit(0)} placeholder="Exact filter, e.g. decision:BLOCK"/><button onClick={() => loadAudit(0)}><Search size={14}/></button></div><div className="toolbar-right"><Filter size={15}/><select value={decisionFilter} onChange={e => {setDecisionFilter(e.target.value); setPage(0);}}><option value="all">All decisions</option><option value="ALLOW">Allow</option><option value="BLOCK">Block</option></select></div></div>
          <div className="table-scroll"><table><thead><tr><th>EVENT</th><th>DECISION</th><th>WHO / PRINCIPAL</th><th>ACTION</th><th>RESOURCE</th><th>WHEN</th><th></th></tr></thead><tbody>
            {loading && <tr><td colSpan="7" className="table-state"><RefreshCw size={17} className="spin"/> Loading audit events…</td></tr>}
            {!loading && visibleEvents.map((e, i) => {const decision = e.decision || e.status || e.allowed; const tone = statusTone(decision); return <tr key={e.id ?? e.event_id ?? i} onClick={() => openEvent(e)} className="event-row"><td><span className="event-id">#{e.id ?? e.event_id ?? "—"}</span></td><td><span className={`decision-pill ${tone}`}>{tone === "good" ? <CheckCircle2 size={13}/> : tone === "bad" ? <XCircle size={13}/> : <Activity size={13}/>} {String(decision ?? "UNKNOWN").toUpperCase()}</span></td><td><div className="primary-cell">{e.user_id || e.principal || "UNKNOWN"}</div><div className="secondary-cell">{e.principal && e.user_id ? e.principal : e.session_id || "—"}</div></td><td>{e.action || e.action_type || "—"}</td><td><span className="resource-cell">{e.resource || e.resource_id || "—"}</span></td><td><span className="date-cell">{fmtDate(e.timestamp || e.created_at)}</span></td><td><button className="row-open" aria-label="Open event" onClick={(ev) => {ev.stopPropagation(); openEvent(e);}}><ArrowUpRight size={15}/></button></td></tr>;})}
            {!loading && !visibleEvents.length && <tr><td colSpan="7" className="table-state"><Database size={20}/><b>No audit events to show</b><span>Connect with an authorized audit-reader identity, then refresh.</span></td></tr>}
          </tbody></table></div>
          <div className="table-footer"><span>Showing {total ? page * pageSize + 1 : 0}–{Math.min((page + 1) * pageSize, total)} of {total} events</span><div><button className="pager-btn" disabled={page === 0 || loading} onClick={() => loadAudit(page - 1)}><ChevronLeft size={15}/> Previous</button><span className="page-count">Page {page + 1}</span><button className="pager-btn" disabled={loading || (page + 1) * pageSize >= total} onClick={() => loadAudit(page + 1)}>Next <ChevronRight size={15}/></button></div></div>
        </section>
        <footer className="page-footer"><span><ShieldCheck size={14}/> FIREWALL · POWERED BY AGENTGATE</span><span>Local audit mode <i/> External WORM archive excluded</span></footer>
      </div>
    </main>
    {selected && <div className="modal-backdrop" onClick={() => setSelected(null)}><section className="event-modal" onClick={e => e.stopPropagation()}><div className="modal-header"><div><span className="section-kicker">AUDIT RECORD</span><h2>Event #{selected.id ?? selected.event_id ?? "—"}</h2></div><button className="modal-close" onClick={() => setSelected(null)}><X size={18}/></button></div><pre>{JSON.stringify(selected, null, 2)}</pre><div className="modal-actions"><button className="btn btn-outline" onClick={() => navigator.clipboard?.writeText(JSON.stringify(selected, null, 2))}>Copy JSON</button><button className="btn btn-primary" onClick={() => setSelected(null)}>Close details</button></div></section></div>}
  </div>;
}
function Metric({ icon, label, value, foot, tone }) {
  return <div className="metric-card"><div className={`metric-icon ${tone}`}>{icon}</div><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-foot"><span className={`foot-mark ${tone}`}/>{foot}</div></div>;
}
export default App;
