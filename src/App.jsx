
import React, { useEffect, useMemo, useRef, useState } from "react";
import jsQR from "jsqr";
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight,
  ArrowUpRight as ExternalLink, BarChart3, Bell, Check,
  ChevronDown, ChevronRight, CircleHelp, Clock3, Download,
  FileCheck2, FileSearch, Fingerprint, Globe, History,
  LayoutDashboard, Link2, LockKeyhole, Menu, MessageSquareText,
  MoreHorizontal, QrCode, Search, Shield, ShieldAlert,
  ShieldCheck, ShieldEllipsis, Sparkles, Target, Upload,
  X, Zap
} from "lucide-react";
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis
} from "recharts";

const NAV = [
  { label: "Overview", icon: LayoutDashboard, group: "WORKSPACE" },
  { label: "URL Investigator", icon: Link2, group: "WORKSPACE" },
  { label: "QR Scanner", icon: QrCode, group: "WORKSPACE" },
  { label: "Message Lab", icon: MessageSquareText, group: "WORKSPACE" },
  { label: "Investigations", icon: History, group: "INTELLIGENCE" },
  { label: "Methodology", icon: ShieldCheck, group: "INTELLIGENCE" }
];

const now = () => new Date().toISOString();
const makeId = () => "TS-" + Date.now().toString(36).toUpperCase();

function readHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem("traceshield-history") || "[]");
    return Array.isArray(parsed) ? parsed.slice(0, 100) : [];
  } catch {
    return [];
  }
}

function safeUrl(raw) {
  const value = raw.trim();

  if (!value) throw new Error("Enter a URL to investigate.");
  if (value.length > 2048) throw new Error("URL is too long.");
  if (/\s/.test(value) || /[\u0000-\u001f]/.test(value)) {
    throw new Error("Remove whitespace and control characters from the URL.");
  }

  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(value)
    ? value
    : "https://" + value;

  let url;
  try {
    url = new URL(candidate);
  } catch {
    throw new Error("This URL could not be parsed.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }

  if (!url.hostname || url.username || url.password) {
    throw new Error("Invalid hostname or embedded credentials.");
  }

  return { value: candidate, url, host: url.hostname.toLowerCase() };
}

function inspectUrl(raw) {
  const { value, url, host } = safeUrl(raw);
  const findings = [];
  let score = 0;

  const add = (points, title, detail) => {
    score += points;
    findings.push({ points, title, detail });
  };

  const ipv4 =
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) ||
    /^\[[\da-f:]+\]$/i.test(host);

  if (ipv4) add(25, "IP-based destination", "An IP address is used instead of a conventional domain name.");
  if (url.protocol === "http:") add(8, "Unencrypted HTTP", "The URL does not use HTTPS. This alone does not prove phishing.");
  if (value.length > 100) add(8, "Long URL", "The URL is long and may make the destination harder to recognise.");
  if (value.length > 180) add(7, "Very long URL", "The unusually long URL deserves manual inspection.");
  if (host.split(".").length >= 5) add(12, "Deep subdomain structure", "Several hostname levels may obscure the registrable domain.");
  if (host.includes("xn--")) add(12, "Internationalised hostname", "Punycode can represent legitimate domains but deserves closer inspection.");
  if (host.includes("-")) add(4, "Hyphenated hostname", "Hyphens can be legitimate; this is only a weak contextual indicator.");
  if (host.length > 50) add(7, "Long hostname", "The hostname is unusually long.");
  if (/@/.test(url.host)) add(15, "At-sign in URL authority", "This URL structure can obscure which host is being visited.");

  const terms = {
    login: 4, verify: 6, account: 4, password: 8,
    wallet: 5, banking: 5, signin: 5, recovery: 4,
    confirm: 3, update: 3
  };
  const matched = Object.keys(terms).filter(term => value.toLowerCase().includes(term));

  if (matched.length) {
    add(
      Math.min(14, matched.reduce((sum, term) => sum + terms[term], 0)),
      "Sensitive-action keywords",
      `Found contextual terms: ${matched.join(", ")}. Legitimate websites can use these terms too.`
    );
  }

  if (/%(?:40|2f|3a)/i.test(value)) {
    add(8, "Encoded URL delimiters", "Encoded delimiters can make the URL harder to interpret.");
  }

  score = Math.min(100, score);

  if (!findings.length) {
    findings.push({
      points: 0,
      title: "No listed indicators triggered",
      detail: "The limited ruleset found no listed warning. This does not establish safety."
    });
  }

  const level = score >= 50 ? "High" : score >= 25 ? "Elevated" : "Lower";

  return {
    id: makeId(), timestamp: now(), type: "URL",
    input: raw, host, score, level, findings,
    advice: level === "High"
      ? "Avoid opening this link or sharing information. Verify the destination using the organisation's official website."
      : level === "Elevated"
      ? "Pause and verify the domain independently before proceeding."
      : "Few listed indicators were detected. Verify independently; a low score does not prove safety.",
    method: "URL structure heuristic rules v1",
    limitations: "Not a trained classifier, calibrated probability, or live reputation check."
  };
}

function inspectMessage(text) {
  if (!text.trim()) throw new Error("Paste a message first.");
  if (text.length > 12000) throw new Error("Message exceeds 12,000 characters.");

  const findings = [];
  let score = 0;

  const rules = [
    [/\b(urgent|immediately|act now|expires today|within 24 hours)\b/i, 12, "Urgency pressure", "The message uses urgency that may pressure a recipient."],
    [/\b(password|otp|one.time.password|passcode|cvv)\b/i, 18, "Credential-related language", "The message references authentication secrets."],
    [/\b(account suspended|account blocked|account locked|verify your account)\b/i, 18, "Account-threat language", "The message may pressure the recipient to resolve an account issue."],
    [/\b(prize|winner|claim your reward|free gift|lottery)\b/i, 12, "Unexpected reward", "Unexpected rewards can be used in social-engineering attempts."],
    [/\b(gift card|wire transfer|crypto payment|send money)\b/i, 16, "Payment request", "The text references a payment or transfer."],
    [/\b(click here|verify now|confirm your details|open the link)\b/i, 12, "Action prompt", "The text encourages an online action."],
    [/\b(keep this secret|do not tell anyone|confidential payment)\b/i, 15, "Secrecy pressure", "The text uses secrecy language associated with some scams."]
  ];

  rules.forEach(([pattern, points, title, detail]) => {
    if (pattern.test(text)) {
      score += points;
      findings.push({ points, title, detail });
    }
  });

  const urls = [...new Set(
    text.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || []
  )].map(url => url.replace(/[.,!?;:)]+$/, "")).slice(0, 10);

  if (urls.length) {
    score += 8;
    findings.push({
      points: 8,
      title: "Embedded links",
      detail: `${urls.length} link(s) found. A link alone does not establish maliciousness.`
    });
  }

  score = Math.min(100, score);
  if (!findings.length) {
    findings.push({
      points: 0, title: "No listed rules triggered",
      detail: "Sophisticated scams may avoid these patterns. No match is not proof of legitimacy."
    });
  }

  const level = score >= 45 ? "High" : score >= 22 ? "Elevated" : "Lower";

  return {
    id: makeId(), timestamp: now(), type: "Message",
    input: text, score, level, findings, urls,
    advice: level === "High"
      ? "Do not share credentials or payment details. Verify the request through an independently obtained official contact."
      : level === "Elevated"
      ? "Pause and verify the sender through another trusted channel."
      : "Few listed indicators were detected. This does not establish legitimacy.",
    method: "Social-engineering pattern rules v1",
    limitations: "No trained NLP model, sender verification, or guarantee of detection."
  };
}

function inspectQR(file) {
  return new Promise((resolve, reject) => {
    const image = new Image();
    const objectURL = URL.createObjectURL(file);

    image.onload = () => {
      try {
        if (image.width * image.height > 16000000) {
          throw new Error("Image dimensions are too large.");
        }

        const canvas = document.createElement("canvas");
        canvas.width = image.width;
        canvas.height = image.height;

        const ctx = canvas.getContext("2d", { willReadFrequently: true });
        ctx.drawImage(image, 0, 0);

        const pixels = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const decoded = jsQR(pixels.data, pixels.width, pixels.height);

        URL.revokeObjectURL(objectURL);

        if (!decoded) throw new Error("No readable QR code detected.");

        const content = decoded.data;
        let result = {
          id: makeId(), timestamp: now(), type: "QR Code",
          input: content.slice(0, 500), decodedContent: content,
          score: null, level: "Unassessed", findings: [{
            points: 0, title: "QR content decoded",
            detail: "Decoding alone cannot determine whether this content is safe."
          }],
          advice: "Verify the decoded destination before opening it.",
          method: "Local QR decoding using jsQR",
          limitations: "Decoding alone does not establish trustworthiness."
        };

        if (/^https?:\/\//i.test(content)) {
          try {
            result = { ...inspectUrl(content), type: "QR Code", decodedContent: content };
            result.method = "Local QR decoding + URL heuristic rules v1";
          } catch {
            // Keep the decoded content visible even if URL validation fails.
          }
        }

        resolve(result);
      } catch (error) {
        URL.revokeObjectURL(objectURL);
        reject(error);
      }
    };

    image.onerror = () => {
      URL.revokeObjectURL(objectURL);
      reject(new Error("Could not read this image."));
    };

    image.src = objectURL;
  });
}

function downloadFile(filename, content, type = "application/json") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function RiskBadge({ level }) {
  const kind = (level || "Unassessed").toLowerCase();
  return <span className={`risk-badge ${kind}`}>{level || "Unassessed"}</span>;
}

function Metric({ icon: Icon, label, value, change, color = "mint" }) {
  return (
    <div className="metric card">
      <div className={`metric-icon ${color}`}><Icon size={19}/></div>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-foot">
        <span className="metric-dot"/> {change}
      </div>
    </div>
  );
}

function SectionHeading({ eyebrow, title, description, right }) {
  return (
    <div className="section-heading">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {right}
    </div>
  );
}

function App() {
  const [page, setPage] = useState("Overview");
  const [history, setHistory] = useState(readHistory);
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState("");
  const [mobileOpen, setMobileOpen] = useState(false);
  const [toast, setToast] = useState("");

  const qrRef = useRef(null);
  const fileRef = useRef(null);

  useEffect(() => {
    try {
      localStorage.setItem("traceshield-history", JSON.stringify(history));
    } catch {
      setToast("Storage is full. Export reports and clear old history.");
    }
  }, [history]);

  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 3000);
    return () => clearTimeout(timer);
  }, [toast]);

  const stats = useMemo(() => ({
    total: history.length,
    high: history.filter(r => r.level === "High").length,
    elevated: history.filter(r => r.level === "Elevated").length,
    lower: history.filter(r => r.level === "Lower").length
  }), [history]);

  const chartData = useMemo(() => {
    const days = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const key = d.toLocaleDateString("en-CA");
      const items = history.filter(r => r.timestamp?.slice(0, 10) === key);
      days.push({
        day: d.toLocaleDateString("en-US", { weekday: "short" }),
        investigations: items.length,
        elevated: items.filter(r => r.level === "Elevated" || r.level === "High").length
      });
    }
    return days;
  }, [history]);

  const addResult = r => {
    setResult(r);
    setHistory(old => [r, ...old].slice(0, 100));
    setError("");
    setToast("Investigation completed");
  };

  const runURL = () => {
    try {
      setError("");
      setBusy(true);
      addResult(inspectUrl(url));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const runMessage = () => {
    try {
      setError("");
      setBusy(true);
      addResult(inspectMessage(message));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const runQR = async file => {
    if (!file) return;
    setError("");
    if (file.size > 5 * 1024 * 1024) {
      setError("Maximum image size is 5 MB.");
      return;
    }

    setBusy(true);
    try {
      addResult(await inspectQR(file));
    } catch (e) {
      setError(e.message || "QR decoding failed.");
    } finally {
      setBusy(false);
    }
  };

  const exportReport = r => downloadFile(
    `${r.id}.json`, JSON.stringify(r, null, 2)
  );

  const filteredHistory = history.filter(r =>
    `${r.id} ${r.type} ${r.level} ${r.input}`
      .toLowerCase().includes(query.toLowerCase())
  );

  const navigate = next => {
    setPage(next);
    setResult(null);
    setError("");
    setMobileOpen(false);
  };

  const titleMap = {
    "Overview": ["YOUR SECURITY WORKSPACE", "Security, with clarity.", "Your digital threat investigation workspace."],
    "URL Investigator": ["THREAT INVESTIGATION", "Inspect a destination.", "Understand URL risk indicators without opening the destination."],
    "QR Scanner": ["QR INTELLIGENCE", "Decode before you trust.", "Inspect QR content locally before deciding whether to open it."],
    "Message Lab": ["SOCIAL ENGINEERING", "Read between the lines.", "Identify suspicious language and extract embedded links."],
    "Investigations": ["CASE MANAGEMENT", "Your investigation history.", "Review, search and export your saved investigation reports."],
    "Methodology": ["TRANSPARENCY CENTRE", "Evidence over guesswork.", "Learn how TraceShield produces and presents its findings."]
  };

  const [eyebrow, heading, description] = titleMap[page];

  return (
    <div className="app-shell">
      {mobileOpen && <button className="mobile-scrim" onClick={() => setMobileOpen(false)} aria-label="Close menu"/>}

      <aside className={`sidebar ${mobileOpen ? "mobile-open" : ""}`}>
        <button className="brand" onClick={() => navigate("Overview")}>
          <span className="brand-mark"><Shield size={23}/><span/></span>
          <span className="brand-copy"><strong>TraceShield<span>AI</span></strong><small>DIGITAL TRUST PLATFORM</small></span>
          <button className="mobile-close" onClick={e => { e.stopPropagation(); setMobileOpen(false); }} aria-label="Close sidebar"><X size={18}/></button>
        </button>

        <div className="workspace-picker">
          <div className="workspace-avatar"><Fingerprint size={20}/></div>
          <div className="workspace-text"><strong>Security workspace</strong><span>Personal environment</span></div>
          <ChevronDown size={15} className="muted-icon"/>
        </div>

        {["WORKSPACE", "INTELLIGENCE"].map(group => (
          <div className="nav-group" key={group}>
            <div className="nav-label">{group}</div>
            {NAV.filter(n => n.group === group).map(item => {
              const Icon = item.icon;
              return (
                <button key={item.label} className={`nav-item ${page === item.label ? "active" : ""}`} onClick={() => navigate(item.label)}>
                  <Icon size={18}/><span>{item.label}</span>
                  {item.label === "Investigations" && history.length > 0 && <span className="nav-count">{history.length}</span>}
                  {page === item.label && <span className="active-indicator"/>}
                </button>
              );
            })}
          </div>
        ))}

        <div className="sidebar-spacer"/>

        <div className="sidebar-security">
          <div className="security-icon"><LockKeyhole size={18}/></div>
          <strong>Privacy-first analysis</strong>
          <p>Submitted URLs are parsed locally. The app does not open destinations.</p>
          <div className="status-line"><span className="status-dot"/> Local engine ready</div>
        </div>

        <div className="profile">
          <div className="profile-avatar">TS</div>
          <div className="profile-copy"><strong>Security Analyst</strong><span>Demo workspace</span></div>
          <MoreHorizontal size={19}/>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open menu"><Menu size={20}/></button>
            <div className="breadcrumbs"><span>Workspace</span><ChevronRight size={14}/><strong>{page}</strong></div>
          </div>
          <div className="topbar-right">
            <div className="system-status"><span className="status-dot"/> System operational</div>
            <button className="icon-button" title="Methodology" onClick={() => navigate("Methodology")}><CircleHelp size={18}/></button>
            <button className="top-avatar" title="Demo workspace">TS</button>
          </div>
        </header>

        <div className="content">
          <div className="page-heading">
            <div><div className="eyebrow">{eyebrow}</div><h1>{heading}</h1><p>{description}</p></div>
            <div className="heading-actions">
              <span className="live-chip"><span className="status-dot"/> ENGINE READY</span>
              <button className="button button-primary" onClick={() => navigate("URL Investigator")}><Sparkles size={16}/> New investigation</button>
            </div>
          </div>

          {page === "Overview" && (
            <>
              <div className="hero-banner">
                <div className="hero-content">
                  <div className="hero-tag"><Sparkles size={13}/> EXPLAINABLE CYBER INTELLIGENCE</div>
                  <h2>See the signal.<br/><span>Understand the threat.</span></h2>
                  <p>Investigate suspicious links, QR codes and digital messages with transparent security indicators and evidence-based guidance.</p>
                  <button className="button button-primary" onClick={() => navigate("URL Investigator")}>Start an investigation <ChevronRight size={17}/></button>
                  <div className="hero-foot"><ShieldCheck size={15}/> Privacy-first · No automatic URL fetching</div>
                </div>
                <div className="hero-art" aria-hidden="true">
                  <div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="orbit orbit-three"/>
                  <div className="hero-core"><ShieldCheck size={64}/><span className="core-spark">✳</span></div>
                  <div className="float-card float-card-top"><span className="float-icon mint-bg"><Activity size={15}/></span><span><b>Evidence analysis</b><small>Explainable indicators</small></span><span className="float-dot"/></div>
                  <div className="float-card float-card-bottom"><span className="float-icon purple-bg"><Fingerprint size={16}/></span><span><b>Digital trust</b><small>Human-readable findings</small></span><Check size={15} className="mint-text"/></div>
                  <div className="art-caption">SIGNALS → EVIDENCE → DECISIONS</div>
                </div>
              </div>

              <div className="metric-grid">
                <Metric icon={FileSearch} label="Total investigations" value={stats.total} change="Saved in this browser" color="mint"/>
                <Metric icon={ShieldAlert} label="High indicators" value={stats.high} change="Requires careful review" color="red"/>
                <Metric icon={AlertTriangle} label="Elevated indicators" value={stats.elevated} change="Verify independently" color="amber"/>
                <Metric icon={Target} label="Lower indicator scores" value={stats.lower} change="Not proof of safety" color="purple"/>
              </div>

              <div className="dashboard-grid">
                <section className="card chart-card">
                  <div className="card-heading"><div><h3>Investigation activity</h3><p>Activity over the last seven days</p></div><span className="chart-label"><span/> Total cases</span></div>
                  <div className="chart-area">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={chartData} margin={{top:12,right:8,left:-20,bottom:0}}>
                        <defs><linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#54e3d1" stopOpacity={0.23}/><stop offset="100%" stopColor="#54e3d1" stopOpacity={0}/></linearGradient></defs>
                        <CartesianGrid stroke="#243044" strokeDasharray="4 5" vertical={false}/>
                        <XAxis dataKey="day" axisLine={false} tickLine={false} tick={{fill:"#8593aa",fontSize:12}} dy={9}/>
                        <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{fill:"#8593aa",fontSize:12}}/>
                        <Tooltip contentStyle={{background:"#111a2a",border:"1px solid #2b3a51",borderRadius:12,color:"#f0f5ff"}}/>
                        <Area type="monotone" dataKey="investigations" stroke="#54e3d1" strokeWidth={2.5} fill="url(#activityFill)" activeDot={{r:5,fill:"#54e3d1",stroke:"#0b121d",strokeWidth:2}}/>
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="chart-foot"><span><span className="legend-dot"/> Investigations recorded</span><span>Actual local history</span></div>
                </section>

                <section className="card modules-card">
                  <div className="card-heading"><div><h3>Investigation modules</h3><p>Choose your analysis workflow</p></div><span className="module-count">03</span></div>
                  {[
                    {icon:Link2,title:"URL Investigator",desc:"Inspect domain and URL indicators",page:"URL Investigator",color:"mint"},
                    {icon:QrCode,title:"QR Intelligence",desc:"Decode QR content locally",page:"QR Scanner",color:"purple"},
                    {icon:MessageSquareText,title:"Message Lab",desc:"Identify suspicious language",page:"Message Lab",color:"blue"}
                  ].map(m => {
                    const Icon = m.icon;
                    return <button className="module-row" key={m.page} onClick={() => navigate(m.page)}><span className={`module-icon ${m.color}`}><Icon size={19}/></span><span className="module-copy"><b>{m.title}</b><small>{m.desc}</small></span><ChevronRight size={17}/></button>;
                  })}
                </section>
              </div>

              <section className="card recent-card">
                <div className="card-heading"><div><h3>Recent investigations</h3><p>Your latest locally saved reports</p></div><button className="text-button" onClick={() => navigate("Investigations")}>View all <ChevronRight size={15}/></button></div>
                {history.length === 0 ? <EmptyState icon={FileSearch} title="Your workspace is ready" text="Run your first investigation to see actual results and evidence here." action={() => navigate("URL Investigator")} actionLabel="Investigate a URL"/> : <InvestigationTable items={history.slice(0,5)} onOpen={setResult} onExport={exportReport}/>}
              </section>
            </>
          )}

          {page === "URL Investigator" && (
            <div className="work-grid">
              <section className="card form-card">
                <div className="card-heading"><div><h3>URL risk investigation</h3><p>Analyse structural indicators without opening the link.</p></div><span className="module-icon mint"><Link2 size={20}/></span></div>
                <form onSubmit={e => {e.preventDefault();runURL();}}>
                  <label className="field-label">Destination URL <span>REQUIRED</span></label>
                  <div className="input-wrap"><Globe size={18}/><input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://example.com/account" autoComplete="off"/></div>
                  <p className="field-help">Enter the complete link or a domain name. The app will not visit it.</p>
                  {error && <div className="error-box"><AlertTriangle size={17}/>{error}</div>}
                  <button className="button button-primary full-button" disabled={busy}>{busy ? "Investigating..." : <><ShieldCheck size={17}/> Analyse URL</>}</button>
                </form>
                <div className="privacy-note"><LockKeyhole size={17}/><span><b>Local analysis</b><small>No destination fetch, credential collection or live reputation lookup.</small></span></div>
              </section>
              <section className="card side-info">
                <div className="eyebrow">ANALYSIS PIPELINE</div><h3>From URL to evidence.</h3><p>Each finding shows which structural indicator was detected and why it matters.</p>
                {["Parse the destination","Inspect hostname structure","Identify contextual keywords","Calculate a heuristic score","Present findings and guidance"].map((s,i)=><div className="pipeline-step" key={s}><span>{String(i+1).padStart(2,"0")}</span><b>{s}</b><Check size={15}/></div>)}
                <div className="note-box"><CircleHelp size={17}/><span>Heuristic indicators are not proof of maliciousness or safety.</span></div>
              </section>
              {result && <div className="result-full"><ResultPanel result={result} onExport={exportReport}/></div>}
            </div>
          )}

          {page === "QR Scanner" && (
            <div className="work-grid">
              <section className="card form-card">
                <div className="card-heading"><div><h3>QR code inspection</h3><p>Decode a QR image before opening its destination.</p></div><span className="module-icon purple"><QrCode size={20}/></span></div>
                <div className="drop-zone" onClick={() => fileRef.current?.click()} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();runQR(e.dataTransfer.files?.[0]);}}>
                  <div className="drop-icon"><Upload size={26}/></div><b>Drop your QR image here</b><p>or click to browse files</p><span>PNG · JPG · WEBP · MAX 5 MB</span>
                  <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={e=>runQR(e.target.files?.[0])}/>
                </div>
                {busy && <div className="loading-line"><span/> Decoding image locally...</div>}
                {error && <div className="error-box"><AlertTriangle size={17}/>{error}</div>}
                <div className="privacy-note"><LockKeyhole size={17}/><span><b>Browser-based decoding</b><small>QR images are decoded locally and are not uploaded to a server by this application.</small></span></div>
              </section>
              <section className="card side-info"><div className="eyebrow">QR INTELLIGENCE</div><h3>Decode. Inspect. Decide.</h3><p>A QR code can conceal a link, text or other content. Decoding is only the first step.</p>
                <div className="qr-illustration"><div className="fake-qr"><QrCode size={100}/><span/></div><div className="scan-line"/></div>
                <div className="note-box"><ShieldAlert size={17}/><span>Never open an unexpected QR destination just because it was decoded successfully.</span></div>
              </section>
              {result && <div className="result-full"><ResultPanel result={result} onExport={exportReport}/></div>}
            </div>
          )}

          {page === "Message Lab" && (
            <div className="work-grid">
              <section className="card form-card">
                <div className="card-heading"><div><h3>Message investigation</h3><p>Inspect text for common social-engineering patterns.</p></div><span className="module-icon blue"><MessageSquareText size={20}/></span></div>
                <form onSubmit={e=>{e.preventDefault();runMessage();}}>
                  <label className="field-label">Suspicious email or message <span>MAX 12,000 CHARACTERS</span></label>
                  <textarea className="message-input" value={message} onChange={e=>setMessage(e.target.value)} maxLength={12000} placeholder={"Paste a suspicious message here...\n\nExample: Your account requires verification. Please review this unexpected request."}/>
                  <div className="textarea-foot"><span>Analysis runs locally in your browser.</span><span>{message.length.toLocaleString()} / 12,000</span></div>
                  {error && <div className="error-box"><AlertTriangle size={17}/>{error}</div>}
                  <button className="button button-primary full-button" disabled={busy}>{busy ? "Investigating..." : <><Sparkles size={17}/> Analyse message</>}</button>
                </form>
                <div className="privacy-note"><LockKeyhole size={17}/><span><b>Privacy first</b><small>Message text is not sent to an AI provider or external analysis API.</small></span></div>
              </section>
              <section className="card side-info"><div className="eyebrow">SOCIAL ENGINEERING</div><h3>Understand the pressure tactics.</h3><p>Look for combinations of language and context, not isolated words alone.</p>
                {[["01","Urgency and fear"],["02","Credential requests"],["03","Unexpected rewards"],["04","Payment pressure"],["05","Embedded links"]].map(([n,t])=><div className="pipeline-step" key={n}><span>{n}</span><b>{t}</b><ChevronRight size={15}/></div>)}
                <div className="note-box"><CircleHelp size={17}/><span>Legitimate messages may trigger rules. Sophisticated scams may evade them.</span></div>
              </section>
              {result && <div className="result-full"><ResultPanel result={result} onExport={exportReport}/></div>}
            </div>
          )}

          {page === "Investigations" && (
            <section className="card recent-card history-page">
              <div className="card-heading"><div><h3>Investigation records</h3><p>Search, review and export reports stored in this browser.</p></div><button className="button button-secondary" onClick={()=>downloadFile("traceshield-history.json",JSON.stringify(history,null,2))}><Download size={16}/> Export all</button></div>
              <div className="search-wrap"><Search size={17}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search by ID, type or assessment..."/></div>
              {filteredHistory.length ? <InvestigationTable items={filteredHistory} onOpen={setResult} onExport={exportReport}/> : <EmptyState icon={History} title="No matching investigations" text="Run a new investigation or try a different search term." action={()=>navigate("URL Investigator")} actionLabel="Start investigation"/>}
              {history.length > 0 && <button className="text-button danger-text" onClick={()=>{if(window.confirm("Clear all locally saved investigation history?")){setHistory([]);setResult(null);}}}>Clear all history</button>}
            </section>
          )}

          {page === "Methodology" && (
            <div className="method-grid">
              <section className="card methodology-card"><div className="eyebrow">TRANSPARENCY FIRST</div><h3>How TraceShield works</h3><p>TraceShield converts observable indicators into understandable findings. Its current implementation uses deterministic rules rather than a trained machine-learning model.</p>
                {[{n:"01",title:"Input validation",text:"Reject malformed URLs and limit input sizes before analysis."},{n:"02",title:"Indicator extraction",text:"Inspect URL structure or match selected social-engineering patterns."},{n:"03",title:"Heuristic assessment",text:"Aggregate rule contributions into a bounded indicator score."},{n:"04",title:"Explainable report",text:"Show findings, limitations and practical recommendations."}].map(s=><div className="method-step" key={s.n}><span>{s.n}</span><div><b>{s.title}</b><p>{s.text}</p></div></div>)}
              </section>
              <section className="card methodology-card"><div className="eyebrow">RESPONSIBLE SECURITY</div><h3>Know the limitations.</h3>
                <div className="limitation-item"><ShieldCheck size={18}/><div><b>What it does</b><p>Parses URLs, decodes QR images, checks selected text patterns and explains triggered rules.</p></div></div>
                <div className="limitation-item"><AlertTriangle size={18}/><div><b>What it does not do</b><p>No live domain reputation, website fetching, sender verification, trained ML model or guarantee of protection.</p></div></div>
                <div className="limitation-item"><LockKeyhole size={18}/><div><b>Data handling</b><p>Analyses run in the browser. Reports and history remain in local browser storage until removed.</p></div></div>
                <div className="note-box"><CircleHelp size={17}/><span>A lower indicator score is not proof that a URL or message is safe.</span></div>
              </section>
            </div>
          )}

          <footer className="app-footer"><div><span className="footer-mark"><ShieldCheck size={15}/></span> <b>TraceShield AI</b> <span>· Explainable digital trust</span></div><div><span className="status-dot"/> Browser-based analysis <span>·</span> Heuristic results only</div></footer>
        </div>
      </main>

      {result && <ResultModal result={result} onClose={()=>setResult(null)} onExport={exportReport}/>}
      {toast && <div className="toast"><Check size={16}/>{toast}</div>}
    </div>
  );
}

function EmptyState({ icon: Icon, title, text, action, actionLabel }) {
  return <div className="empty-state"><div className="empty-icon"><Icon size={25}/></div><h3>{title}</h3><p>{text}</p><button className="button button-secondary" onClick={action}>{actionLabel}<ChevronRight size={15}/></button></div>;
}

function InvestigationTable({ items, onOpen, onExport }) {
  return (
    <div className="table-scroll"><table className="investigation-table"><thead><tr><th>INVESTIGATION</th><th>TYPE</th><th>INDICATOR SCORE</th><th>ASSESSMENT</th><th>DATE</th><th/></tr></thead><tbody>
      {items.map(r=><tr key={r.id}><td><button className="case-link" onClick={()=>onOpen(r)}><span className="case-icon"><FileSearch size={16}/></span><span><b>{r.id}</b><small>{(r.input||"").slice(0,42)}</small></span></button></td><td>{r.type}</td><td>{r.score == null ? "N/A" : `${r.score}/100`}</td><td><RiskBadge level={r.level}/></td><td>{new Date(r.timestamp).toLocaleDateString()}</td><td><button className="icon-button table-action" title="Download report" onClick={()=>onExport(r)}><Download size={15}/></button></td></tr>)}
    </tbody></table></div>
  );
}

function ResultPanel({ result, onExport }) {
  return <section className="card result-panel">
    <div className="card-heading"><div><div className="eyebrow">INVESTIGATION COMPLETE</div><h3>Evidence report</h3><p>{result.id} · {new Date(result.timestamp).toLocaleString()}</p></div><button className="button button-secondary" onClick={()=>onExport(result)}><Download size={16}/> Export JSON</button></div>
    <div className="result-summary">
      <div className="score-ring" style={{"--score":`${result.score ?? 0}%`}}><div><strong>{result.score == null ? "—" : result.score}</strong><small>{result.score == null ? "UNASSESSED" : "OUT OF 100"}</small></div></div>
      <div className="result-overview"><RiskBadge level={result.level}/><h3>{result.level === "High" ? "High indicator score detected" : result.level === "Elevated" ? "Some indicators need attention" : "Fewer listed indicators detected"}</h3><p>{result.advice}</p></div>
    </div>
    <div className="result-section-heading"><h4>Evidence breakdown</h4><span>{result.findings.length} indicator(s)</span></div>
    <div className="findings-list">{result.findings.map((f,i)=><div className="finding" key={`${f.title}-${i}`}><div className="finding-symbol">{f.points ? <AlertTriangle size={17}/> : <FileCheck2 size={17}/>}</div><div className="finding-copy"><b>{f.title}</b><p>{f.detail || f.explanation}</p></div><span className="finding-points">{f.points ? `+${f.points}` : "INFO"}</span></div>)}</div>
    {result.decodedContent && <div className="decoded-box"><b>Decoded QR content</b><code>{result.decodedContent}</code></div>}
    {result.urls?.length > 0 && <div className="decoded-box"><b>Extracted links</b>{result.urls.map(u=><code key={u}>{u}</code>)}</div>}
    <div className="report-caveat"><ShieldAlert size={17}/><span><b>Method:</b> {result.method}. <b>Limitation:</b> {result.limitations}</span></div>
  </section>;
}

function ResultModal({ result, onClose, onExport }) {
  useEffect(() => {
    const handler = e => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  return <div className="modal-backdrop" onMouseDown={e=>{if(e.target===e.currentTarget)onClose();}}><div className="result-modal"><div className="modal-header"><div><div className="eyebrow">SAVED INVESTIGATION</div><h3>{result.id}</h3></div><button className="icon-button" onClick={onClose} aria-label="Close report"><X size={19}/></button></div><ResultPanel result={result} onExport={onExport}/></div></div>;
}

export default App;
