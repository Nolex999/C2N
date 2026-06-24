import { useState, useEffect, useRef, useCallback, Fragment } from 'react';
import mapboxgl from 'mapbox-gl';
import {
  Activity, History, Mail, LogOut, User, Play, Square, Trash,
  Copy, ExternalLink, CheckCircle, XCircle, AlertCircle,
  ChevronDown, ChevronUp, Globe, MapPin, Info, RefreshCw,
  Download, BarChart, Terminal, Plug, Unplug, Server, Zap,
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

interface DashboardCountry { code: string; count: number; creds: number; open: number; lat?: number; lon?: number; }
interface DashboardPort { port: number; count: number; }
interface DashboardStats { total_scans: number; total_results: number; total_creds: number; total_open: number; countries_hit: number; unique_ips: number; }
interface DashboardData { stats: DashboardStats; by_country: DashboardCountry[]; by_port: DashboardPort[]; recent: any[]; }

export default function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem(TOKEN_KEY));
  const [user, setUser] = useState<UserInfo | null>(null);
  const [checking, setChecking] = useState(true);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'scan' | 'output' | 'invites' | 'devices' | 'settings'>('dashboard');
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
  const setStopping = useState(false)[1];
  const [totalScanned, setTotalScanned] = useState(0);
  const [totalResponded, setTotalResponded] = useState(0);
  const [scanResults, setScanResults] = useState<ScanResultItem[]>([]);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [elapsed, setElapsed] = useState('0:00');
  const stoppedRef = useRef(false);
  const abortRef = useRef<AbortController | null>(null);
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

  // Dashboard
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [dashLoading, setDashLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInitRef = useRef(false);
  const mapInstRef = useRef<mapboxgl.Map | null>(null);

  // Exploit / Devices
  interface ExploitDevice {
    id: number; ip: string; port: number; url: string; device: string;
    username: string; password: string; country_code?: string; org?: string;
    broken?: boolean;
  }
  interface ExploitSession {
    id: string; ip: string; protocol: string; username: string;
    created: number; item_id?: string;
  }
  const [exploitDevices, setExploitDevices] = useState<ExploitDevice[]>([]);
  const [expLoading, setExpLoading] = useState(false);
  const [sessions, setSessions] = useState<ExploitSession[]>([]);
  const [terminalInput, setTerminalInput] = useState('');
  const [terminalOutput, setTerminalOutput] = useState<{sessionId: string; lines: string[];}[]>([]);
  const [connectingId, setConnectingId] = useState<number | null>(null);
  const [autoExploit, setAutoExploit] = useState(false);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Scan filters & expanded rows
  const [filterText, setFilterText] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [expandedScanRows, setExpandedScanRows] = useState<Set<number>>(new Set());

  // Presets
  interface ScanPreset { name: string; region: string; maxIps: number; threads: number; ports: string; countryFilter: string; geoEnrich: boolean; }
  const [presets, setPresets] = useState<ScanPreset[]>(() => {
    try { return JSON.parse(localStorage.getItem('gyd_presets') || '[]'); } catch { return []; }
  });

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
    if (token && activeTab === 'dashboard') fetchDashboard();
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

  const startScan = async () => {
    if (scanning) return;
    setScanning(true);
    setStopping(false);
    stoppedRef.current = false;
    abortRef.current = new AbortController();
    setTotalScanned(0);
    setTotalResponded(0);
    setScanResults([]);
    setLogs([]);
    startRef.current = Date.now();
    setElapsed('0:00');
    timerRef.current = setInterval(tickTimer, 1000);

    addLog(`Starting scan — ${maxIps} targets (streaming)`, 'info');

    try {
      const body: any = { max_ips: maxIps, threads, ports, geo: geoEnrich };
      if (region === 'internet') body.internet = true;
      else body.region = region;
      if (countryFilter.trim()) body.country = countryFilter.trim();

      const response = await apiFetch('/api/scan/stream', {
        method: 'POST',
        body: JSON.stringify(body),
        signal: abortRef.current?.signal,
      });
      if (!response.ok) { addLog('Scan request failed', 'err'); return; }

      const reader = response.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let eventType = '';
      let dataStr = '';

      const flushEvent = () => {
        if (!dataStr) return;
        try {
          const data = JSON.parse(dataStr);
          if (eventType === 'start') {
            setTotalScanned(0);
          } else if (eventType === 'hit') {
            const results: ScanResultItem[] = data.results || [];
            setTotalResponded(p => p + results.length);
            setScanResults(prev => [...prev, ...results]);
            results.forEach((r: ScanResultItem) => {
              if (r.auth_found) addLog(`Found: ${r.url} — ${r.username}:${r.password} [${r.device}]`, 'hit');
              else if (r.no_auth) addLog(`Open: ${r.url} [${r.device}]`, 'hit-open');
            });
          } else if (eventType === 'progress') {
            setTotalScanned(data.scanned);
          } else if (eventType === 'done') {
            addLog(`Scan complete — ${data.results_count} results from ${data.total_scanned} IPs`, 'info');
            toast(`Scan complete: ${data.results_count} results`, 'success');
          }
        } catch (e) { /* skip parse errors */ }
        dataStr = '';
      };

      while (true) {
        const { done, value } = await reader.read();
        if (done) { flushEvent(); break; }
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n');
        buffer = parts.pop() || '';
        for (const line of parts) {
          if (line.startsWith('event: ')) {
            flushEvent();
            eventType = line.slice(7).trim();
          } else if (line.startsWith('data: ')) {
            dataStr = line.slice(6);
          }
        }
      }
    } catch (err: any) {
      if (err.name === 'AbortError') { addLog('Scan aborted.', 'info'); }
      else { addLog(`Scan error: ${err.message}`, 'err'); }
    }

    setScanning(false);
    setStopping(false);
    clearInterval(timerRef.current);
  };

  const stopScan = () => {
    if (stoppedRef.current) return; // prevent duplicate calls
    stoppedRef.current = true;
    setStopping(true);
    abortRef.current?.abort(); // cancel the in-flight HTTP request immediately
    addLog('Stopping…', 'info');
  };

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
      const score = d.score !== undefined ? ` [score=${d.score}]` : '';
      const reasons = d.reasons?.length ? `\nSignals: ${d.reasons.join(', ')}` : '';
      if (d.status === 'ok') {
        updDevice(id, {
          loading: false, status: '✓ Working', showShell: true,
          output: `✓ Credentials accepted${score}\nHTTP ${d.status_code}\n\n${JSON.stringify(d.headers, null, 2)}${reasons}`
        });
        setItems(p => p.map(i => i.id === id ? { ...i, broken: true } : i));
        toast(`Device ${id} — credentials verified`, 'success');
      } else {
        updDevice(id, { loading: false, status: '✗ Failed', output: `✗ ${d.message || 'Failed'}${score}${reasons}` });
      }
    } catch (err: any) {
      updDevice(id, { loading: false, status: '✗ Error', output: `Error: ${err.message}` });
    }
  };

  const bruteDevice = async (id: number) => {
    const s = deviceStates[id];
    if (!s) return;
    updDevice(id, { loading: true, output: 'Brute forcing…' });
    try {
      const r = await apiFetch(`/api/devices/${id}/brute`, {
        method: 'POST', body: JSON.stringify({ max_tries: 50 })
      });
      const d = await r.json();
      if (d.working?.length > 0) {
        const lines = d.working.map((w: any) => `✓ ${w.username}:${w.password} [score=${w.score}] ${w.note || ''}`).join('\n');
        updDevice(id, {
          loading: false, status: `✓ Bruted (${d.working.length})`, showShell: true,
          output: `Found ${d.working.length} working creds (tried ${d.total_tried}):\n\n${lines}`
        });
        setItems(p => p.map(i => i.id === id ? { ...i, broken: true, username: d.working[0].username, password: d.working[0].password } : i));
        toast(`Device ${id} — ${d.working.length} working creds found`, 'success');
      } else {
        updDevice(id, { loading: false, status: '✗ No creds', output: `Tried ${d.total_tried} creds — none worked.` });
      }
    } catch (err: any) {
      updDevice(id, { loading: false, status: '✗ Error', output: `Brute error: ${err.message}` });
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

  // ── Exploit / Device exploitation ──
  const fetchExploitDevices = async () => {
    setExpLoading(true);
    try {
      const r = await apiFetch('/api/exploit/devices');
      if (r.ok) setExploitDevices((await r.json()).devices || []);
    } catch {} finally { setExpLoading(false); }
  };

  const fetchSessions = async () => {
    try {
      const r = await apiFetch('/api/exploit/sessions');
      if (r.ok) setSessions((await r.json()).sessions || []);
    } catch {}
  };

  const connectDevice = async (item: ExploitDevice) => {
    setConnectingId(item.id);
    try {
      const r = await apiFetch('/api/exploit/connect', {
        method: 'POST',
        body: JSON.stringify({ item_id: item.id }),
      });
      if (r.ok) {
        const d = await r.json();
        toast(`Connected via ${d.protocol}`, 'success');
        setTerminalOutput(p => [...p.filter(x => x.sessionId !== d.session_id), { sessionId: d.session_id, lines: [`[${d.protocol}] Connected to ${item.ip}:${item.port}\r\n`] }]);
        fetchSessions();
      } else {
        const d = await r.json();
        toast(d.error || 'Connect failed', 'error');
      }
    } catch (err: any) {
      toast(err.message, 'error');
    } finally { setConnectingId(null); }
  };

  const disconnectDevice = async (sid: string) => {
    try {
      const r = await apiFetch(`/api/exploit/session/${sid}/disconnect`, { method: 'POST' });
      if (r.ok) {
        toast('Disconnected', 'info');
        fetchSessions();
      }
    } catch {}
  };

  const sendCommand = async (sid: string) => {
    if (!terminalInput.trim()) return;
    const cmd = terminalInput.trim();
    setTerminalInput('');
    setTerminalOutput(p => p.map(s => s.sessionId === sid ? { ...s, lines: [...s.lines, `$ ${cmd}\r\n`] } : s));
    try {
      const r = await apiFetch(`/api/exploit/session/${sid}/command`, {
        method: 'POST',
        body: JSON.stringify({ command: cmd }),
      });
      if (r.ok) {
        const d = await r.json();
        const out = (d.output || '') + (d.stderr ? `\r\nstderr:\r\n${d.stderr}` : '');
        setTerminalOutput(p => p.map(s => s.sessionId === sid ? { ...s, lines: [...s.lines, `${out}\r\n`] } : s));
      } else {
        const d = await r.json();
        setTerminalOutput(p => p.map(s => s.sessionId === sid ? { ...s, lines: [...s.lines, `Error: ${d.error || 'command failed'}\r\n`] } : s));
      }
    } catch (err: any) {
      setTerminalOutput(p => p.map(s => s.sessionId === sid ? { ...s, lines: [...s.lines, `Error: ${err.message}\r\n`] } : s));
    }
  };

  const runAutoExploit = async () => {
    setAutoExploit(true);
    toast('Auto-exploit started…', 'info');
    try {
      const r = await apiFetch('/api/exploit/batch', { method: 'POST' });
      if (r.ok) {
        const d = await r.json();
        toast(`Auto-exploit: ${d.total} devices checked`, 'success');
        fetchSessions();
        fetchExploitDevices();
        const reachable = (d.results || []).filter((x: any) => x.status === 'connected' || x.status === 'web_reachable');
        if (reachable.length > 0) {
          const lines = reachable.map((x: any) => `[${x.protocol || 'http'}] ${x.ip} — ${x.status} (sid: ${x.session_id || 'none'})`).join('\r\n');
          setTerminalOutput(p => [...p, { sessionId: 'batch', lines: [`[auto-exploit] ${reachable.length} devices reachable\r\n${lines}\r\n`] }]);
        }
      } else {
        const d = await r.json();
        toast(d.error || 'Batch failed', 'error');
      }
    } catch (err: any) {
      toast(err.message, 'error');
    } finally { setAutoExploit(false); }
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

  // ── Dashboard / Map Data ──

  const COUNTRY_CENTROIDS: Record<string, [number,number]> = {
    US:[-98,38], CA:[-106,56], MX:[-100,23], BR:[-55,-15], AR:[-63,-38], CL:[-71,-35],
    CO:[-74,4], PE:[-76,-10], GB:[-3,55], FR:[2,46], DE:[10,51], IT:[12,42],
    ES:[-4,40], PT:[-8,40], NL:[5,52], BE:[4,50], CH:[8,47], SE:[15,62],
    NO:[10,62], DK:[10,56], PL:[20,52], CZ:[15,50], SK:[18,49], HU:[19,47],
    RO:[25,46], BG:[25,43], GR:[22,39], AT:[14,48], IE:[-8,53], FI:[26,64],
    LT:[24,55], LV:[25,57], EE:[26,59], RU:[40,60], UA:[31,49], BY:[28,54],
    TR:[35,39], NG:[8,8], ZA:[26,-30], EG:[30,27], MA:[-7,32], KE:[38,0],
    DZ:[3,28], TN:[10,34], LY:[17,26], SD:[30,15], GH:[-2,8], CN:[105,35],
    JP:[138,38], IN:[78,20], KR:[128,37], TH:[101,15], VN:[107,14], ID:[120,-5],
    PH:[123,12], MY:[102,4], SG:[104,1], PK:[70,30], BD:[90,24], IR:[54,32],
    IQ:[44,33], SA:[45,24], AE:[55,24], IL:[35,31], JO:[36,31], KW:[48,29],
    QA:[51,25], AU:[134,-25], NZ:[174,-41], UY:[-56,-32], PY:[-58,-23],
    SI:[15,46], HR:[16,45], BA:[18,44], RS:[21,44], ME:[19,43], MK:[22,41],
    AL:[20,41], MD:[29,47], AM:[45,40], GE:[43,42], AZ:[47,40], KZ:[68,48],
    UZ:[64,42], TM:[60,40], KG:[74,41], TJ:[71,39], MN:[105,46], NP:[84,28],
    BT:[90,27], LK:[80,7], MM:[96,22], KH:[105,13], LA:[102,18],
  };

  const fetchDashboard = async () => {
    setDashLoading(true);
    try {
      const r = await apiFetch('/api/dashboard/stats');
      if (r.ok) setDashboard(await r.json());
    } catch {} finally { setDashLoading(false); }
  };

  // ── Mapbox GL JS ──

  useEffect(() => {
    if (mapInitRef.current || checking || !token || !mapRef.current) return;
    mapboxgl.accessToken = 'pk.eyJ1IjoibjBsZXg5OSIsImEiOiJjbXFycnJoOW8wMHZiMnBzaDV1Mzg0c2d0In0.c-ol61AlQs9LiNQ6TCBAig';

    const map = new mapboxgl.Map({
      container: mapRef.current!,
      style: 'mapbox://styles/mapbox/dark-v11',
      center: [0, 20],
      zoom: 1.5,
    });

    map.on('load', () => {
      map.addSource('countries', { type: 'geojson', data: { type: 'FeatureCollection', features: [] } });
      map.addLayer({
        id: 'country-circles',
        type: 'circle',
        source: 'countries',
        paint: {
          'circle-radius': ['interpolate', ['linear'], ['get', 'count'], 1, 5, 10, 15, 100, 30, 500, 45],
          'circle-color': '#2563eb',
          'circle-opacity': 0.75,
          'circle-stroke-width': 2,
          'circle-stroke-color': '#fff',
        },
      });
      map.addLayer({
        id: 'country-labels',
        type: 'symbol',
        source: 'countries',
        layout: {
          'text-field': ['concat', ['get', 'code'], '\n', ['to-string', ['get', 'count']]],
          'text-size': 10,
          'text-offset': [0, 1.8],
          'text-line-height': 1.3,
        },
        paint: {
          'text-color': '#fff',
          'text-halo-color': '#000',
          'text-halo-width': 1.2,
        },
      });
      mapInitRef.current = true;
      updateMapData(map);
    });

    mapInstRef.current = map;

    return () => {
      if (mapInstRef.current) {
        mapInstRef.current.remove();
        mapInitRef.current = false;
        mapInstRef.current = null;
      }
    };
  }, [checking, token]);

  const updateMapData = useCallback((map: mapboxgl.Map) => {
    if (!dashboard) return;
    const features: any[] = [];
    dashboard.by_country.forEach(c => {
      const centroid = COUNTRY_CENTROIDS[c.code] || (c.lat != null && c.lon != null ? [c.lon, c.lat] : null);
      if (!centroid) return;
      features.push({
        type: 'Feature',
        geometry: { type: 'Point', coordinates: [centroid[0], centroid[1]] },
        properties: { code: c.code, count: c.count },
      });
    });
    try {
      (map.getSource('countries') as mapboxgl.GeoJSONSource)?.setData({ type: 'FeatureCollection', features });
    } catch {}
  }, [dashboard]);

  useEffect(() => {
    if (mapInstRef.current) updateMapData(mapInstRef.current);
  }, [dashboard, updateMapData]);

  useEffect(() => {
    if (activeTab === 'dashboard' && mapInstRef.current) {
      setTimeout(() => mapInstRef.current?.resize(), 150);
    }
  }, [activeTab]);

  const exportCSV = (results: ScanResultItem[]) => {
    const header = 'IP,Port,URL,Device,Status,Username,Password,Country,Org,Lat,Lon\n';
    const rows = results.map(r =>
      `"${r.ip}",${r.port},"${r.url || ''}","${r.device || ''}",${r.auth_found ? 'CRED' : r.no_auth ? 'OPEN' : 'AUTH'},"${r.username || ''}","${r.password || ''}","${r.country_code || ''}","${r.org || ''}",${r.lat ?? ''},${r.lon ?? ''}`
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `gyd-scan-${Date.now()}.csv`;
    a.click(); URL.revokeObjectURL(url);
  };

  // Filtered results
  const filteredResults = scanResults
    .map((r, i) => ({ ...r, _idx: i }))
    .filter(r => {
      if (filterStatus === 'cred' && !r.auth_found) return false;
      if (filterStatus === 'open' && !r.no_auth) return false;
      if (filterStatus === 'auth' && (r.auth_found || r.no_auth)) return false;
      if (filterText) {
        const q = filterText.toLowerCase();
        if (!r.ip.includes(q) && !String(r.port).includes(q) && !(r.device || '').toLowerCase().includes(q) && !(r.country_code || '').toLowerCase().includes(q))
          return false;
      }
      return true;
    });

  const toggleScanRow = (idx: number) => {
    setExpandedScanRows(p => {
      const next = new Set(p);
      if (next.has(idx)) next.delete(idx); else next.add(idx);
      return next;
    });
  };

  const savePreset = () => {
    const name = prompt('Preset name:');
    if (!name) return;
    const p: ScanPreset = { name, region, maxIps, threads, ports, countryFilter, geoEnrich };
    const updated = [...presets.filter(x => x.name !== name), p];
    setPresets(updated);
    localStorage.setItem('gyd_presets', JSON.stringify(updated));
    toast(`Preset "${name}" saved`, 'success');
  };

  const loadPreset = (p: ScanPreset) => {
    setRegion(p.region); setMaxIps(p.maxIps); setThreads(p.threads);
    setPorts(p.ports); setCountryFilter(p.countryFilter); setGeoEnrich(p.geoEnrich);
    toast(`Preset "${p.name}" loaded`, 'info');
  };

  const deletePreset = (name: string) => {
    const updated = presets.filter(x => x.name !== name);
    setPresets(updated);
    localStorage.setItem('gyd_presets', JSON.stringify(updated));
  };

  const clearAllData = () => {
    if (!confirm('Delete ALL your scan results and history? This cannot be undone.')) return;
    setScanResults([]); setTotalResponded(0); setTotalScanned(0);
    setLogs([]); setItems([]); setOutputs([]); setDashboard(null);
    toast('Local data cleared', 'info');
  };

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement) return;
      switch (e.key) {
        case '1': setActiveTab('dashboard'); break;
        case '2': setActiveTab('scan'); break;
        case '3': setActiveTab('output'); break;
        case '4': setActiveTab('invites'); break;
        case '5': setActiveTab('devices'); break;
        case '6': setActiveTab('settings'); break;
        case 's':
        case 'S':
          e.preventDefault();
          if (scanning) stopScan(); else if (!scanning && activeTab === 'scan') startScan();
          break;
        case 'Escape':
          setExpandedScanRows(new Set()); setExpanded(new Set()); break;
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [scanning, activeTab]);

  // Auto-refresh dashboard
  useEffect(() => {
    if (!autoRefresh || activeTab !== 'dashboard') return;
    fetchDashboard();
    const iv = setInterval(fetchDashboard, 30000);
    return () => clearInterval(iv);
  }, [autoRefresh, activeTab]);

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
          <button className={`nav-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}>
            <BarChart size={14} /> Dashboard
          </button>
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
          <button className={`nav-btn ${activeTab === 'devices' ? 'active' : ''}`}
            onClick={() => setActiveTab('devices')}>
            <Terminal size={14} /> Devices
          </button>
          <button className={`nav-btn ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveTab('settings')}>
            <Activity size={14} /> Settings
          </button>
        </nav>
        <div className="header-right">
          <span className="user-tag"><User size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} />{user?.email}</span>
          <button className="btn-logout" onClick={doLogout}><LogOut size={12} /> Logout</button>
        </div>
      </header>

      <main className="page">

        {/* ── Dashboard ── */}
        <div className={`tab-panel ${activeTab === 'dashboard' ? 'active' : ''}`}>
          {dashLoading && !dashboard && (
            <div style={{ textAlign: 'center', padding: 60 }}>
              <RefreshCw size={24} className="spin" color="var(--gray-400)" />
              <p style={{ marginTop: 12, color: 'var(--gray-500)' }}>Loading dashboard data…</p>
            </div>
          )}

          {/* Map — always visible */}
          <div className="dash-map-wrap">
            <div ref={mapRef} className="dash-map" />
          </div>

          {dashboard && (
            <div className="dash-grid" style={{ marginTop: 0 }}>
              {/* Stats cards */}
              <div className="dash-cards">
                <div className="dash-stat"><div className="dash-stat-n">{dashboard.stats.total_scans}</div><div className="dash-stat-l">Scans</div></div>
                <div className="dash-stat"><div className="dash-stat-n">{dashboard.stats.total_results}</div><div className="dash-stat-l">Devices Found</div></div>
                <div className="dash-stat"><div className="dash-stat-n">{dashboard.stats.total_creds}</div><div className="dash-stat-l">Credentials</div></div>
                <div className="dash-stat"><div className="dash-stat-n">{dashboard.stats.total_open}</div><div className="dash-stat-l">Open</div></div>
                <div className="dash-stat"><div className="dash-stat-n">{dashboard.stats.countries_hit}</div><div className="dash-stat-l">Countries</div></div>
                <div className="dash-stat"><div className="dash-stat-n">{dashboard.stats.unique_ips}</div><div className="dash-stat-l">Unique IPs</div></div>
              </div>

              {/* Bottom row */}
              <div className="dash-bottom">
                {/* Country breakdown */}
                <div className="dash-panel">
                  <div className="dash-panel-title">Top Countries</div>
                  <div className="dash-panel-body">
                    {dashboard.by_country.slice(0, 15).map(c => (
                      <div key={c.code} className="dash-country-row">
                        <span className="dash-country-code">{c.code || '??'}</span>
                        <div className="dash-country-bar-wrap">
                          <div className="dash-country-bar" style={{ width: `${(c.count / Math.max(...dashboard.by_country.map(x => x.count))) * 100}%` }} />
                        </div>
                        <span className="dash-country-count">{c.count}</span>
                        {c.creds > 0 && <span className="dash-country-creds">+{c.creds}</span>}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Port distribution */}
                <div className="dash-panel">
                  <div className="dash-panel-title">Port Distribution</div>
                  <div className="dash-panel-body">
                    {dashboard.by_port.slice(0, 10).map(p => {
                      const maxCount = Math.max(...dashboard.by_port.map(x => x.count));
                      return (
                        <div key={p.port} className="dash-port-row">
                          <span className="dash-port-n">{p.port}</span>
                          <div className="dash-country-bar-wrap">
                            <div className="dash-port-bar" style={{ width: `${(p.count / maxCount) * 100}%` }} />
                          </div>
                          <span className="dash-country-count">{p.count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Recent activity */}
                <div className="dash-panel">
                  <div className="dash-panel-title">Recent Finds</div>
                  <div className="dash-panel-body">
                    {dashboard.recent.length === 0 ? (
                      <div className="empty" style={{ padding: 20 }}><p>No recent finds</p></div>
                    ) : (
                      dashboard.recent.map((r, i) => (
                        <div key={i} className="dash-recent-item">
                          <span className={`badge ${r.auth_found ? 'cred' : r.no_auth ? 'open' : 'auth'}`}>
                            {r.auth_found ? 'CRED' : r.no_auth ? 'OPEN' : 'AUTH'}
                          </span>
                          <span className="dash-recent-ip">{r.ip}:{r.port}</span>
                          <span className="dash-recent-device">{r.device || ''}</span>
                          {r.country_code && <span className="dash-recent-cc">{r.country_code}</span>}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
          {!dashLoading && !dashboard && (
            <div className="empty" style={{ padding: 60 }}>
              <BarChart size={36} />
              <h3>No Data Yet</h3>
              <p>Run a scan to see your dashboard with map and statistics.</p>
            </div>
          )}
        </div>

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
                    <option value="india">India</option>
                    <option value="middle-east">Middle East</option>
                    <option value="oceania">Oceania</option>
                    <option value="southeast-asia">Southeast Asia</option>
                    <option value="east-asia">East Asia</option>
                    <option value="central-asia">Central Asia</option>
                    <option value="nordics">Nordics</option>
                    <option value="eastern-europe">Eastern Europe</option>
                    <option value="south-america">South America</option>
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
                <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--gray-200)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div className="card-title" style={{ marginBottom: 0 }}>Results</div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    {scanResults.length > 0 && (
                      <button className="btn outline sm" onClick={() => exportCSV(scanResults)}>
                        <Download size={11} /> CSV
                      </button>
                    )}
                  </div>
                </div>
                {scanResults.length === 0 ? (
                  <div className="empty">
                    <AlertCircle size={36} />
                    <h3>No results yet</h3>
                    <p>Configure and start a scan to see discovered devices here.</p>
                  </div>
                ) : (
                  <>
                    {/* Filter bar */}
                    <div className="filter-bar">
                      <input className="field-input" type="text" placeholder="Search IP, port, device, country…"
                        value={filterText} onChange={e => setFilterText(e.target.value)} style={{ flex: 1 }} />
                      <select className="field-input" value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
                        style={{ width: 120 }}>
                        <option value="all">All ({filteredResults.length})</option>
                        <option value="cred">Credentials</option>
                        <option value="open">Open</option>
                        <option value="auth">Protected</option>
                      </select>
                    </div>
                    <div className="table-wrap">
                      <div className="table-scroll">
                        <table>
                          <thead>
                            <tr>
                              <th style={{ width: 20 }}></th>
                              <th>IP</th><th>Port</th><th>URL</th><th>Device</th>
                              <th>Status</th><th>Credentials</th><th>Country</th><th>Org</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filteredResults.length === 0 ? (
                              <tr><td colSpan={9} style={{ textAlign: 'center', padding: 24, color: 'var(--gray-400)' }}>No matching results</td></tr>
                            ) : (
                              filteredResults.slice().reverse().map(r => {
                                const isExpanded = expandedScanRows.has(r._idx);
                                return (
                                  <Fragment key={r._idx}>
                                    <tr className={`${r.auth_found ? 'cred' : r.no_auth ? 'open' : ''} ${isExpanded ? 'expanded' : ''}`}
                                      onClick={() => toggleScanRow(r._idx)} style={{ cursor: 'pointer' }}>
                                      <td>{isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}</td>
                                      <td style={{ fontFamily: 'var(--font-mono)' }}>{r.ip}</td>
                                      <td style={{ fontFamily: 'var(--font-mono)' }}>{r.port}</td>
                                      <td style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: 'var(--font-mono)' }} title={r.url}>{r.url}</td>
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
                                      <td style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.org || '—'}</td>
                                    </tr>
                                    {isExpanded && (
                                      <tr className="scan-detail-row">
                                        <td colSpan={9}>
                                          <div className="scan-detail-body">
                                            <div className="scan-detail-grid">
                                              <div><span className="scan-detail-lbl">URL</span><span className="scan-detail-val">{r.url}</span></div>
                                              <div><span className="scan-detail-lbl">Device</span><span className="scan-detail-val">{r.device || 'Unknown'}</span></div>
                                              <div><span className="scan-detail-lbl">Status</span><span className="scan-detail-val">{r.auth_found ? 'Credentials Found' : r.no_auth ? 'No Auth Required' : 'Protected'}</span></div>
                                              <div><span className="scan-detail-lbl">Creds</span><span className="scan-detail-val">{r.auth_found ? `${r.username}:${r.password}` : '—'}</span></div>
                                              <div><span className="scan-detail-lbl">Country</span><span className="scan-detail-val">{r.country_code || '—'} {r.country || ''}</span></div>
                                              {r.org && <div><span className="scan-detail-lbl">Org</span><span className="scan-detail-val">{r.org}</span></div>}
                                              {r.isp && <div><span className="scan-detail-lbl">ISP</span><span className="scan-detail-val">{r.isp}</span></div>}
                                              {r.as_info && <div><span className="scan-detail-lbl">AS</span><span className="scan-detail-val">{r.as_info}</span></div>}
                                              <div><span className="scan-detail-lbl">HTTP</span><span className="scan-detail-val">{r.status_code}</span></div>
                                            </div>
                                            <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                                              <button className="btn outline sm" onClick={(e) => { e.stopPropagation(); openDevice(r); }}>
                                                <ExternalLink size={10} /> Open
                                              </button>
                                            </div>
                                          </div>
                                        </td>
                                      </tr>
                                    )}
                                  </Fragment>
                                );
                              })
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </>
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
                                    <button className="interact-btn outline-btn" onClick={() => bruteDevice(item.id)} disabled={ds.loading} title="Try 50 credential combinations">
                                      <RefreshCw size={11} /> Brute
                                    </button>
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

        {/* ── Devices ── */}
        <div className={`tab-panel ${activeTab === 'devices' ? 'active' : ''}`}>
          <div className="devices-header">
            <div>
              <div className="devices-title"><Server size={16} /> Exploitable Devices</div>
              <div className="devices-sub">Hardware devices with working credentials. Try SSH or HTTP shell access.</div>
            </div>
            <div className="devices-header-actions">
              <button className="btn outline sm" onClick={fetchSessions}>
                <RefreshCw size={11} /> Sessions ({sessions.length})
              </button>
              <button className="btn outline sm" onClick={runAutoExploit} disabled={autoExploit}>
                {autoExploit ? <RefreshCw size={11} className="spin" /> : <Zap size={11} />} Auto-Exploit
              </button>
              <button className="btn outline sm" onClick={fetchExploitDevices}>
                <RefreshCw size={11} /> Refresh
              </button>
            </div>
          </div>

          {/* Terminal output area */}
          <div className="exploit-terminals">
            {sessions.length === 0 && terminalOutput.length === 0 && (
              <div className="empty" style={{ padding: '24px 0' }}>
                <Terminal size={32} />
                <h3>No active sessions</h3>
                <p>Connect to a device below, or run Auto-Exploit to scan all devices at once.</p>
              </div>
            )}
            {terminalOutput.map(t => (
              <div key={t.sessionId} className="terminal-box">
                <div className="terminal-header">
                  <Terminal size={10} /> Session {t.sessionId === 'batch' ? '(batch)' : t.sessionId.slice(0, 8)}…
                  <button className="btn outline sm" style={{ marginLeft: 'auto' }}
                    onClick={() => { navigator.clipboard.writeText(t.lines.join('')); toast('Copied', 'success'); }}>
                    <Copy size={9} />
                  </button>
                  {t.sessionId !== 'batch' && (
                    <button className="btn outline sm" onClick={() => disconnectDevice(t.sessionId)}
                      style={{ color: 'var(--red)', borderColor: 'var(--red)', marginLeft: 4 }}>
                      <Unplug size={9} /> Close
                    </button>
                  )}
                </div>
                <div className="terminal-body">
                  {t.lines.map((line, li) => (
                    <div key={li} className="terminal-line" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{line}</div>
                  ))}
                  <div ref={terminalEndRef} />
                </div>
                {t.sessionId !== 'batch' && (
                  <div className="terminal-input-row">
                    <input className="terminal-input" type="text" value={terminalInput}
                      onChange={e => setTerminalInput(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter') sendCommand(t.sessionId); }}
                      placeholder="Enter command…" autoFocus />
                    <button className="btn fill sm" onClick={() => sendCommand(t.sessionId)}>
                      <Play size={10} /> Send
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Device list */}
          <div className="card" style={{ padding: 0 }}>
            <div className="device-list-header">
              <span>Discovered Hardware Devices ({exploitDevices.length})</span>
            </div>
            {expLoading ? (
              <div style={{ textAlign: 'center', padding: 32 }}>
                <RefreshCw size={20} className="spin" color="var(--gray-400)" />
              </div>
            ) : exploitDevices.length === 0 ? (
              <div className="empty">
                <Server size={28} />
                <h3>No hardware devices found</h3>
                <p>Run a scan first. Hardware devices (routers, cameras, switches) with working credentials will appear here.</p>
              </div>
            ) : (
              <div className="exploit-device-list">
                {exploitDevices.map(d => {
                  const activeSession = sessions.find(s => s.item_id === String(d.id));
                  return (
                    <div key={d.id} className={`exploit-device-item ${activeSession ? 'connected' : ''}`}>
                      <div className="exploit-device-info">
                        <div className="exploit-device-name">
                          <Server size={12} style={{ marginRight: 6, flexShrink: 0 }} />
                          <strong>{d.device}</strong>
                          <span className="exploit-device-ip">{d.ip}:{d.port}</span>
                        </div>
                        <div className="exploit-device-meta">
                          <span className="exploit-country">{d.country_code || '?'}</span>
                          <span className="exploit-creds">{d.username}:{d.password}</span>
                          {d.org && <span className="exploit-org">{d.org}</span>}
                        </div>
                      </div>
                      <div className="exploit-device-actions">
                        {activeSession ? (
                          <>
                            <span className="badge-status active">CONNECTED</span>
                            <button className="btn outline sm" onClick={() => disconnectDevice(activeSession.id)}
                              style={{ color: 'var(--red)', borderColor: 'var(--red)' }}>
                              <Unplug size={10} /> Disconnect
                            </button>
                          </>
                        ) : (
                          <button className="btn fill sm" onClick={() => connectDevice(d)}
                            disabled={connectingId === d.id}>
                            {connectingId === d.id ? <RefreshCw size={10} className="spin" /> : <Plug size={10} />} Connect
                          </button>
                        )}
                        <button className="btn outline sm" onClick={() => openDevice({...d, no_auth: false, auth_found: true, id: d.id, device: d.device, url: d.url || ''})}>
                          <ExternalLink size={10} /> Open
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* ── Settings ── */}
        <div className={`tab-panel ${activeTab === 'settings' ? 'active' : ''}`}>
          <div className="settings-grid">
            {/* Scan Presets */}
            <div className="settings-card">
              <div className="settings-card-title">Scan Presets</div>
              <div className="settings-card-body">
                <p className="settings-desc">Save and load scan configurations.</p>
                <div className="preset-list">
                  {presets.length === 0 && <span className="settings-empty">No presets saved yet.</span>}
                  {presets.map(p => (
                    <div key={p.name} className="preset-item">
                      <div className="preset-info">
                        <strong>{p.name}</strong>
                        <span>{p.region} · {p.maxIps} IPs · {p.threads}t · {p.ports}</span>
                      </div>
                      <div className="preset-actions">
                        <button className="btn outline sm" onClick={() => loadPreset(p)}>Load</button>
                        <button className="btn outline sm" onClick={() => deletePreset(p.name)} style={{ color: 'var(--red)', borderColor: 'var(--red)' }}>Del</button>
                      </div>
                    </div>
                  ))}
                </div>
                <button className="btn outline" style={{ marginTop: 12, width: '100%' }} onClick={savePreset}>
                  <Download size={12} /> Save Current Config
                </button>
              </div>
            </div>

            {/* Shortcuts */}
            <div className="settings-card">
              <div className="settings-card-title">Keyboard Shortcuts</div>
              <div className="settings-card-body">
                <div className="shortcut-row"><kbd>1</kbd><span>Dashboard</span></div>
                <div className="shortcut-row"><kbd>2</kbd><span>Scan</span></div>
                <div className="shortcut-row"><kbd>3</kbd><span>Results</span></div>
                <div className="shortcut-row"><kbd>4</kbd><span>Invites</span></div>
                <div className="shortcut-row"><kbd>5</kbd><span>Devices</span></div>
                <div className="shortcut-row"><kbd>6</kbd><span>Settings</span></div>
                <div className="shortcut-row"><kbd>S</kbd><span>Start / Stop scan</span></div>
                <div className="shortcut-row"><kbd>Esc</kbd><span>Collapse all rows</span></div>
              </div>
            </div>

            {/* Dashboard Settings */}
            <div className="settings-card">
              <div className="settings-card-title">Dashboard</div>
              <div className="settings-card-body">
                <label className="checkbox-row" style={{ marginBottom: 0 }}>
                  <input type="checkbox" checked={autoRefresh}
                    onChange={e => setAutoRefresh(e.target.checked)} />
                  Auto-refresh every 30s
                </label>
              </div>
            </div>

            {/* Data */}
            <div className="settings-card">
              <div className="settings-card-title">Data</div>
              <div className="settings-card-body">
                <p className="settings-desc">Clear locally cached data (does not affect server).</p>
                <button className="btn outline" style={{ width: '100%', color: 'var(--red)', borderColor: 'var(--red)' }} onClick={clearAllData}>
                  <Trash size={12} /> Clear Local Data
                </button>
              </div>
            </div>
          </div>
        </div>

      </main>
    </>
  );
}
