import { useState, useEffect, useRef } from 'react';
import { 
  Shield, Activity, History, Mail, LogOut, User, Play, Square, Trash, 
  Copy, ExternalLink, Terminal, CheckCircle, XCircle, AlertCircle, 
  ChevronDown, ChevronUp, Globe, MapPin, Info, RefreshCw
} from 'lucide-react';

// --- API Helpers ---
const TOKEN_KEY = 'gyd_token';

interface UserInfo {
  email: string;
  username: string;
  uid: string;
}

interface ScanResultItem {
  id: number;
  ip: string;
  port: number;
  url: string;
  device: string;
  no_auth: boolean;
  auth_found: boolean;
  username?: string;
  password?: string;
  note?: string;
  status_code?: number;
  country?: string;
  country_code?: string;
  region_name?: string;
  city?: string;
  lat?: number;
  lon?: number;
  org?: string;
  isp?: string;
  as_info?: string;
  broken?: boolean;
}

interface ScanResult {
  id: string;
  user_id: string;
  total_scanned: number;
  results_count: number;
  creds_count: number;
  open_count: number;
  region: string;
  ports: string;
  created_at: string;
}

interface InviteCode {
  id: string;
  code: string;
  status: 'active' | 'used';
  issuer: string;
  used_by?: string;
  created_at: string;
  used_at?: string;
}

interface Toast {
  id: string;
  message: string;
  type: 'success' | 'error' | 'info';
}

interface LogLine {
  timestamp: string;
  message: string;
  type: 'info' | 'hit' | 'hit-open' | 'err';
}

interface DeviceTestState {
  loading: boolean;
  status: string;
  output: string;
  user: string;
  pass: string;
  showShell: boolean;
  command: string;
}

export default function App() {
  // --- Auth State ---
  const [token, setToken] = useState<string | null>(localStorage.getItem(TOKEN_KEY));
  const [user, setUser] = useState<UserInfo | null>(null);
  const [isCheckingSession, setIsCheckingSession] = useState(true);
  const [activeTab, setActiveTab] = useState<'scan' | 'output' | 'invites'>('scan');
  
  // Auth Form State
  const [authTab, setAuthTab] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [regUsername, setRegUsername] = useState('');
  const [inviteCode, setInviteCode] = useState('');
  const [authError, setAuthError] = useState('');
  const [authSuccess, setAuthSuccess] = useState('');
  const [authLoading, setAuthLoading] = useState(false);
  const [inviteOnly, setInviteOnly] = useState(true);

  // --- Scan Panel State ---
  const [region, setRegion] = useState('worldwide');
  const [maxIps, setMaxIps] = useState(200);
  const [batchSize, setBatchSize] = useState(50);
  const [threads, setThreads] = useState(20);
  const [ports, setPorts] = useState('fast');
  const [countryFilter, setCountryFilter] = useState('');
  const [geoEnrichment, setGeoEnrichment] = useState(true);
  
  // Scan Status & Results
  const [scanning, setScanning] = useState(false);
  const [stopped, setStopped] = useState(false);
  const [totalScanned, setTotalScanned] = useState(0);
  const [totalResponded, setTotalResponded] = useState(0);
  const [scanResults, setScanResults] = useState<ScanResultItem[]>([]);
  const [liveLogs, setLiveLogs] = useState<LogLine[]>([]);
  const [scanElapsedTime, setScanElapsedTime] = useState('0:00');
  
  const scanStartTimeRef = useRef<number | null>(null);
  const scanTimerRef = useRef<any>(null);
  const stoppedRef = useRef(false);

  // --- Outputs History State ---
  const [outputs, setOutputs] = useState<ScanResult[]>([]);
  const [selectedResultId, setSelectedResultId] = useState<string | null>(null);
  const [selectedResultItems, setSelectedResultItems] = useState<ScanResultItem[]>([]);
  const [detailView, setDetailView] = useState<'grouped' | 'raw'>('grouped');
  const [expandedItems, setExpandedItems] = useState<Set<number>>(new Set());
  const [deviceTestStates, setDeviceTestStates] = useState<Record<number, DeviceTestState>>({});
  const [historyLoading, setHistoryLoading] = useState(false);

  // --- Invite Code State ---
  const [invites, setInvites] = useState<InviteCode[]>([]);
  const [invitesLoading, setInvitesLoading] = useState(false);

  // --- Toast State ---
  const [toasts, setToasts] = useState<Toast[]>([]);

  // Refs for auto-scrolling
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // --- Toast System ---
  const showToast = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4000);
  };

  // --- Custom API Wrapper ---
  const apiFetch = async (url: string, opts: RequestInit = {}) => {
    const currentToken = localStorage.getItem(TOKEN_KEY);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(opts.headers as Record<string, string>),
    };
    if (currentToken) {
      headers['Authorization'] = `Bearer ${currentToken}`;
    }
    const resp = await fetch(url, { ...opts, headers });
    if (resp.status === 401 && !url.includes('/auth/')) {
      doLogout();
      showToast('Session expired, please login again.', 'error');
      throw new Error('Session expired');
    }
    return resp;
  };

  // --- Session & Health check ---
  useEffect(() => {
    const initApp = async () => {
      try {
        const healthResp = await fetch('/api/health');
        if (healthResp.ok) {
          const health = await healthResp.json();
          setInviteOnly(health.invite_only);
        }
      } catch (err) {
        console.error('Health check failed', err);
      }

      if (token) {
        try {
          const meResp = await fetch('/api/auth/me', {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          if (meResp.ok) {
            const data = await meResp.json();
            setUser(data.user);
          } else {
            localStorage.removeItem(TOKEN_KEY);
            setToken(null);
          }
        } catch (err) {
          localStorage.removeItem(TOKEN_KEY);
          setToken(null);
        }
      }
      setIsCheckingSession(false);
    };

    initApp();
  }, [token]);

  // Load outputs when outputs tab active
  useEffect(() => {
    if (token && activeTab === 'output') {
      fetchOutputs();
    } else if (token && activeTab === 'invites') {
      fetchInvites();
    }
  }, [activeTab, token]);

  // Auto scroll terminal log
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [liveLogs]);

  // --- Auth Handlers ---
  const doLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    setAuthSuccess('');
    setAuthLoading(true);
    try {
      const resp = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await resp.json();
      if (!resp.ok) {
        setAuthError(data.error || 'Login failed');
        return;
      }
      localStorage.setItem(TOKEN_KEY, data.token);
      setToken(data.token);
      setUser(data.user);
      showToast(`Welcome back, ${data.user.username || data.user.email}!`, 'success');
    } catch (err: any) {
      setAuthError(err.message || 'Server error during login');
    } finally {
      setAuthLoading(false);
    }
  };

  const doRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    setAuthSuccess('');
    setAuthLoading(true);
    try {
      const resp = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password,
          username: regUsername || undefined,
          invite_code: inviteCode
        })
      });
      const data = await resp.json();
      if (!resp.ok) {
        setAuthError(data.error || 'Registration failed');
        return;
      }
      localStorage.setItem(TOKEN_KEY, data.token);
      setToken(data.token);
      setUser(data.user);
      showToast('Registration successful! Welcome.', 'success');
    } catch (err: any) {
      setAuthError(err.message || 'Server error during registration');
    } finally {
      setAuthLoading(false);
    }
  };

  const doLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch (e) {}
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setUser(null);
    setActiveTab('scan');
  };

  // --- Scan Handlers ---
  const addLog = (message: string, type: LogLine['type'] = 'info') => {
    const timestamp = new Date().toISOString().slice(11, 19);
    setLiveLogs(prev => [...prev, { timestamp, message, type }]);
  };

  const updateScanTimer = () => {
    if (scanStartTimeRef.current) {
      const sec = Math.floor((Date.now() - scanStartTimeRef.current) / 1000);
      const min = Math.floor(sec / 60);
      const remSec = sec % 60;
      setScanElapsedTime(`${min}:${String(remSec).padStart(2, '0')}`);
    }
  };

  const scanChunk = async (currentBatchSize: number) => {
    const body: any = {
      max_ips: currentBatchSize,
      threads,
      ports,
      geo: geoEnrichment
    };
    if (region === 'internet') {
      body.internet = true;
    } else {
      body.region = region;
    }
    if (countryFilter.trim()) {
      body.country = countryFilter.trim();
    }

    const resp = await apiFetch('/api/scan', {
      method: 'POST',
      body: JSON.stringify(body)
    });
    if (!resp.ok) throw new Error('Scan batch request failed');
    return await resp.json();
  };

  const startScan = async () => {
    if (scanning) return;
    setScanning(true);
    setStopped(false);
    stoppedRef.current = false;
    setTotalScanned(0);
    setTotalResponded(0);
    setScanResults([]);
    setLiveLogs([]);
    scanStartTimeRef.current = Date.now();
    setScanElapsedTime('0:00');

    scanTimerRef.current = setInterval(updateScanTimer, 1000);

    const totalIps = maxIps;
    const batch = batchSize;
    const numBatches = Math.ceil(totalIps / batch);
    
    addLog(`Initiating network scanner: ${totalIps} targets via ${region} region`, 'info');

    let currentScanned = 0;
    let currentHits = 0;
    const tempResults: ScanResultItem[] = [];

    for (let i = 0; i < numBatches; i++) {
      if (stoppedRef.current) {
        addLog('Scanner halted by user intervention', 'info');
        break;
      }

      const actualSize = Math.min(batch, totalIps - currentScanned);
      addLog(`Scanning block ${i + 1}/${numBatches} (Size: ${actualSize} IPs)...`, 'info');

      try {
        const data = await scanChunk(actualSize);
        currentScanned += data.total_scanned || actualSize;
        currentHits += data.results_count || 0;
        
        setTotalScanned(currentScanned);
        setTotalResponded(currentHits);

        if (data.results && data.results.length > 0) {
          data.results.forEach((r: ScanResultItem) => {
            tempResults.push(r);
            if (r.auth_found) {
              addLog(`CRITICAL: Found vulnerability at ${r.url} - Credentials: ${r.username}:${r.password} [${r.device}]`, 'hit');
            } else if (r.no_auth) {
              addLog(`ALERT: Unauthenticated access at ${r.url} [${r.device}]`, 'hit-open');
            }
          });
          setScanResults([...tempResults]);
        }
      } catch (err: any) {
        addLog(`Error scanning block: ${err.message}. Retrying in 2 seconds...`, 'err');
        await new Promise(res => setTimeout(res, 2000));
        
        try {
          if (stoppedRef.current) break;
          const data = await scanChunk(actualSize);
          currentScanned += data.total_scanned || actualSize;
          currentHits += data.results_count || 0;
          setTotalScanned(currentScanned);
          setTotalResponded(currentHits);
          if (data.results && data.results.length > 0) {
            data.results.forEach((r: ScanResultItem) => {
              tempResults.push(r);
            });
            setScanResults([...tempResults]);
          }
          addLog(`Retry successful for current block.`, 'info');
        } catch (retryErr: any) {
          addLog(`Block scan retry failed: ${retryErr.message}. Skipping block.`, 'err');
          currentScanned += actualSize;
          setTotalScanned(currentScanned);
        }
      }

      // Small throttle between batches
      if (i < numBatches - 1 && !stoppedRef.current) {
        await new Promise(res => setTimeout(res, 300));
      }
    }

    // Wrap up scan
    setScanning(false);
    clearInterval(scanTimerRef.current);
    if (!stoppedRef.current) {
      addLog(`Scan operation finalized. Scanned: ${currentScanned} IPs. Found: ${tempResults.length} responsive services.`, 'info');
      showToast(`Scan finalized with ${tempResults.length} findings!`, 'success');
    }
  };

  const stopScan = () => {
    stoppedRef.current = true;
    setStopped(true);
    addLog('Stopping scanner... waiting for active block to exit.', 'info');
  };

  const clearScan = () => {
    if (scanning) return;
    setScanResults([]);
    setTotalScanned(0);
    setTotalResponded(0);
    setLiveLogs([]);
    setScanElapsedTime('0:00');
  };

  // --- Output Tab Handlers ---
  const fetchOutputs = async () => {
    setHistoryLoading(true);
    try {
      const resp = await apiFetch('/api/results');
      if (resp.ok) {
        const data = await resp.json();
        setOutputs(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setHistoryLoading(false);
    }
  };

  const selectResult = async (id: string) => {
    setSelectedResultId(id);
    setSelectedResultItems([]);
    setExpandedItems(new Set());
    setDeviceTestStates({});
    
    try {
      const resp = await apiFetch(`/api/results/${id}/items`);
      if (resp.ok) {
        const data = await resp.json();
        setSelectedResultItems(data);
      }
    } catch (err) {
      showToast('Failed to load scan details', 'error');
    }
  };

  const deleteResult = async (id: string) => {
    if (!window.confirm('Are you sure you want to permanently delete this scan result?')) return;
    try {
      const resp = await apiFetch(`/api/results/${id}`, { method: 'DELETE' });
      if (resp.ok) {
        showToast('Scan result deleted successfully', 'success');
        setSelectedResultId(null);
        setSelectedResultItems([]);
        fetchOutputs();
      }
    } catch (err) {
      showToast('Delete operation failed', 'error');
    }
  };

  const toggleItemExpansion = (itemId: number) => {
    setExpandedItems(prev => {
      const next = new Set(prev);
      if (next.has(itemId)) {
        next.delete(itemId);
      } else {
        next.add(itemId);
        // Initialize interaction states for this item if not exists
        if (!deviceTestStates[itemId]) {
          const item = selectedResultItems.find(i => i.id === itemId);
          setDeviceTestStates(prevStates => ({
            ...prevStates,
            [itemId]: {
              loading: false,
              status: item?.broken ? '✅ Working!' : '— not tested',
              output: '',
              user: item?.username || 'admin',
              pass: item?.password || 'admin',
              showShell: !!item?.broken,
              command: 'id'
            }
          }));
        }
      }
      return next;
    });
  };

  const updateTestState = (itemId: number, fields: Partial<DeviceTestState>) => {
    setDeviceTestStates(prev => ({
      ...prev,
      [itemId]: {
        ...prev[itemId],
        ...fields
      }
    }));
  };

  const testDevice = async (itemId: number) => {
    const state = deviceTestStates[itemId];
    if (!state) return;

    updateTestState(itemId, { loading: true, output: 'Initiating authentication test...' });
    
    try {
      const resp = await apiFetch(`/api/devices/${itemId}/test`, {
        method: 'POST',
        body: JSON.stringify({ username: state.user, password: state.pass })
      });
      const data = await resp.json();
      if (data.status === 'ok') {
        const headersStr = JSON.stringify(data.headers, null, 2);
        updateTestState(itemId, {
          loading: false,
          status: '✅ Working!',
          output: `✅ Credentials accepted!\nHTTP Status: ${data.status_code}\n\nHeaders:\n${headersStr}`,
          showShell: true
        });
        showToast(`Vulnerability confirmed on device ID ${itemId}!`, 'success');
        // Mark item as broken locally
        setSelectedResultItems(prev => prev.map(item => item.id === itemId ? { ...item, broken: true } : item));
      } else {
        updateTestState(itemId, {
          loading: false,
          status: '❌ Failed',
          output: `❌ Connection / Auth Failed:\n${data.message || 'Unknown failure'}`
        });
        showToast('Authentication test failed.', 'error');
      }
    } catch (err: any) {
      updateTestState(itemId, {
        loading: false,
        status: '❌ Error',
        output: `Error during test: ${err.message}`
      });
    }
  };

  const execShell = async (itemId: number) => {
    const state = deviceTestStates[itemId];
    if (!state) return;

    updateTestState(itemId, { loading: true, output: `Executing: ${state.command}...` });

    try {
      const resp = await apiFetch(`/api/devices/${itemId}/access`, {
        method: 'POST',
        body: JSON.stringify({ action: 'shell', command: state.command })
      });
      const data = await resp.json();
      if (data.status === 'ok') {
        updateTestState(itemId, {
          loading: false,
          output: `✅ Command executed.\n\nTerminal Output:\n${data.output || '(No response)'}`
        });
      } else {
        updateTestState(itemId, {
          loading: false,
          output: `❌ Execution Failed:\n${data.message || 'API error'}`
        });
      }
    } catch (err: any) {
      updateTestState(itemId, {
        loading: false,
        output: `Error sending request: ${err.message}`
      });
    }
  };

  const openDevice = (item: ScanResultItem) => {
    const port = item.port || 80;
    const scheme = [443, 8443, 9443].includes(port) ? 'https' : 'http';
    window.open(`${scheme}://${item.ip}:${port}`, '_blank');
  };

  // --- Invite Code Handlers ---
  const fetchInvites = async () => {
    setInvitesLoading(true);
    try {
      const resp = await apiFetch('/api/admin/invites');
      if (resp.ok) {
        const data = await resp.json();
        setInvites(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setInvitesLoading(false);
    }
  };

  const createInvite = async () => {
    setInvitesLoading(true);
    try {
      const resp = await apiFetch('/api/admin/invites', { method: 'POST' });
      if (resp.ok) {
        const data = await resp.json();
        showToast(`Generated code: ${data.code}`, 'success');
        fetchInvites();
      } else {
        showToast('Failed to generate invite code', 'error');
      }
    } catch (err) {
      showToast('Generate operation failed', 'error');
    } finally {
      setInvitesLoading(false);
    }
  };

  // Group outputs by date
  const groupOutputsByDate = () => {
    const groups: Record<string, ScanResult[]> = {};
    outputs.forEach(o => {
      const date = o.created_at ? o.created_at.slice(0, 10) : 'Unknown Date';
      if (!groups[date]) groups[date] = [];
      groups[date].push(o);
    });
    return Object.entries(groups).sort((a, b) => b[0].localeCompare(a[0]));
  };

  // --- Render Utils ---
  if (isCheckingSession) {
    return (
      <div className="auth-container">
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
          <RefreshCw size={36} className="color-blue" style={{ animation: 'spin 1.5s linear infinite' }} />
          <p style={{ color: 'var(--text-secondary)', fontSize: 14 }}>Authenticating secure environment...</p>
        </div>
      </div>
    );
  }

  if (!token) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="auth-header">
            <div className="auth-logo">GYD SCANNER</div>
            <div className="auth-desc">Global Device Intelligence Dashboard</div>
          </div>

          <div className="auth-tabs">
            <button 
              className={`auth-tab ${authTab === 'login' ? 'active' : ''}`}
              onClick={() => { setAuthTab('login'); setAuthError(''); }}
            >
              Sign In
            </button>
            <button 
              className={`auth-tab ${authTab === 'register' ? 'active' : ''}`}
              onClick={() => { setAuthTab('register'); setAuthError(''); }}
            >
              Register
            </button>
          </div>

          {authError && <div className="auth-alert error" style={{ marginBottom: 16 }}>{authError}</div>}
          {authSuccess && <div className="auth-alert success" style={{ marginBottom: 16 }}>{authSuccess}</div>}

          {authTab === 'login' ? (
            <form onSubmit={doLogin} className="auth-form">
              <div className="form-group">
                <label className="form-label">Email Address</label>
                <input 
                  type="email" 
                  className="input-field" 
                  placeholder="name@agency.gov" 
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  required 
                />
              </div>
              <div className="form-group">
                <label className="form-label">Security Keyphrase</label>
                <input 
                  type="password" 
                  className="input-field" 
                  placeholder="••••••••" 
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required 
                />
              </div>
              <button type="submit" className="btn-submit" disabled={authLoading}>
                {authLoading ? <RefreshCw size={16} style={{ animation: 'spin 1s linear infinite' }} /> : 'Authenticate Access'}
              </button>
            </form>
          ) : (
            <form onSubmit={doRegister} className="auth-form">
              <div className="form-group">
                <label className="form-label">Email Address</label>
                <input 
                  type="email" 
                  className="input-field" 
                  placeholder="name@agency.gov" 
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  required 
                />
              </div>
              <div className="form-group">
                <label className="form-label">Codename (Username)</label>
                <input 
                  type="text" 
                  className="input-field" 
                  placeholder="Agent Smith" 
                  value={regUsername}
                  onChange={e => setRegUsername(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Security Keyphrase</label>
                <input 
                  type="password" 
                  className="input-field" 
                  placeholder="•••••••• (6+ chars)" 
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  minLength={6}
                  required 
                />
              </div>
              {inviteOnly && (
                <div className="form-group">
                  <label className="form-label">Secure Invitation Code</label>
                  <input 
                    type="text" 
                    className="input-field" 
                    placeholder="INV-XXXXXX" 
                    value={inviteCode}
                    onChange={e => setInviteCode(e.target.value)}
                    required={inviteOnly} 
                  />
                  <span style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                    This deployment is restricted. An active invite code is mandatory.
                  </span>
                </div>
              )}
              <button type="submit" className="btn-submit" disabled={authLoading}>
                {authLoading ? <RefreshCw size={16} style={{ animation: 'spin 1s linear infinite' }} /> : 'Establish Account'}
              </button>
            </form>
          )}
        </div>
      </div>
    );
  }

  return (
    <>
      {/* Toast Notifications */}
      <div className="toast-container">
        {toasts.map(t => (
          <div key={t.id} className={`toast ${t.type}`}>
            {t.type === 'success' && <CheckCircle size={16} />}
            {t.type === 'error' && <XCircle size={16} />}
            {t.type === 'info' && <Info size={16} />}
            <span>{t.message}</span>
          </div>
        ))}
      </div>

      {/* Main Header */}
      <header className="app-header">
        <a href="#/" className="brand">
          <Shield className="brand-icon" size={24} />
          <span className="brand-name">GYD C2</span>
        </a>

        <nav className="nav-tabs">
          <button 
            className={`nav-tab ${activeTab === 'scan' ? 'active' : ''}`}
            onClick={() => setActiveTab('scan')}
          >
            <Activity size={16} />
            Network Scan
          </button>
          <button 
            className={`nav-tab ${activeTab === 'output' ? 'active' : ''}`}
            onClick={() => setActiveTab('output')}
          >
            <History size={16} />
            Intel Repository
          </button>
          <button 
            className={`nav-tab ${activeTab === 'invites' ? 'active' : ''}`}
            onClick={() => setActiveTab('invites')}
          >
            <Mail size={16} />
            Gatekeeper
          </button>
        </nav>

        <div className="user-profile">
          <div className="user-email">
            <User size={12} style={{ marginRight: 6, verticalAlign: 'middle', display: 'inline-block' }} />
            {user?.username || user?.email}
          </div>
          <button className="btn-logout" onClick={doLogout}>
            <LogOut size={14} />
            Exit Secure Node
          </button>
        </div>
      </header>

      {/* Content Panels */}
      <main className="app-content">
        
        {/* --- SCAN TAB --- */}
        <section className={`tab-panel ${activeTab === 'scan' ? 'active' : ''}`}>
          <div className="grid-2">
            
            {/* Sidebar Settings */}
            <div className="scan-sidebar">
              <div className="card highlight">
                <div className="card-title">
                  <Globe size={14} />
                  Targeting Configuration
                </div>
                
                <div className="form-group" style={{ marginBottom: 12 }}>
                  <label className="form-label">Search Context / Region</label>
                  <select 
                    className="input-field select-control"
                    value={region}
                    onChange={e => setRegion(e.target.value)}
                    disabled={scanning}
                  >
                    <option value="worldwide">Worldwide (All RIRs)</option>
                    <option value="europe">Europe (RIPE)</option>
                    <option value="north-america">North America (ARIN)</option>
                    <option value="asia">Asia Pacific (APNIC)</option>
                    <option value="latin-america">Latin America (LACNIC)</option>
                    <option value="africa">Africa (AFRINIC)</option>
                    <option value="subsaharan">Sub-Saharan Africa</option>
                    <option value="internet">Random Global Shards (Internet)</option>
                  </select>
                </div>

                <div className="form-row-2" style={{ marginBottom: 12 }}>
                  <div className="form-group">
                    <label className="form-label">Cap Targets</label>
                    <input 
                      type="number" 
                      className="input-field" 
                      min={10} 
                      max={5000} 
                      step={100}
                      value={maxIps}
                      onChange={e => setMaxIps(parseInt(e.target.value) || 10)}
                      disabled={scanning}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Batch Size</label>
                    <input 
                      type="number" 
                      className="input-field" 
                      min={10} 
                      max={500} 
                      step={10}
                      value={batchSize}
                      onChange={e => setBatchSize(parseInt(e.target.value) || 10)}
                      disabled={scanning}
                    />
                  </div>
                </div>

                <div className="form-row-2" style={{ marginBottom: 12 }}>
                  <div className="form-group">
                    <label className="form-label">Thread Pools</label>
                    <input 
                      type="number" 
                      className="input-field" 
                      min={1} 
                      max={100}
                      value={threads}
                      onChange={e => setThreads(parseInt(e.target.value) || 1)}
                      disabled={scanning}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Ports Profile</label>
                    <select 
                      className="input-field select-control"
                      value={ports}
                      onChange={e => setPorts(e.target.value)}
                      disabled={scanning}
                    >
                      <option value="fast">Fast Scan (12 standard ports)</option>
                      <option value="all">Comprehensive (Web + CCTV Webcams)</option>
                    </select>
                  </div>
                </div>

                <div className="form-group" style={{ marginBottom: 12 }}>
                  <label className="form-label">Country Filter</label>
                  <input 
                    type="text" 
                    className="input-field" 
                    placeholder="e.g. US,DE,FR,JP" 
                    value={countryFilter}
                    onChange={e => setCountryFilter(e.target.value)}
                    disabled={scanning}
                  />
                </div>

                <div className="form-group" style={{ marginBottom: 16 }}>
                  <label className="checkbox-label">
                    <input 
                      type="checkbox" 
                      className="checkbox-control"
                      checked={geoEnrichment}
                      onChange={e => setGeoEnrichment(e.target.checked)}
                      disabled={scanning}
                    />
                    <span>IP Geolocation Resolution</span>
                  </label>
                </div>

                <div className="btn-row">
                  {!scanning ? (
                    <button className="btn-action primary" onClick={startScan}>
                      <Play size={14} />
                      Start Scanner
                    </button>
                  ) : (
                    <button className="btn-action danger" onClick={stopScan}>
                      <Square size={14} />
                      Halt Scanner
                    </button>
                  )}
                  <button 
                    className="btn-action" 
                    onClick={clearScan} 
                    disabled={scanning || scanResults.length === 0}
                  >
                    <Trash size={14} />
                    Reset
                  </button>
                </div>
              </div>
            </div>

            {/* Scan Activity Output */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              
              {/* Stats dashboard */}
              <div className="card">
                <div className="stats-container">
                  <div className="stat-card">
                    <div className="stat-val color-muted">{totalScanned}</div>
                    <div className="stat-lbl">Scanned</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-val color-blue">{totalResponded}</div>
                    <div className="stat-lbl">Online</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-val color-blue">
                      {scanResults.filter(r => r.device && r.device !== 'Unknown HTTP Service').length}
                    </div>
                    <div className="stat-lbl">Identified</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-val color-green">
                      {scanResults.filter(r => r.auth_found).length}
                    </div>
                    <div className="stat-lbl">Exploitable</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-val color-orange">
                      {scanResults.filter(r => r.no_auth).length}
                    </div>
                    <div className="stat-lbl">Open Web</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-val color-muted">{scanElapsedTime}</div>
                    <div className="stat-lbl">Time Elapsed</div>
                  </div>
                </div>

                {/* Progress bar */}
                {(scanning || totalScanned > 0) && (
                  <div className="progress-panel">
                    <div className="progress-header">
                      <span>Scanner Engine Status: {scanning ? 'Scanning...' : stopped ? 'Aborted' : 'Idle'}</span>
                      <span>{totalScanned} / {maxIps} Targets ({Math.round((totalScanned / maxIps) * 100)}%)</span>
                    </div>
                    <div className="progress-track">
                      <div 
                        className="progress-fill" 
                        style={{ width: `${Math.min(100, (totalScanned / maxIps) * 100)}%` }}
                      ></div>
                    </div>
                  </div>
                )}
              </div>

              {/* Log Console Terminal */}
              {(liveLogs.length > 0) && (
                <div className="terminal-log">
                  <div className="terminal-header">
                    <span>Active Telemetry Output</span>
                    <span style={{ color: 'var(--blue)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                      <span className="dot active" style={{ animation: 'pulse 1.5s infinite' }}></span>
                      Live Stream
                    </span>
                  </div>
                  <div className="terminal-body">
                    {liveLogs.map((log, idx) => (
                      <div key={idx} className="terminal-line">
                        <span className="time">[{log.timestamp}]</span>
                        <span style={{
                          color: log.type === 'hit' ? '#10b981' : 
                                 log.type === 'hit-open' ? '#f59e0b' : 
                                 log.type === 'err' ? '#ef4444' : '#38bdf8'
                        }}>
                          {log.message}
                        </span>
                      </div>
                    ))}
                    <div ref={terminalEndRef} />
                  </div>
                </div>
              )}

              {/* Scan Results Table */}
              <div className="card">
                <div className="card-title">
                  <Terminal size={14} />
                  Discovery Database
                </div>
                {scanResults.length === 0 ? (
                  <div className="empty-state">
                    <AlertCircle className="empty-icon" size={40} />
                    <div className="empty-title">Ready for execution</div>
                    <div className="empty-desc">Set target scope and press Start to monitor active sockets.</div>
                  </div>
                ) : (
                  <div className="table-container">
                    <div className="table-scroller">
                      <table className="sc-table">
                        <thead>
                          <tr>
                            <th>Host IP</th>
                            <th>Port</th>
                            <th>Resolved URL</th>
                            <th>Device Archetype</th>
                            <th>Intel Tag</th>
                            <th>Defaults Found</th>
                            <th>Country</th>
                            <th>ISP / Autonomous System</th>
                          </tr>
                        </thead>
                        <tbody>
                          {scanResults.slice().reverse().map((res, i) => {
                            const isCred = res.auth_found;
                            const isOpen = res.no_auth;
                            return (
                              <tr 
                                key={i} 
                                className={isCred ? 'highlight-cred' : isOpen ? 'highlight-open' : ''}
                              >
                                <td style={{ fontFamily: 'var(--font-mono)' }}>{res.ip}</td>
                                <td style={{ fontFamily: 'var(--font-mono)' }}>{res.port}</td>
                                <td style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: 'var(--font-mono)' }} title={res.url}>
                                  {res.url}
                                </td>
                                <td>{res.device || '?'}</td>
                                <td>
                                  {isCred ? (
                                    <span className="badge cred">VULNERABLE</span>
                                  ) : isOpen ? (
                                    <span className="badge open">OPEN WEB</span>
                                  ) : (
                                    <span className="badge auth">PROTECTED</span>
                                  )}
                                </td>
                                <td style={{ fontFamily: 'var(--font-mono)' }}>
                                  {isCred ? (
                                    <span style={{ color: 'var(--green)', fontWeight: 600 }}>{res.username}:{res.password}</span>
                                  ) : '-'}
                                </td>
                                <td>{res.country_code || '-'}</td>
                                <td style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis' }} title={res.org}>
                                  {res.org || '-'}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>

            </div>
          </div>
        </section>

        {/* --- OUTPUT TAB --- */}
        <section className={`tab-panel ${activeTab === 'output' ? 'active' : ''}`}>
          <div className="history-layout">
            
            {/* Sidebar list of past scans */}
            <div className="history-sidebar">
              {historyLoading && (
                <div style={{ textAlign: 'center', padding: 20 }}>
                  <RefreshCw size={24} className="color-blue" style={{ animation: 'spin 1.5s linear infinite', margin: '0 auto' }} />
                  <span style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginTop: 8 }}>Querying archives...</span>
                </div>
              )}
              
              {!historyLoading && outputs.length === 0 ? (
                <div className="empty-state" style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'rgba(17,24,39,0.3)' }}>
                  <History className="empty-icon" size={32} />
                  <div className="empty-title">Intel Vault Empty</div>
                  <div className="empty-desc">Run network scans. Confirmed signals will be cached here.</div>
                </div>
              ) : (
                groupOutputsByDate().map(([date, items]) => (
                  <div key={date} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <div className="history-group-title">{date}</div>
                    {items.map(item => {
                      const isActive = selectedResultId === item.id;
                      return (
                        <div 
                          key={item.id} 
                          className={`history-card ${isActive ? 'active' : ''}`}
                          onClick={() => selectResult(item.id)}
                        >
                          <div className="h-card-top">
                            <div className="h-card-region">{item.region || 'Worldwide Scan'}</div>
                            <div className="h-card-badges">
                              <span className="h-badge green">{item.creds_count || 0}</span>
                              <span className="h-badge orange">{item.open_count || 0}</span>
                            </div>
                          </div>
                          <div className="h-card-meta">
                            <span>{item.total_scanned || 0} Targets</span>
                            <span style={{ fontFamily: 'var(--font-mono)' }}>{(item.created_at || '').slice(11, 19)}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ))
              )}
            </div>

            {/* Selected Scan Detail Area */}
            <div className="history-detail-panel">
              {selectedResultId ? (
                <>
                  <div className="detail-header">
                    <div className="detail-title-area">
                      <div className="detail-title">
                        {outputs.find(o => o.id === selectedResultId)?.region || 'Scan Target Block'}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                        Cached: {new Date(outputs.find(o => o.id === selectedResultId)?.created_at || '').toLocaleString()}
                      </div>
                    </div>

                    <div className="detail-actions">
                      <div className="view-toggle">
                        <button 
                          className={`view-toggle-btn ${detailView === 'grouped' ? 'active' : ''}`}
                          onClick={() => setDetailView('grouped')}
                        >
                          Grouped Details
                        </button>
                        <button 
                          className={`view-toggle-btn ${detailView === 'raw' ? 'active' : ''}`}
                          onClick={() => setDetailView('raw')}
                        >
                          Raw Log
                        </button>
                      </div>
                      <button 
                        className="btn-action danger" 
                        style={{ padding: '6px 12px' }}
                        onClick={() => deleteResult(selectedResultId)}
                      >
                        <Trash size={12} />
                        Purge
                      </button>
                    </div>
                  </div>

                  <div className="detail-body">
                    {detailView === 'raw' ? (
                      <div className="raw-json-box">
                        {JSON.stringify(selectedResultItems, null, 2)}
                      </div>
                    ) : selectedResultItems.length === 0 ? (
                      <div className="empty-state">
                        <AlertCircle className="empty-icon" size={32} />
                        <div className="empty-title">Zero Active Targets Found</div>
                        <div className="empty-desc">This scope scan did not yield open access points.</div>
                      </div>
                    ) : (
                      <div>
                        {selectedResultItems.map(item => {
                          const isExpanded = expandedItems.has(item.id);
                          const state = deviceTestStates[item.id] || {
                            loading: false,
                            status: item.broken ? '✅ Working!' : '— not tested',
                            output: '',
                            user: item.username || 'admin',
                            pass: item.password || 'admin',
                            showShell: !!item.broken,
                            command: 'id'
                          };
                          
                          return (
                            <div 
                              key={item.id} 
                              className={`acc-item ${item.broken ? 'broken' : ''}`}
                            >
                              <div 
                                className="acc-header"
                                onClick={() => toggleItemExpansion(item.id)}
                              >
                                <div className="acc-header-info">
                                  {item.auth_found ? (
                                    <span className="badge cred">VULN</span>
                                  ) : item.no_auth ? (
                                    <span className="badge open">OPEN</span>
                                  ) : (
                                    <span className="badge auth">AUTH</span>
                                  )}
                                  <div className="acc-ip">{item.ip}:{item.port}</div>
                                  <div className="acc-device">{item.device || '?'}</div>
                                  {item.country_code && <span className="acc-device">• {item.country_code}</span>}
                                  {item.org && <span className="acc-desc">• {item.org.slice(0, 36)}</span>}
                                </div>
                                <div className="acc-actions">
                                  <button 
                                    className="interact-btn" 
                                    style={{ padding: '4px 10px', fontSize: 10 }}
                                    onClick={(e) => { e.stopPropagation(); testDevice(item.id); }}
                                    disabled={state.loading}
                                  >
                                    Verify
                                  </button>
                                  {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                                </div>
                              </div>

                              {isExpanded && (
                                <div className="acc-body">
                                  <div className="detail-grid">
                                    <div className="detail-tile">
                                      <div className="detail-tile-label">Service Endpoint</div>
                                      <div className="detail-tile-value" style={{ fontFamily: 'var(--font-mono)' }}>{item.url}</div>
                                    </div>
                                    <div className="detail-tile">
                                      <div className="detail-tile-label">Credentials Found</div>
                                      <div className="detail-tile-value" style={{ color: 'var(--green)', fontWeight: 600 }}>
                                        {item.auth_found ? `${item.username}:${item.password}` : 'None (No auth or Protected)'}
                                      </div>
                                    </div>
                                    {item.org && (
                                      <div className="detail-tile">
                                        <div className="detail-tile-label">Provider Organization</div>
                                        <div className="detail-tile-value">{item.org}</div>
                                      </div>
                                    )}
                                    {item.isp && (
                                      <div className="detail-tile">
                                        <div className="detail-tile-label">ISP Network</div>
                                        <div className="detail-tile-value">{item.isp}</div>
                                      </div>
                                    )}
                                    {item.lat && (
                                      <div className="detail-tile">
                                        <div className="detail-tile-label">Coordinates</div>
                                        <div className="detail-tile-value" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                                          <MapPin size={12} className="color-blue" />
                                          {item.lat}, {item.lon} ({item.city || 'Unknown City'})
                                        </div>
                                      </div>
                                    )}
                                    {item.as_info && (
                                      <div className="detail-tile">
                                        <div className="detail-tile-label">Autonomous System</div>
                                        <div className="detail-tile-value" style={{ fontFamily: 'var(--font-mono)' }}>{item.as_info}</div>
                                      </div>
                                    )}
                                  </div>

                                  <div className="interact-box">
                                    <div className="interact-box-title">
                                      <span className={`dot ${item.broken ? 'active' : ''}`}></span>
                                      Remote Shell Access Terminal
                                      <span style={{ fontWeight: 400, fontSize: 11, textTransform: 'none', marginLeft: 'auto', color: item.broken ? 'var(--green)' : 'var(--text-secondary)' }}>
                                        Connection State: {state.status}
                                      </span>
                                    </div>

                                    <div className="interact-row">
                                      <input 
                                        type="text" 
                                        placeholder="Admin Username" 
                                        value={state.user} 
                                        onChange={e => updateTestState(item.id, { user: e.target.value })}
                                        disabled={state.loading}
                                      />
                                      <input 
                                        type="text" 
                                        placeholder="Admin Password" 
                                        value={state.pass} 
                                        onChange={e => updateTestState(item.id, { pass: e.target.value })}
                                        disabled={state.loading}
                                      />
                                      <button 
                                        className="interact-btn" 
                                        onClick={() => testDevice(item.id)}
                                        disabled={state.loading}
                                      >
                                        Verify Access
                                      </button>
                                      <button 
                                        className="interact-btn dark-btn"
                                        onClick={() => openDevice(item)}
                                      >
                                        <ExternalLink size={12} style={{ marginRight: 4 }} />
                                        Launch GUI
                                      </button>
                                    </div>

                                    {state.showShell && (
                                      <div className="interact-row" style={{ marginTop: 12 }}>
                                        <input 
                                          type="text" 
                                          placeholder="Command (e.g. whoami, id, ls -la)" 
                                          value={state.command}
                                          onChange={e => updateTestState(item.id, { command: e.target.value })}
                                          disabled={state.loading}
                                        />
                                        <button 
                                          className="interact-btn dark-btn" 
                                          onClick={() => execShell(item.id)}
                                          disabled={state.loading}
                                        >
                                          Execute Action
                                        </button>
                                      </div>
                                    )}

                                    {state.output && (
                                      <div className="interact-output-box">
                                        <button 
                                          className="terminal-copy-btn"
                                          onClick={() => {
                                            navigator.clipboard.writeText(state.output);
                                            showToast('Terminal logs copied!', 'success');
                                          }}
                                        >
                                          Copy Logs
                                        </button>
                                        {state.output}
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <div className="empty-state" style={{ height: '100%' }}>
                  <Shield size={48} className="empty-icon" />
                  <div className="empty-title">Select Scan Profile</div>
                  <div className="empty-desc">Choose a compiled scan record from the left pane to explore target endpoints, run credentials audits, and verify security hooks.</div>
                </div>
              )}
            </div>

          </div>
        </section>

        {/* --- INVITES TAB --- */}
        <section className={`tab-panel ${activeTab === 'invites' ? 'active' : ''}`}>
          <div className="invite-container">
            <div className="invite-actions-bar">
              <div>
                <h2 style={{ color: 'white', fontWeight: 700 }}>Access Invitation Panel</h2>
                <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 4 }}>
                  Generate and monitor secure admission keys for administrative users.
                </p>
              </div>
              <button 
                className="btn-action primary" 
                style={{ width: 'auto', padding: '10px 20px' }}
                onClick={createInvite}
                disabled={invitesLoading}
              >
                <Mail size={14} style={{ marginRight: 6 }} />
                Generate Security Token
              </button>
            </div>

            <div className="card invite-table-card">
              {invitesLoading && invites.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 40 }}>
                  <RefreshCw size={24} className="color-blue" style={{ animation: 'spin 1.5s linear infinite', margin: '0 auto' }} />
                  <span style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginTop: 8 }}>Querying tokens...</span>
                </div>
              ) : invites.length === 0 ? (
                <div className="empty-state" style={{ padding: 40 }}>
                  <Mail className="empty-icon" size={32} />
                  <div className="empty-title">No Invitation Tokens</div>
                  <div className="empty-desc">All registration slots are locked. Click Generate Token to spawn new invitations.</div>
                </div>
              ) : (
                <div className="table-container">
                  <table className="sc-table">
                    <thead>
                      <tr>
                        <th>Security Token</th>
                        <th>State</th>
                        <th>Issuer UUID</th>
                        <th>Used By (User ID)</th>
                        <th>Created Timestamp</th>
                        <th>Redeemed Timestamp</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {invites.map((inv) => {
                        const isActive = inv.status === 'active';
                        return (
                          <tr key={inv.id}>
                            <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: isActive ? 'var(--blue)' : 'var(--text-secondary)' }}>
                              {inv.code}
                            </td>
                            <td>
                              <span className={`badge-status ${isActive ? 'active' : 'used'}`}>
                                {isActive ? 'ACTIVE' : 'REDEEMED'}
                              </span>
                            </td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{inv.issuer}</td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{inv.used_by || '—'}</td>
                            <td>{inv.created_at ? new Date(inv.created_at).toLocaleString() : '—'}</td>
                            <td>{inv.used_at ? new Date(inv.used_at).toLocaleString() : '—'}</td>
                            <td>
                              <button 
                                className="btn-logout" 
                                style={{ padding: '4px 8px', fontSize: 11 }}
                                onClick={() => {
                                  navigator.clipboard.writeText(inv.code);
                                  showToast('Token copied to clipboard!', 'success');
                                }}
                              >
                                <Copy size={10} style={{ marginRight: 4 }} />
                                Copy Code
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </section>

      </main>
    </>
  );
}
