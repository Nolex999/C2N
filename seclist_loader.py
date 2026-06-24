"""Load SecLists default credentials and web paths."""
import os, re

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SecLists")
CREDS_DIR = os.path.join(BASE, "Passwords", "Default-Credentials")
ROUTERS_DIR = os.path.join(CREDS_DIR, "Routers")
COMMON_TXT = os.path.join(BASE, "Discovery", "Web-Content", "common.txt")

_creds_cache = None
_vendor_creds_cache = None
_paths_cache = None


def _load_flat_creds():
    """Parse *-betterdefaultpasslist.txt and default-passwords.txt -> [(user,pass,note)]"""
    creds = {}
    if not os.path.isdir(CREDS_DIR):
        return []
    for fname in os.listdir(CREDS_DIR):
        fpath = os.path.join(CREDS_DIR, fname)
        if not os.path.isfile(fpath) or fname.endswith(".csv") or fname.endswith(".md"):
            continue
        try:
            with open(fpath, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    if ":" in line:
                        user, _, pw = line.partition(":")
                        user, pw = user.strip(), pw.strip()
                        if user and pw:
                            creds[f"{user}:{pw}"] = (user, pw, fname.replace(".txt", ""))
        except:
            pass
    return list(creds.values())


def _load_vendor_creds():
    """Parse Routers/ directory -> [(user,pass,note)] with vendor naming."""
    creds = {}
    if not os.path.isdir(ROUTERS_DIR):
        return []
    pw_files = {}
    user_files = {}
    for fname in os.listdir(ROUTERS_DIR):
        fpath = os.path.join(ROUTERS_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        if fname.endswith("-passwords.txt"):
            vendor = fname.replace("_default-passwords.txt", "").replace("-passwords.txt", "")
            pw_files[vendor] = fpath
        elif fname.endswith("-users.txt"):
            vendor = fname.replace("_default-users.txt", "").replace("-users.txt", "")
            user_files[vendor] = fpath
    # Also check the ALL file
    all_path = os.path.join(ROUTERS_DIR, "0ALL-USERNAMES-AND-PASSWORDS.txt")
    if os.path.isfile(all_path):
        try:
            with open(all_path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    if ":" in line:
                        user, _, pw = line.partition(":")
                        user, pw = user.strip(), pw.strip()
                        if user and pw:
                            creds[f"{user}:{pw}"] = (user, pw, "router-all")
        except:
            pass
    for vendor in pw_files:
        pws = []
        try:
            with open(pw_files[vendor], encoding="utf-8", errors="replace") as f:
                pws = [l.strip() for l in f if l.strip()]
        except:
            pass
        users = ["admin"]  # default fallback
        if vendor in user_files:
            try:
                with open(user_files[vendor], encoding="utf-8", errors="replace") as f:
                    us = [l.strip() for l in f if l.strip()]
                    if us:
                        users = us
            except:
                pass
        for u in users:
            for p in pws:
                key = f"{u}:{p}"
                if key not in creds:
                    creds[key] = (u, p, vendor)
    return list(creds.values())


def load_all_creds():
    """Return all default credentials from SecLists as [(user, pass, note)]."""
    global _creds_cache
    if _creds_cache is not None:
        return _creds_cache
    _creds_cache = _load_flat_creds() + _load_vendor_creds()
    return _creds_cache


def get_creds_for_device(device_type, max_creds=100):
    """Get relevant creds for a device type from SecLists."""
    all_creds = load_all_creds()
    if not device_type:
        return all_creds[:max_creds]
    dt = device_type.lower().replace(" ", "-").replace("(", "").replace(")", "").replace("/", "-")
    # Score: exact vendor match first
    scored = []
    for u, p, note in all_creds:
        score = 0
        n_lower = note.lower()
        if dt in n_lower or dt.replace("-", "") in n_lower:
            score += 10
        # Partial brand match
        brand_parts = re.split(r"[\s\-/]", dt)
        for bp in brand_parts:
            if len(bp) > 2 and bp in n_lower:
                score += 3
        scored.append((score, u, p, note))
    scored.sort(key=lambda x: -x[0])
    return [(u, p, note) for s, u, p, note in scored[:max_creds]]


def load_web_paths():
    """Load common.txt web paths for HTTP discovery."""
    global _paths_cache
    if _paths_cache is not None:
        return _paths_cache
    _paths_cache = []
    if os.path.isfile(COMMON_TXT):
        try:
            with open(COMMON_TXT, encoding="utf-8", errors="replace") as f:
                _paths_cache = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except:
            pass
    return _paths_cache


def get_shell_endpoints():
    """Filter common.txt for potential shell/CGI/exec endpoints."""
    paths = load_web_paths()
    keywords = ["cgi", "exec", "shell", "cmd", "console", "admin", "config",
                "setup", "debug", "test", "ping", "diag", "system", "command",
                "run", "api", "cli", "term", "bash", "sh", "perl", "python",
                "php-cgi", "cgi-bin"]
    matched = []
    for p in paths:
        pl = p.lower().strip("/")
        for kw in keywords:
            if kw in pl:
                matched.append(p)
                break
    return sorted(set(matched), key=lambda x: len(x))


# High-value shell/CGI endpoints most likely to be exploitable on routers
HIGH_VALUE_ENDPOINTS = [
    "/cgi-bin/exec", "/cgi-bin/", "/cgi-bin/config", "/cgi-bin/cmd",
    "/exec", "/shell", "/cmd", "/console", "/command",
    "/cgi-bin/admin", "/cgi-bin/debug", "/cgi-bin/test",
    "/cgi-bin/ping", "/cgi-bin/traceroute", "/cgi-bin/diag",
    "/cgi-bin/system", "/cgi-bin/command",
    "/admin/exec", "/admin/cmd", "/admin/shell",
    "/debug", "/ping", "/diag", "/system",
    "/api/exec", "/api/cmd", "/api/shell", "/api/command",
    "/setup", "/config", "/configuration",
    "/cgi-bin/reboot", "/cgi-bin/restart",
    "/cgi-bin/download", "/cgi-bin/upload",
    "/cgi-bin/backup", "/cgi-bin/restore",
    "/cgi-bin/status", "/cgi-bin/info",
    "/cgi-bin/login.cgi", "/cgi-bin/webproc",
    "/cgi-bin/luci", "/cgi-bin/webcm",
    "/goform/exec", "/goform/cmd",
    "/goform/config", "/goform/setup",
]


def get_exploit_endpoints(device_type=""):
    """Return prioritized shell endpoints: hardcoded highs, then SecLists high-value, then remaining."""
    core = ["/exec", "/cgi-bin/exec", "/shell", "/cmd", "/console"]
    seen = set(core)
    extra = []
    for ep in HIGH_VALUE_ENDPOINTS:
        if ep not in seen:
            extra.append(ep)
            seen.add(ep)
    # Add device-specific paths from full list
    dt = (device_type or "").lower()
    if dt:
        for ep in get_shell_endpoints():
            if ep not in seen:
                extra.append(ep)
                seen.add(ep)
    return core + extra[:200]  # limit to avoid excessive requests
